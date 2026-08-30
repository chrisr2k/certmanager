"""Reporting service — generates compliance reports from certificate data.

Uses Jinja2 templates for HTML reports and WeasyPrint for PDF rendering.
Supports three report types:
- expiry_summary: Certificates expiring within a window
- full_inventory: Complete certificate inventory dump
- change_report: New/renewed/expired certificates in a time period

Output formats: PDF (via WeasyPrint), CSV, JSON
"""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import structlog
from jinja2 import Environment, FileSystemLoader, select_autoescape
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from certmanager.core.models import Certificate, CertificateAuthority, Datacenter

logger = structlog.get_logger()

TEMPLATES_DIR = Path(__file__).parent.parent / "templates" / "reports"


class ReportingService:
    """Generates compliance reports from the certificate inventory."""

    def __init__(self, db: AsyncSession):
        self.db = db
        self._jinja = Environment(
            loader=FileSystemLoader(str(TEMPLATES_DIR)),
            autoescape=select_autoescape(["html"]),
        )

    async def generate_report(
        self,
        report_type: str,
        parameters: Optional[dict] = None,
        output_format: str = "pdf",
    ) -> tuple[bytes, str]:
        """Generate a report.

        Args:
            report_type: expiry_summary | full_inventory | change_report | audit_export
            parameters: Report-specific parameters (date range, dc filter, etc.)
            output_format: pdf | csv | json

        Returns:
            Tuple of (file_bytes, mime_type).
        """
        params = parameters or {}

        if report_type == "expiry_summary":
            return await self._expiry_summary(params, output_format)
        elif report_type == "full_inventory":
            return await self._full_inventory(params, output_format)
        elif report_type == "change_report":
            return await self._change_report(params, output_format)
        elif report_type == "audit_export":
            return await self._audit_export(params, output_format)
        else:
            raise ValueError(f"Unknown report type: {report_type}")

    async def _expiry_summary(
        self, params: dict, output_format: str
    ) -> tuple[bytes, str]:
        """Generate a certificate expiry summary report."""
        now = datetime.now(timezone.utc)
        thirty_days = now + timedelta(days=30)
        seven_days = now + timedelta(days=7)

        # Base query
        query = select(Certificate)
        dc_ids = params.get("datacenter_ids", [])
        if dc_ids:
            query = query.where(Certificate.datacenter_id.in_(dc_ids))

        result = await self.db.execute(query)
        all_certs = result.scalars().all()

        # Classify
        expiring_soon = []
        expired_certs = []

        for cert in all_certs:
            days_left = (cert.not_after - now).days
            if cert.status == "expired" or days_left < 0:
                expired_certs.append({
                    "common_name": cert.common_name,
                    "issuer": cert.issuer,
                    "not_after": cert.not_after.isoformat(),
                    "days_left": days_left,
                    "source_type": cert.source_type,
                    "datacenter_name": cert.datacenter.name if cert.datacenter else None,
                })
            elif days_left <= 30:
                expiring_soon.append({
                    "common_name": cert.common_name,
                    "issuer": cert.issuer,
                    "not_after": cert.not_after.isoformat(),
                    "days_left": days_left,
                    "source_type": cert.source_type,
                    "datacenter_name": cert.datacenter.name if cert.datacenter else None,
                })

        expiring_soon.sort(key=lambda c: c["days_left"])
        expired_certs.sort(key=lambda c: c["not_after"], reverse=True)

        # By datacenter
        dc_result = await self.db.execute(select(Datacenter))
        dcs = dc_result.scalars().all()
        by_datacenter = []
        for dc in dcs:
            dc_certs = [c for c in all_certs if str(c.datacenter_id) == str(dc.id)]
            by_datacenter.append({
                "name": dc.name,
                "total": len(dc_certs),
                "active": sum(1 for c in dc_certs if c.status == "active"),
                "expiring_30d": sum(1 for c in dc_certs if 0 <= (c.not_after - now).days <= 30),
                "expired": sum(1 for c in dc_certs if c.status == "expired"),
            })

        # Summary
        expiring_7d_count = sum(1 for c in expiring_soon if c["days_left"] <= 7)

        template_data = {
            "generated_at": now.strftime("%Y-%m-%d %H:%M UTC"),
            "period_start": (now - timedelta(days=90)).strftime("%Y-%m-%d"),
            "period_end": now.strftime("%Y-%m-%d"),
            "datacenters": [dc.name for dc in dcs if dc_ids and str(dc.id) in dc_ids] or [dc.name for dc in dcs],
            "summary": {
                "total": len(all_certs),
                "active": sum(1 for c in all_certs if c.status == "active"),
                "expiring_30d": len(expiring_soon),
                "expiring_7d": expiring_7d_count,
                "expired": len(expired_certs),
            },
            "expiring_soon": expiring_soon,
            "expired_certs": expired_certs,
            "by_datacenter": by_datacenter,
        }

        return await self._render(template_data, "expiry_summary", output_format)

    async def _full_inventory(
        self, params: dict, output_format: str
    ) -> tuple[bytes, str]:
        """Generate a full certificate inventory dump."""
        query = select(Certificate).order_by(Certificate.not_after.asc())

        status_filter = params.get("status")
        if status_filter:
            query = query.where(Certificate.status == status_filter)

        dc_ids = params.get("datacenter_ids", [])
        if dc_ids:
            query = query.where(Certificate.datacenter_id.in_(dc_ids))

        result = await self.db.execute(query)
        certs = result.scalars().all()

        cert_data = [
            {
                "common_name": c.common_name,
                "subject": c.subject,
                "issuer": c.issuer,
                "serial_number": c.serial_number,
                "not_before": c.not_before.isoformat() if c.not_before else None,
                "not_after": c.not_after.isoformat() if c.not_after else None,
                "cert_type": c.cert_type,
                "key_algorithm": c.key_algorithm,
                "status": c.status,
                "source_type": c.source_type,
                "sans": c.sans,
                "datacenter_name": c.datacenter.name if c.datacenter else None,
            }
            for c in certs
        ]

        now = datetime.now(timezone.utc)
        template_data = {
            "generated_at": now.strftime("%Y-%m-%d %H:%M UTC"),
            "datacenter_filter": params.get("datacenter_filter", ""),
            "status_filter": status_filter or "",
            "certificates": cert_data,
        }

        return await self._render(template_data, "full_inventory", output_format)

    async def _change_report(
        self, params: dict, output_format: str
    ) -> tuple[bytes, str]:
        """Generate a report of certificate changes in a time period."""
        now = datetime.now(timezone.utc)
        days = params.get("days", 7)
        since = now - timedelta(days=days)

        # Newly discovered certs
        new_result = await self.db.execute(
            select(Certificate)
            .where(Certificate.first_seen_at >= since)
            .order_by(Certificate.first_seen_at.desc())
        )
        new_certs = new_result.scalars().all()

        # Recently expired
        expired_result = await self.db.execute(
            select(Certificate)
            .where(
                Certificate.status == "expired",
                Certificate.updated_at >= since,
            )
            .order_by(Certificate.not_after.desc())
        )
        expired_certs = expired_result.scalars().all()

        # Recently revoked
        revoked_result = await self.db.execute(
            select(Certificate)
            .where(
                Certificate.status == "revoked",
                Certificate.updated_at >= since,
            )
        )
        revoked_certs = revoked_result.scalars().all()

        now_str = now.strftime("%Y-%m-%d %H:%M UTC")

        template_data = {
            "generated_at": now_str,
            "period_start": since.strftime("%Y-%m-%d"),
            "period_end": now.strftime("%Y-%m-%d"),
            "summary": {
                "new_certs": len(new_certs),
                "renewed_certs": 0,  # Would need renewal tracking
                "expired_certs": len(expired_certs),
                "revoked_certs": len(revoked_certs),
            },
            "new_certs": [
                {
                    "common_name": c.common_name,
                    "issuer": c.issuer,
                    "source_type": c.source_type,
                    "first_seen_at": c.first_seen_at.isoformat() if c.first_seen_at else None,
                    "not_after": c.not_after.isoformat() if c.not_after else None,
                }
                for c in new_certs
            ],
            "expired_certs": [
                {
                    "common_name": c.common_name,
                    "issuer": c.issuer,
                    "not_after": c.not_after.isoformat() if c.not_after else None,
                    "datacenter_name": c.datacenter.name if c.datacenter else None,
                }
                for c in expired_certs
            ],
        }

        return await self._render(template_data, "change_report", output_format)

    async def _audit_export(
        self, params: dict, output_format: str
    ) -> tuple[bytes, str]:
        """Export audit log entries as CSV or JSON."""
        from certmanager.core.models import AuditLog

        days = params.get("days", 30)
        since = datetime.now(timezone.utc) - timedelta(days=days)

        result = await self.db.execute(
            select(AuditLog)
            .where(AuditLog.created_at >= since)
            .order_by(AuditLog.created_at.desc())
            .limit(10000)
        )
        logs = result.scalars().all()

        if output_format == "csv":
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow([
                "ID", "Event Type", "Actor Type", "Actor Email",
                "Resource Type", "Action", "Details", "IP", "Timestamp"
            ])
            for log in logs:
                writer.writerow([
                    log.id,
                    log.event_type,
                    log.actor_type,
                    log.actor_email or "",
                    log.resource_type or "",
                    log.action,
                    json.dumps(log.details or {}),
                    log.ip_address or "",
                    log.created_at.isoformat() if log.created_at else "",
                ])
            return output.getvalue().encode("utf-8"), "text/csv"

        else:  # JSON
            data = [
                {
                    "id": log.id,
                    "event_type": log.event_type,
                    "actor_type": log.actor_type,
                    "actor_email": log.actor_email,
                    "resource_type": log.resource_type,
                    "action": log.action,
                    "details": log.details,
                    "ip_address": log.ip_address,
                    "created_at": log.created_at.isoformat() if log.created_at else None,
                }
                for log in logs
            ]
            return json.dumps(data, indent=2, default=str).encode("utf-8"), "application/json"

    async def _render(
        self, template_data: dict, template_name: str, output_format: str
    ) -> tuple[bytes, str]:
        """Render a Jinja2 template to PDF (via WeasyPrint) or CSV.

        Args:
            template_data: Data to pass to the template.
            template_name: Name of the Jinja2 template (without .html).
            output_format: pdf | csv | json

        Returns:
            Tuple of (file_bytes, mime_type).
        """
        if output_format == "csv":
            return self._render_csv(template_data, template_name)
        elif output_format == "json":
            return json.dumps(template_data, indent=2, default=str).encode("utf-8"), "application/json"
        else:
            return self._render_pdf(template_data, template_name)

    def _render_pdf(self, template_data: dict, template_name: str) -> tuple[bytes, str]:
        """Render HTML template to PDF using WeasyPrint."""
        try:
            template = self._jinja.get_template(f"{template_name}.html")
            html = template.render(**template_data)

            from weasyprint import HTML

            pdf_bytes = HTML(string=html).write_pdf()
            return pdf_bytes, "application/pdf"
        except ImportError:
            # WeasyPrint not installed — return HTML instead
            template = self._jinja.get_template(f"{template_name}.html")
            html = template.render(**template_data)
            return html.encode("utf-8"), "text/html"
        except Exception as e:
            logger.error("pdf_render_failed", template=template_name, error=str(e))
            # Fallback to HTML
            template = self._jinja.get_template(f"{template_name}.html")
            html = template.render(**template_data)
            return html.encode("utf-8"), "text/html"

    def _render_csv(self, template_data: dict, template_name: str) -> tuple[bytes, str]:
        """Export certificate data as CSV."""
        output = io.StringIO()
        writer = csv.writer(output)

        # Extract certificate data from template context
        certs = template_data.get("certificates", [])
        expiring = template_data.get("expiring_soon", [])

        rows = certs or expiring or []

        if rows:
            # Write headers from first row keys
            headers = list(rows[0].keys())
            writer.writerow(headers)
            for row in rows:
                writer.writerow([row.get(h, "") for h in headers])
        else:
            writer.writerow(["No data"])

        return output.getvalue().encode("utf-8"), "text/csv"
