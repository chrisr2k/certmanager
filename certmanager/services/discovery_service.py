"""Discovery service — orchestrates certificate discovery scans.

Coordinates:
1. Loading CA configuration from the database
2. Creating the appropriate connector via the factory
3. Running health checks (pre-scan validation)
4. Executing discovery via the connector
5. Upserting results into the certificate inventory
6. Updating scan job status in the database
"""

from __future__ import annotations

import time
from datetime import UTC, datetime

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from certmanager.connectors.base import CAHealthStatus
from certmanager.connectors.factory import CredentialStore, get_connector
from certmanager.core.models import CertificateAuthority, ScanJob
from certmanager.services.certificate_service import CertificateService

logger = structlog.get_logger()


class DiscoveryService:
    """Orchestrates certificate discovery across all CA types.

    Usage:
        service = DiscoveryService(db_session)
        result = await service.run_discovery(scan_job_id)
        # Or for a single CA:
        result = await service.scan_authority(authority_id, scan_job_id)
    """

    def __init__(
        self,
        db: AsyncSession,
        credential_store: CredentialStore | None = None,
    ):
        self.db = db
        self.credential_store = credential_store or CredentialStore()
        self.cert_service = CertificateService(db)

    async def run_discovery(self, scan_job_id: str) -> dict:
        """Execute a discovery scan job.

        Loads the ScanJob, determines scope (which CAs to scan),
        runs discovery for each CA, and upserts results.

        Args:
            scan_job_id: UUID of the ScanJob to execute.

        Returns:
            Summary dict with job status and stats.
        """
        # Load the scan job
        result = await self.db.execute(select(ScanJob).where(ScanJob.id == scan_job_id))
        job = result.scalar_one_or_none()

        if not job:
            raise ValueError(f"ScanJob {scan_job_id} not found")

        # Mark job as running
        job.status = "running"
        job.started_at = datetime.now(UTC)
        await self.db.flush()

        scope = job.scope_config or {}
        ca_ids = scope.get("ca_ids", [])

        # If no specific CAs, scan all active CAs
        if not ca_ids:
            all_cas = await self.db.execute(
                select(CertificateAuthority).where(CertificateAuthority.is_active)
            )
            ca_ids = [ca.id for ca in all_cas.scalars().all()]

        logger.info("discovery_starting", scan_job_id=scan_job_id, ca_count=len(ca_ids))

        total_new = 0
        total_updated = 0
        total_checked = 0
        total_errors = 0
        errors_detail = []

        for ca_id in ca_ids:
            try:
                ca_stats = await self.scan_authority(
                    authority_id=ca_id,
                    scan_job_id=scan_job_id,
                    scope=scope,
                )
                total_new += ca_stats.get("new", 0)
                total_updated += ca_stats.get("updated", 0)
                total_checked += ca_stats.get("total", 0)
                total_errors += ca_stats.get("errors", 0)
            except Exception as e:
                error_msg = str(e)
                logger.error("ca_scan_failed", ca_id=ca_id, error=error_msg)
                total_errors += 1
                errors_detail.append({"ca_id": ca_id, "error": error_msg})

        # Update job with final stats
        job.status = "completed"
        job.completed_at = datetime.now(UTC)
        job.total_checked = total_checked
        job.total_new = total_new
        job.total_updated = total_updated
        job.total_errors = total_errors
        job.error_detail = errors_detail
        await self.db.flush()

        logger.info(
            "discovery_complete",
            scan_job_id=scan_job_id,
            new=total_new,
            updated=total_updated,
            errors=total_errors,
        )

        return {
            "scan_job_id": scan_job_id,
            "status": "completed",
            "total_checked": total_checked,
            "total_new": total_new,
            "total_updated": total_updated,
            "total_errors": total_errors,
            "errors": errors_detail,
        }

    async def scan_authority(
        self,
        authority_id: str,
        scan_job_id: str,
        scope: dict | None = None,
    ) -> dict:
        """Scan a single Certificate Authority and upsert its certificates.

        Args:
            authority_id: UUID of the CertificateAuthority to scan.
            scan_job_id: UUID of the parent ScanJob.
            scope: Optional scope filter (CA-type-specific).

        Returns:
            Dict with {new, updated, unchanged, errors, total}.
        """
        # Load CA from database
        result = await self.db.execute(
            select(CertificateAuthority).where(CertificateAuthority.id == authority_id)
        )
        authority = result.scalar_one_or_none()

        if not authority:
            raise ValueError(f"CertificateAuthority {authority_id} not found")

        if not authority.is_active:
            logger.info("ca_inactive_skipped", ca_id=authority_id, name=authority.name)
            return {"new": 0, "updated": 0, "unchanged": 0, "errors": 0, "total": 0}

        start = time.monotonic()

        # Create connector
        connector = get_connector(authority, self.credential_store)

        # Pre-scan health check
        health = await connector.health_check()
        authority.last_scan_at = datetime.now(UTC)
        authority.health_status = health.status.value

        if health.status == CAHealthStatus.UNHEALTHY:
            authority.last_error = health.message
            authority.last_scan_status = "failed"
            await self.db.flush()
            logger.error(
                "ca_unhealthy_skipped",
                ca_id=authority_id,
                name=authority.name,
                message=health.message,
            )
            return {"new": 0, "updated": 0, "unchanged": 0, "errors": 1, "total": 0}

        # Run discovery
        try:
            records = await connector.discover_certificates(scope)
        except Exception as e:
            authority.last_scan_status = "failed"
            authority.last_error = str(e)
            await self.db.flush()
            raise

        # Upsert certificates
        upsert_stats = await self.cert_service.upsert_from_discovery(
            records=records,
            source_ca_id=authority_id,
            source_type=connector.connector_type,
            datacenter_id=authority.datacenter_id,
            scan_job_id=scan_job_id,
        )

        # Update CA health
        elapsed = (time.monotonic() - start) * 1000
        authority.last_scan_status = "success" if upsert_stats["errors"] == 0 else "partial"
        authority.last_error = None
        authority.health_status = "healthy"
        await self.db.flush()

        logger.info(
            "ca_scan_complete",
            ca_id=authority_id,
            name=authority.name,
            ca_type=authority.ca_type,
            elapsed_ms=round(elapsed, 2),
            **upsert_stats,
        )

        return {
            **upsert_stats,
            "total": len(records),
        }

    async def run_health_checks(self) -> dict:
        """Run health checks on all active CAs.

        Updates CA health_status in the database.

        Returns:
            Dict mapping ca_id to health status.
        """
        result = await self.db.execute(
            select(CertificateAuthority).where(CertificateAuthority.is_active)
        )
        authorities = result.scalars().all()

        health_results = {}
        for authority in authorities:
            try:
                connector = get_connector(authority, self.credential_store)
                health = await connector.health_check()
                authority.health_status = health.status.value
                authority.last_scan_at = datetime.now(UTC)
                health_results[authority.id] = health.status.value
            except Exception as e:
                authority.health_status = "unhealthy"
                authority.last_error = str(e)
                health_results[authority.id] = "unhealthy"

        await self.db.flush()
        return health_results
