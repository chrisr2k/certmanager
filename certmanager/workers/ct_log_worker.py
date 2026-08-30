"""Certificate Transparency log monitoring worker.

Polls Certificate Transparency logs to detect certificates issued for
managed domains that are NOT in the CertManager inventory.

This detects "shadow" or "rogue" certificates — certs issued by any CA
for your domains without your knowledge.

Uses the crt.sh free API (https://crt.sh/?q=%25.example.com&output=json)
as the CT log data source. Regularly polls for all domains seen in the
certificate inventory.
"""

from __future__ import annotations

import asyncio
import hashlib
from datetime import UTC, datetime

import structlog
from celery import shared_task
from celery.utils.log import get_task_logger

from certmanager.core.database import get_session_factory

logger = structlog.get_logger()
task_logger = get_task_logger(__name__)


@shared_task(
    name="certmanager.workers.ct_log_worker.check_ct_logs",
    bind=True,
)
def check_ct_logs(self):
    """Check Certificate Transparency logs for unknown certificates.

    Scheduled task — runs daily (or more frequently for critical domains).
    """

    async def _run():
        factory = get_session_factory()
        async with factory() as db:
            monitor = CTMonitor(db)
            return await monitor.check_all_domains()

    try:
        result = _run_async(_run())
        task_logger.info(
            f"CT check complete: {result['domains_checked']} domains, "
            f"{result['new_entries']} new, {result['unknown_certs']} unknown"
        )
        return result
    except Exception as exc:
        task_logger.error(f"CT check failed: {exc}")
        raise


def _run_async(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


class CTMonitor:
    """Monitors Certificate Transparency logs via crt.sh."""

    def __init__(self, db):
        self.db = db

    async def check_all_domains(self) -> dict:
        """Check CT logs for all domains in the certificate inventory.

        Returns:
            Dict with stats: domains_checked, new_entries, unknown_certs.
        """
        from sqlalchemy import func, select

        from certmanager.core.models import Certificate

        # Collect unique domains from certificate inventory
        result = await self.db.execute(select(func.unnest(Certificate.sans)).distinct())
        domains = [row[0] for row in result.all() if row[0]]

        # Also include common names
        cn_result = await self.db.execute(
            select(Certificate.common_name)
            .where(
                Certificate.common_name.isnot(None),
                Certificate.status == "active",
            )
            .distinct()
        )
        for row in cn_result.all():
            cn = row[0]
            if cn and cn not in domains and not cn.startswith("*"):
                domains.append(cn)

        # Deduplicate
        domains = list({d for d in domains if d and "." in d})

        if not domains:
            logger.info("ct_no_domains_to_check")
            return {"domains_checked": 0, "new_entries": 0, "unknown_certs": 0}

        stats = {"domains_checked": 0, "new_entries": 0, "unknown_certs": 0}

        # Check each domain (batch to avoid rate-limiting)
        for domain in domains:
            try:
                entries = await self._query_crtsh(domain)
                stats["domains_checked"] += 1

                for entry in entries:
                    is_new, is_unknown = await self._process_entry(entry, domain)
                    if is_new:
                        stats["new_entries"] += 1
                    if is_unknown:
                        stats["unknown_certs"] += 1

            except Exception as e:
                logger.warning("ct_domain_check_failed", domain=domain, error=str(e))
                continue

            # Rate limit: crt.sh asks for ~1 req/sec
            await asyncio.sleep(1.5)

        await self.db.commit()
        return stats

    async def _query_crtsh(self, domain: str) -> list[dict]:
        """Query crt.sh for certificates matching a domain.

        Uses the JSON API: https://crt.sh/?q=%.example.com&output=json
        """
        import aiohttp

        url = f"https://crt.sh/?q=%25.{domain}&output=json"

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url,
                    headers={"User-Agent": "CertManager-CT-Monitor/1.0"},
                    timeout=aiohttp.ClientTimeout(total=30),
                ) as resp:
                    if resp.status != 200:
                        logger.warning("crtsh_error", domain=domain, status=resp.status)
                        return []

                    data = await resp.json()
                    return data if isinstance(data, list) else []

        except Exception as e:
            logger.warning("crtsh_request_failed", domain=domain, error=str(e))
            return []

    async def _process_entry(self, entry: dict, domain: str) -> tuple[bool, bool]:
        """Process a CT log entry.

        Determines if the entry is new (not seen before) and if the
        certificate is unknown (not in our inventory).

        Returns:
            Tuple of (is_new, is_unknown).
        """
        from certmanager.core.models import Certificate, CTLogEntry

        entry_id = entry.get("id")
        entry.get("issuer_ca_id", "")  # crt.sh uses CA IDs
        issuer_name = entry.get("issuer_name", "")
        logged_at_str = entry.get("entry_timestamp")
        not_before_str = entry.get("not_before")
        not_after_str = entry.get("not_after")
        name_value = entry.get("name_value", "")
        serial = entry.get("serial_number", "")

        # Compute thumbprint from serial
        thumbprint = hashlib.sha256(f"{domain}:{serial}:{name_value}".encode()).hexdigest()

        # Check if we've already seen this entry
        existing = await self.db.execute(
            __import__("sqlalchemy").select(CTLogEntry).where(CTLogEntry.entry_index == entry_id)
        )
        if existing.scalar_one_or_none():
            return False, False  # Already seen

        # Parse dates
        logged_at = self._parse_date(logged_at_str)
        not_before = self._parse_date(not_before_str)
        not_after = self._parse_date(not_after_str)

        # The name_value field contains all SANs, one per line
        domains = [d.strip() for d in name_value.split("\n") if d.strip()]

        # Check if any matching certificate is in our inventory
        matching_cert = None
        for d in domains:
            result = await self.db.execute(
                __import__("sqlalchemy").select(Certificate).where(Certificate.sans.contains([d]))
            )
            cert = result.scalar_one_or_none()
            if cert:
                matching_cert = cert
                break

        # Also check by common name
        if not matching_cert:
            for d in domains:
                result = await self.db.execute(
                    __import__("sqlalchemy")
                    .select(Certificate)
                    .where(
                        Certificate.common_name == d,
                        Certificate.status == "active",
                    )
                )
                cert = result.scalar_one_or_none()
                if cert:
                    matching_cert = cert
                    break

        # Create CT log entry
        ct_entry = CTLogEntry(
            log_name="crt.sh",
            log_url="https://crt.sh/",
            entry_index=entry_id,
            logged_at=logged_at,
            cert_thumbprint=thumbprint,
            domains=domains,
            issuer=issuer_name,
            not_before=not_before,
            not_after=not_after,
            is_precert="precert" in name_value.lower(),
            matched_cert_id=str(matching_cert.id) if matching_cert else None,
        )
        self.db.add(ct_entry)
        is_new = True

        # Unknown certificate = not in our inventory
        is_unknown = matching_cert is None

        if is_unknown:
            # Generate a high-severity alert for shadow certs
            await self._create_shadow_cert_alert(
                domains=domains,
                issuer=issuer_name,
                serial=serial,
                thumbprint=thumbprint,
                logged_at=logged_at,
                not_after=not_after,
            )

        return is_new, is_unknown

    async def _create_shadow_cert_alert(
        self,
        domains: list[str],
        issuer: str,
        serial: str,
        thumbprint: str,
        logged_at: datetime | None,
        not_after: datetime | None,
    ) -> None:
        """Create a high-severity alert for a shadow/unknown certificate."""
        from certmanager.core.models import AlertEvent, AlertRule

        # Find CT monitoring alert rules
        result = await self.db.execute(
            __import__("sqlalchemy")
            .select(AlertRule)
            .where(
                AlertRule.condition_type == "ct_new_cert",
                AlertRule.is_enabled,
            )
        )
        rules = result.scalars().all()

        domain_str = ", ".join(domains[:5])
        if len(domains) > 5:
            domain_str += f" (+{len(domains) - 5} more)"

        for rule in rules:
            event = AlertEvent(
                alert_rule_id=str(rule.id),
                event_type="ct_new_cert",
                severity="critical",
                title=f"Unknown certificate detected for managed domain(s): {domain_str}",
                description=(
                    f"A certificate was logged in Certificate Transparency for "
                    f"domain(s) **{domain_str}** that is **NOT** in your CertManager inventory.\n\n"
                    f"Issuer: {issuer}\n"
                    f"Serial: {serial}\n"
                    f"Thumbprint: {thumbprint}\n"
                    f"CT Logged at: {logged_at}\n"
                    f"Expires: {not_after}\n\n"
                    f"This may indicate an unauthorized or rogue certificate. Investigate immediately."
                ),
                context={
                    "domains": domains,
                    "issuer": issuer,
                    "serial": serial,
                    "thumbprint": thumbprint,
                },
            )
            self.db.add(event)

    @staticmethod
    def _parse_date(date_str: str | None) -> datetime | None:
        """Parse a date string from crt.sh format."""
        if not date_str:
            return None
        try:
            return datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=UTC)
        except ValueError:
            try:
                return datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%S.%f").replace(tzinfo=UTC)
            except ValueError:
                return None
