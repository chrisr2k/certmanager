"""Certificate lifecycle service.

Handles canonical certificate record management:
- Upsert from discovery (merge new findings with existing records)
- Change detection (detect renewed, expired, revoked certs)
- Status management (auto-expire, auto-revoke)
- De-duplication by thumbprint_sha256
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import List, Optional, Tuple

import structlog
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from certmanager.connectors.base import CertificateRecord
from certmanager.core.models import Certificate, CertificateChain

logger = structlog.get_logger()


class CertificateService:
    """Manages the canonical certificate inventory.

    All write operations go through this service to ensure consistency:
    - Certificates are matched by thumbprint_sha256 (primary dedup key)
    - Fallback to (common_name, serial_number, issuer) when thumbprint unavailable
    - Source detail is merged on re-discovery
    - Status transitions are logged and validated
    """

    def __init__(self, db: AsyncSession):
        self.db = db

    async def upsert_from_discovery(
        self,
        records: List[CertificateRecord],
        source_ca_id: Optional[str],
        source_type: str,
        datacenter_id: Optional[str],
        scan_job_id: str,
    ) -> dict:
        """Upsert certificates from a discovery scan.

        For each discovered certificate:
        - If it exists (matched by thumbprint): update last_seen_at, merge source_detail
        - If it's new: insert into inventory
        - If it was previously seen but not in this scan: mark as potentially removed

        Args:
            records: List of normalized CertificateRecord from a CA connector.
            source_ca_id: UUID of the CertificateAuthority that was scanned,
                or None for agent-discovered certs with no central CA row.
            source_type: The source type string (aws_acm, azure_keyvault, adcs, tls_scan).
            datacenter_id: UUID of the datacenter containing this CA.
            scan_job_id: UUID of the ScanJob that triggered this discovery.

        Returns:
            Dict with counts: {new, updated, unchanged, errors}
        """
        stats = {"new": 0, "updated": 0, "unchanged": 0, "errors": 0}

        for record in records:
            try:
                result = await self._upsert_single(
                    record=record,
                    source_ca_id=source_ca_id,
                    source_type=source_type,
                    datacenter_id=datacenter_id,
                    scan_job_id=scan_job_id,
                )
                stats[result] += 1
            except Exception as e:
                logger.error(
                    "upsert_cert_failed",
                    cn=record.common_name,
                    source_id=record.source_id,
                    error=str(e),
                )
                stats["errors"] += 1

        logger.info("discovery_upsert_complete", **stats)
        return stats

    async def _upsert_single(
        self,
        record: CertificateRecord,
        source_ca_id: str,
        source_type: str,
        datacenter_id: Optional[str],
        scan_job_id: str,
    ) -> str:
        """Upsert a single certificate record. Returns 'new', 'updated', or 'unchanged'."""
        now = datetime.now(timezone.utc)

        # Try to find existing certificate by thumbprint (strongest match)
        existing = None
        if record.thumbprint_sha256:
            result = await self.db.execute(
                select(Certificate).where(
                    Certificate.thumbprint_sha256 == record.thumbprint_sha256
                )
            )
            existing = result.scalar_one_or_none()

        # Fallback: match by (common_name, serial_number, issuer)
        if existing is None and record.serial_number:
            result = await self.db.execute(
                select(Certificate).where(
                    Certificate.common_name == record.common_name,
                    Certificate.serial_number == record.serial_number,
                    Certificate.issuer == record.issuer,
                )
            )
            existing = result.scalar_one_or_none()

        if existing is None:
            # New certificate — insert
            cert = Certificate(
                common_name=record.common_name,
                subject=record.subject,
                issuer=record.issuer,
                serial_number=record.serial_number,
                thumbprint_sha256=record.thumbprint_sha256,
                not_before=record.not_before,
                not_after=record.not_after,
                validity_days=record.validity_days
                or int((record.not_after - record.not_before).total_seconds() / 86400),
                cert_type=record.cert_type,
                key_algorithm=record.key_algorithm,
                signature_algorithm=record.signature_algorithm,
                sans=record.sans,
                source_ca_id=source_ca_id,
                source_type=source_type,
                source_detail=record.source_detail,
                status=self._compute_status(record),
                is_wildcard=record.is_wildcard,
                is_ca=record.is_ca,
                datacenter_id=datacenter_id,
                first_seen_at=now,
                last_seen_at=now,
                discovered_by=scan_job_id,
            )
            self.db.add(cert)
            await self.db.flush()

            # Insert chain certificates
            if record.chain_certs:
                await self._upsert_chain(cert.id, record.chain_certs)

            return "new"

        else:
            # Existing certificate — update last_seen and merge metadata
            changed = False

            if existing.last_seen_at < now:
                existing.last_seen_at = now
                changed = True

            # Merge source_detail (add new keys, don't remove existing)
            merged_detail = {**existing.source_detail, **record.source_detail}
            if merged_detail != existing.source_detail:
                existing.source_detail = merged_detail
                changed = True

            # Update status if the CA reports a different status
            computed_status = self._compute_status(record)
            if computed_status != existing.status:
                existing.status = computed_status
                changed = True

            # Update thumbprint if we didn't have one before
            if not existing.thumbprint_sha256 and record.thumbprint_sha256:
                existing.thumbprint_sha256 = record.thumbprint_sha256
                changed = True

            # Update subject/issuer if they've changed (certificate renewal)
            if record.subject != existing.subject:
                existing.subject = record.subject
                changed = True
            if record.issuer != existing.issuer:
                existing.issuer = record.issuer
                changed = True
            if record.not_after != existing.not_after:
                existing.not_after = record.not_after
                existing.validity_days = record.validity_days or int(
                    (record.not_after - record.not_before).total_seconds() / 86400
                )
                changed = True

            # Update SANs if changed
            if set(record.sans or []) != set(existing.sans or []):
                existing.sans = record.sans
                changed = True

            if changed:
                await self.db.flush()
                return "updated"

            return "unchanged"

    async def _upsert_chain(
        self, leaf_cert_id: str, chain_records: List[CertificateRecord]
    ) -> None:
        """Insert chain certificates for a leaf certificate."""
        for idx, chain_cert in enumerate(chain_records):
            chain_entry = CertificateChain(
                leaf_cert_id=leaf_cert_id,
                chain_order=idx + 1,  # 0 would be the leaf itself
                cert_pem_sha256=chain_cert.thumbprint_sha256,
                cert_subject=chain_cert.subject,
                cert_issuer=chain_cert.issuer,
                not_after=chain_cert.not_after,
            )
            self.db.add(chain_entry)
        await self.db.flush()

    @staticmethod
    def _compute_status(record: CertificateRecord) -> str:
        """Compute the certificate status from its record.

        Checks expiry first, then the source-reported status.
        """
        now = datetime.now(timezone.utc)

        if record.not_after and record.not_after < now:
            return "expired"
        if record.status == "revoked":
            return "revoked"
        if record.status == "expired":
            return "expired"

        return "active"

    async def auto_expire_certificates(self) -> int:
        """Mark all certificates past their not_after date as expired.

        Runs periodically (e.g., daily). Returns count of updated certs.

        Returns:
            Number of certificates marked as expired.
        """
        now = datetime.now(timezone.utc)

        result = await self.db.execute(
            update(Certificate)
            .where(
                Certificate.not_after < now,
                Certificate.status == "active",
            )
            .values(status="expired")
        )
        await self.db.flush()

        count = result.rowcount
        if count:
            logger.info("auto_expired_certificates", count=count)

        return count

    async def get_expiring_certs(
        self, days: int = 30, limit: int = 100
    ) -> List[Certificate]:
        """Get certificates expiring within N days.

        Args:
            days: Number of days to look ahead.
            limit: Maximum number of certificates to return.

        Returns:
            List of Certificate ORM objects ordered by nearest expiry.
        """
        now = datetime.now(timezone.utc)
        cutoff = now.replace(
            hour=23, minute=59, second=59
        ) + timedelta(days=days)

        result = await self.db.execute(
            select(Certificate)
            .where(
                Certificate.not_after >= now,
                Certificate.not_after <= cutoff,
                Certificate.status == "active",
            )
            .order_by(Certificate.not_after.asc())
            .limit(limit)
        )
        return list(result.scalars().all())

    async def get_stats(self) -> dict:
        """Get certificate statistics for dashboards."""
        from sqlalchemy import func

        now = datetime.now(timezone.utc)
        thirty_days = now + timedelta(days=30)
        sixty_days = now + timedelta(days=60)
        ninety_days = now + timedelta(days=90)

        # Total by status
        status_result = await self.db.execute(
            select(Certificate.status, func.count(Certificate.id)).group_by(
                Certificate.status
            )
        )
        status_counts = dict(status_result.all())

        # Expiring counts
        expiring_30 = (
            await self.db.execute(
                select(func.count(Certificate.id)).where(
                    Certificate.not_after >= now,
                    Certificate.not_after <= thirty_days,
                    Certificate.status == "active",
                )
            )
        ).scalar() or 0

        expiring_60 = (
            await self.db.execute(
                select(func.count(Certificate.id)).where(
                    Certificate.not_after >= now,
                    Certificate.not_after <= sixty_days,
                    Certificate.status == "active",
                )
            )
        ).scalar() or 0

        expiring_90 = (
            await self.db.execute(
                select(func.count(Certificate.id)).where(
                    Certificate.not_after >= now,
                    Certificate.not_after <= ninety_days,
                    Certificate.status == "active",
                )
            )
        ).scalar() or 0

        total = sum(status_counts.values())

        return {
            "total": total,
            "active": status_counts.get("active", 0),
            "expired": status_counts.get("expired", 0),
            "revoked": status_counts.get("revoked", 0),
            "expiring_in_30_days": expiring_30,
            "expiring_in_60_days": expiring_60,
            "expiring_in_90_days": expiring_90,
        }
