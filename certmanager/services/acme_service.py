"""ACME issuance/renewal orchestration.

Bridges the stateless ACMEConnector (no DB access, built fresh from config
each time — same as every other connector) and the database: persisting a
newly-generated ACME account back into CertificateAuthority.config,
upserting the issued certificate's public metadata through the existing
discovery pipeline, and storing the private key encrypted for later
download. This is the platform's first real certificate-issuance flow —
nothing previously called a connector's issue/renew/revoke methods.
"""

from __future__ import annotations

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from certmanager.connectors.factory import get_connector
from certmanager.connectors.secrets import encrypt_sensitive_values
from certmanager.core.crypto import encrypt_value
from certmanager.core.exceptions import NotFoundError, ValidationError
from certmanager.core.models import Certificate, CertificateAuthority, CertificateKeyBundle
from certmanager.services.certificate_service import CertificateService

logger = structlog.get_logger()


class AcmeService:
    """Orchestrates ACME certificate issuance and renewal."""

    def __init__(self, db: AsyncSession):
        self.db = db
        self.cert_service = CertificateService(db)

    async def issue_or_renew(
        self,
        authority_id: str,
        mode: str,
        scan_job_id: str,
        common_name: str | None = None,
        sans: list[str] | None = None,
        key_algorithm: str = "RSA-2048",
        cert_type: str = "server",
        renew_certificate_id: str | None = None,
    ) -> dict:
        """Issue a new certificate or renew an existing one.

        Idempotent against Celery retries: if a CertificateKeyBundle already
        exists for `scan_job_id` (a prior attempt succeeded but the task
        crashed before marking the ScanJob completed), it's returned as-is
        rather than issuing a second certificate — avoiding a duplicate
        Let's Encrypt order (and burning a real weekly-duplicate-cert slot)
        on retry.

        Returns:
            {"certificate_id": ..., "key_bundle_id": ..., "common_name": ...}
        """
        existing_bundle = await self._find_bundle_for_job(scan_job_id)
        if existing_bundle is not None:
            logger.info("acme_issue_or_renew_idempotent_hit", scan_job_id=scan_job_id)
            return {
                "certificate_id": existing_bundle.certificate_id,
                "key_bundle_id": existing_bundle.id,
            }

        result = await self.db.execute(
            select(CertificateAuthority).where(CertificateAuthority.id == authority_id)
        )
        authority = result.scalar_one_or_none()
        if authority is None:
            raise NotFoundError(f"Authority {authority_id} not found")
        if authority.ca_type != "acme":
            raise ValidationError(f"Authority {authority_id} is not an ACME authority")

        connector = get_connector(authority)

        new_key_pem, new_account_url = await connector.ensure_account()
        if new_key_pem or new_account_url:
            config = dict(authority.config or {})
            if new_key_pem:
                config["account_key_pem"] = new_key_pem
            if new_account_url:
                config["account_url"] = new_account_url
            authority.config = encrypt_sensitive_values(config)
            await self.db.flush()
            logger.info("acme_account_persisted", authority_id=authority_id)

        if mode == "issue":
            from certmanager.connectors.base import IssueRequest

            if not common_name:
                raise ValidationError("common_name is required to issue a certificate")
            issue_result = await connector.issue_certificate(
                IssueRequest(
                    common_name=common_name,
                    sans=sans or [],
                    key_algorithm=key_algorithm,
                    cert_type=cert_type,
                )
            )
        elif mode == "renew":
            if not renew_certificate_id:
                raise ValidationError("renew_certificate_id is required to renew a certificate")
            cert_result = await self.db.execute(
                select(Certificate).where(Certificate.id == renew_certificate_id)
            )
            existing_cert = cert_result.scalar_one_or_none()
            if existing_cert is None:
                raise NotFoundError(f"Certificate {renew_certificate_id} not found")
            cert_pem = (existing_cert.source_detail or {}).get("cert_pem")
            if not cert_pem:
                raise ValidationError(
                    f"Certificate {renew_certificate_id} has no stored PEM to renew from "
                    "(it wasn't issued through this ACME connector)"
                )
            issue_result = await connector.renew_certificate(cert_pem)
        else:
            raise ValidationError(f"Unknown mode: {mode!r} (expected 'issue' or 'renew')")

        stats = await self.cert_service.upsert_from_discovery(
            records=[issue_result.certificate],
            source_ca_id=authority_id,
            source_type="acme",
            datacenter_id=authority.datacenter_id,
            scan_job_id=scan_job_id,
        )
        if stats["errors"]:
            raise ValidationError("Failed to record the issued certificate in the inventory")

        cert_row = await self.db.execute(
            select(Certificate).where(
                Certificate.thumbprint_sha256 == issue_result.certificate.thumbprint_sha256
            )
        )
        certificate = cert_row.scalar_one()

        bundle = CertificateKeyBundle(
            certificate_id=certificate.id,
            scan_job_id=scan_job_id,
            encrypted_private_key=encrypt_value(issue_result.private_key_pem or ""),
        )
        self.db.add(bundle)
        await self.db.flush()

        logger.info(
            "acme_issue_or_renew_complete",
            mode=mode,
            authority_id=authority_id,
            certificate_id=certificate.id,
            key_bundle_id=bundle.id,
        )
        return {"certificate_id": certificate.id, "key_bundle_id": bundle.id}

    async def _find_bundle_for_job(self, scan_job_id: str) -> CertificateKeyBundle | None:
        result = await self.db.execute(
            select(CertificateKeyBundle).where(CertificateKeyBundle.scan_job_id == scan_job_id)
        )
        return result.scalar_one_or_none()
