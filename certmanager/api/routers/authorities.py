"""Certificate Authority management router."""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from certmanager.api.dependencies import get_current_active_user, get_db, require_permission
from certmanager.connectors.secrets import encrypt_sensitive_values, redact_for_display
from certmanager.core.exceptions import ConflictError, NotFoundError, ValidationError
from certmanager.core.models import CertificateAuthority, User

router = APIRouter()


class AcmeIssueRequest(BaseModel):
    """Body for triggering an ACME certificate issuance."""

    common_name: str
    sans: list[str] | None = None
    key_algorithm: str = "RSA-2048"
    cert_type: str = "server"


class AcmeRenewRequest(BaseModel):
    """Body for triggering an ACME certificate renewal."""

    certificate_id: str


class RevokeRequest(BaseModel):
    """Body for revoking an issued certificate at its issuing CA."""

    certificate_id: str
    reason_code: int = 0


class AuthorityCreate(BaseModel):
    """Body for registering a certificate authority."""

    name: str
    ca_type: str
    datacenter_id: str | None = None
    config: dict | None = None


class AuthorityUpdate(BaseModel):
    """Body for updating a CA — all fields optional."""

    name: str | None = None
    config: dict | None = None
    is_active: bool | None = None


@router.get("")
async def list_authorities(
    ca_type: str | None = Query(default=None),
    dc_id: str | None = Query(default=None),
    health: str | None = Query(default=None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """List configured certificate authorities with health status."""
    query = select(CertificateAuthority)
    if ca_type:
        query = query.where(CertificateAuthority.ca_type == ca_type)
    if dc_id:
        query = query.where(CertificateAuthority.datacenter_id == dc_id)
    if health:
        query = query.where(CertificateAuthority.health_status == health)

    result = await db.execute(query.order_by(CertificateAuthority.name))
    authorities = result.scalars().all()

    return {
        "data": [
            {
                "id": a.id,
                "name": a.name,
                "ca_type": a.ca_type,
                "datacenter_id": a.datacenter_id,
                "is_active": a.is_active,
                "health_status": a.health_status,
                "last_scan_at": a.last_scan_at.isoformat() if a.last_scan_at else None,
                "last_scan_status": a.last_scan_status,
                "last_error": a.last_error,
                "created_at": a.created_at.isoformat(),
                "updated_at": a.updated_at.isoformat(),
            }
            for a in authorities
        ],
        "total": len(authorities),
    }


@router.post("", status_code=201)
async def create_authority(
    body: AuthorityCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Register a new certificate authority."""
    # Check for duplicates
    existing = await db.execute(
        select(CertificateAuthority).where(
            CertificateAuthority.name == body.name,
            CertificateAuthority.ca_type == body.ca_type,
        )
    )
    if existing.scalar_one_or_none():
        raise ConflictError(f"Authority '{body.name}' of type '{body.ca_type}' already exists")

    authority = CertificateAuthority(
        name=body.name,
        ca_type=body.ca_type,
        datacenter_id=body.datacenter_id,
        # Credential values are encrypted before they touch the database
        config=encrypt_sensitive_values(body.config or {}),
    )
    db.add(authority)
    await db.flush()
    await db.refresh(authority)

    return {"data": {"id": authority.id, "name": authority.name, "ca_type": authority.ca_type}}


@router.get("/{authority_id}")
async def get_authority(
    authority_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Get a CA's full configuration and health details."""
    result = await db.execute(
        select(CertificateAuthority).where(CertificateAuthority.id == authority_id)
    )
    authority = result.scalar_one_or_none()
    if not authority:
        raise NotFoundError(f"Authority {authority_id} not found")

    return {
        "data": {
            "id": authority.id,
            "name": authority.name,
            "ca_type": authority.ca_type,
            "datacenter_id": authority.datacenter_id,
            "is_active": authority.is_active,
            # Never return credential values in API responses
            "config": redact_for_display(authority.config or {}),
            "health_status": authority.health_status,
            "last_scan_at": authority.last_scan_at.isoformat() if authority.last_scan_at else None,
            "last_scan_status": authority.last_scan_status,
            "last_error": authority.last_error,
        }
    }


@router.patch("/{authority_id}")
async def update_authority(
    authority_id: str,
    body: AuthorityUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Update a CA configuration."""
    result = await db.execute(
        select(CertificateAuthority).where(CertificateAuthority.id == authority_id)
    )
    authority = result.scalar_one_or_none()
    if not authority:
        raise NotFoundError(f"Authority {authority_id} not found")

    if body.name is not None:
        authority.name = body.name
    if body.config is not None:
        # Encrypt any new credential values before storing
        authority.config = encrypt_sensitive_values(body.config)
    if body.is_active is not None:
        authority.is_active = body.is_active

    await db.flush()
    return {"data": {"id": authority.id, "updated": True}}


@router.delete("/{authority_id}", status_code=204)
async def delete_authority(
    authority_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Remove a CA configuration."""
    result = await db.execute(
        select(CertificateAuthority).where(CertificateAuthority.id == authority_id)
    )
    authority = result.scalar_one_or_none()
    if not authority:
        raise NotFoundError(f"Authority {authority_id} not found")
    await db.delete(authority)
    await db.flush()


@router.post("/{authority_id}/test")
async def test_authority(
    authority_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Test connectivity to a CA using its connector."""
    from certmanager.connectors.factory import get_connector

    result = await db.execute(
        select(CertificateAuthority).where(CertificateAuthority.id == authority_id)
    )
    authority = result.scalar_one_or_none()
    if not authority:
        raise NotFoundError(f"Authority {authority_id} not found")

    try:
        connector = get_connector(authority)
        health = await connector.health_check()

        # Update CA health status
        authority.health_status = health.status.value
        authority.last_scan_at = datetime.now(UTC)
        await db.flush()

        return {
            "data": {
                "status": health.status.value,
                "message": health.message,
                "latency_ms": health.latency_ms,
                "detail": health.detail,
            }
        }
    except Exception as e:
        authority.health_status = "unhealthy"
        authority.last_error = str(e)
        await db.flush()

        return {
            "data": {
                "status": "unhealthy",
                "message": str(e),
            }
        }


@router.post("/{authority_id}/scan")
async def trigger_authority_scan(
    authority_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Trigger an immediate discovery scan for this CA via Celery worker."""
    from certmanager.core.models import ScanJob

    result = await db.execute(
        select(CertificateAuthority).where(CertificateAuthority.id == authority_id)
    )
    authority = result.scalar_one_or_none()
    if not authority:
        raise NotFoundError(f"Authority {authority_id} not found")

    # Create scan job
    job = ScanJob(
        job_type="ca_sync",
        status="pending",
        triggered_by="manual",
        triggered_by_user=current_user.id,
        scope_config={"ca_ids": [authority_id]},
    )
    db.add(job)
    await db.flush()
    await db.refresh(job)

    # Dispatch to Celery scanner worker
    try:
        from certmanager.workers.scanner_worker import run_scan_job

        run_scan_job.delay(str(job.id))
    except Exception:
        import structlog

        structlog.get_logger().warning(
            "celery_unavailable_scan_pending",
            job_id=str(job.id),
        )

    return {
        "data": {
            "scan_job_id": str(job.id),
            "authority_id": authority_id,
            "status": "pending",
            "message": "CA scan dispatched. Monitor at GET /scans/{id}",
        }
    }


def _dispatch_acme_job(job_id: str) -> None:
    """Dispatch an ACME issue/renew job to the Celery worker. Falls back to
    logging (job stays pending) if Celery is unavailable, same as every
    other scan/report dispatch in this codebase."""
    try:
        from certmanager.workers.acme_worker import issue_or_renew_task

        issue_or_renew_task.delay(job_id)
    except Exception:
        import structlog

        structlog.get_logger().warning("celery_unavailable_acme_job_pending", job_id=job_id)


@router.post("/{authority_id}/issue", status_code=201)
async def issue_acme_certificate(
    authority_id: str,
    body: AcmeIssueRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Trigger certificate issuance for an ACME or AD CS authority.

    ACME dispatches immediately to the Celery worker (DNS-01 via
    Cloudflare). AD CS creates the identical ScanJob shape but leaves it
    `pending` for the agent to pick up on its next poll cycle — no
    Celery dispatch, no inbound exposure to the agent ever required.
    Status is polled via the existing GET /scans/{id} either way.
    """
    from certmanager.core.models import ScanJob

    result = await db.execute(
        select(CertificateAuthority).where(CertificateAuthority.id == authority_id)
    )
    authority = result.scalar_one_or_none()
    if not authority:
        raise NotFoundError(f"Authority {authority_id} not found")
    if authority.ca_type not in ("acme", "adcs"):
        raise ValidationError(f"Authority {authority_id} does not support issuance")

    if authority.ca_type == "acme":
        job = ScanJob(
            job_type="acme_issue",
            status="pending",
            triggered_by="manual",
            triggered_by_user=current_user.id,
            scope_config={
                "authority_id": authority_id,
                "common_name": body.common_name,
                "sans": body.sans or [],
                "key_algorithm": body.key_algorithm,
                "cert_type": body.cert_type,
            },
        )
        db.add(job)
        await db.flush()
        await db.refresh(job)
        _dispatch_acme_job(str(job.id))
        message = "Certificate issuance dispatched. Monitor at GET /scans/{id}."
    else:
        config = authority.config or {}
        agent_id = config.get("agent_id")
        if not agent_id:
            raise ValidationError(f"Authority {authority_id} has no agent_id configured")

        job = ScanJob(
            job_type="adcs_issue",
            status="pending",
            triggered_by="manual",
            triggered_by_user=current_user.id,
            scope_config={
                "agent_id": agent_id,
                "authority_id": authority_id,
                "common_name": body.common_name,
                "sans": body.sans or [],
                "template": config.get("template", ""),
                "deployment_target": config.get("deployment_target", "store"),
                "deployment_path": config.get("deployment_path", ""),
                "post_install_hook": config.get("post_install_hook", ""),
                "deliver_key_to_central": bool(config.get("deliver_key_to_central", False)),
            },
        )
        db.add(job)
        await db.flush()
        await db.refresh(job)
        message = "Certificate issuance queued. The agent will pick this up on its next poll cycle."

    return {
        "data": {
            "scan_job_id": str(job.id),
            "authority_id": authority_id,
            "status": "pending",
            "message": message,
        }
    }


@router.post("/{authority_id}/renew", status_code=201)
async def renew_acme_certificate(
    authority_id: str,
    body: AcmeRenewRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Trigger certificate renewal for an ACME or AD CS authority.

    Renews using what the certificate was actually issued with (domain
    set / template), not the authority's current config defaults — a
    single CA can plausibly issue certs under more than one template.
    """
    from certmanager.core.models import Certificate, ScanJob

    result = await db.execute(
        select(CertificateAuthority).where(CertificateAuthority.id == authority_id)
    )
    authority = result.scalar_one_or_none()
    if not authority:
        raise NotFoundError(f"Authority {authority_id} not found")
    if authority.ca_type not in ("acme", "adcs"):
        raise ValidationError(f"Authority {authority_id} does not support renewal")

    if authority.ca_type == "acme":
        job = ScanJob(
            job_type="acme_renew",
            status="pending",
            triggered_by="manual",
            triggered_by_user=current_user.id,
            scope_config={"authority_id": authority_id, "certificate_id": body.certificate_id},
        )
        db.add(job)
        await db.flush()
        await db.refresh(job)
        _dispatch_acme_job(str(job.id))
        message = "Certificate renewal dispatched. Monitor at GET /scans/{id}."
    else:
        config = authority.config or {}
        agent_id = config.get("agent_id")
        if not agent_id:
            raise ValidationError(f"Authority {authority_id} has no agent_id configured")

        cert_result = await db.execute(
            select(Certificate).where(Certificate.id == body.certificate_id)
        )
        certificate = cert_result.scalar_one_or_none()
        if not certificate:
            raise NotFoundError(f"Certificate {body.certificate_id} not found")

        cert_detail = certificate.source_detail or {}
        job = ScanJob(
            job_type="adcs_renew",
            status="pending",
            triggered_by="manual",
            triggered_by_user=current_user.id,
            scope_config={
                "agent_id": agent_id,
                "authority_id": authority_id,
                "certificate_id": body.certificate_id,
                "common_name": certificate.common_name,
                "sans": certificate.sans or [],
                "template": cert_detail.get("template") or config.get("template", ""),
                "deployment_target": config.get("deployment_target", "store"),
                "deployment_path": config.get("deployment_path", ""),
                "post_install_hook": config.get("post_install_hook", ""),
                "deliver_key_to_central": bool(config.get("deliver_key_to_central", False)),
            },
        )
        db.add(job)
        await db.flush()
        await db.refresh(job)
        message = "Certificate renewal queued. The agent will pick this up on its next poll cycle."

    return {
        "data": {
            "scan_job_id": str(job.id),
            "authority_id": authority_id,
            "status": "pending",
            "message": message,
        }
    }


@router.post("/{authority_id}/revoke", status_code=201)
async def revoke_certificate(
    authority_id: str,
    body: RevokeRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Revoke a certificate at its issuing CA. AD CS only for now — the
    ACME connector doesn't implement revocation yet."""
    from certmanager.core.models import Certificate, ScanJob

    result = await db.execute(
        select(CertificateAuthority).where(CertificateAuthority.id == authority_id)
    )
    authority = result.scalar_one_or_none()
    if not authority:
        raise NotFoundError(f"Authority {authority_id} not found")
    if authority.ca_type not in ("acme", "adcs"):
        raise ValidationError(f"Authority {authority_id} does not support revocation")
    if authority.ca_type == "acme":
        raise ValidationError("ACME revocation is not yet supported")

    cert_result = await db.execute(select(Certificate).where(Certificate.id == body.certificate_id))
    certificate = cert_result.scalar_one_or_none()
    if not certificate:
        raise NotFoundError(f"Certificate {body.certificate_id} not found")
    if not certificate.serial_number:
        raise ValidationError(f"Certificate {body.certificate_id} has no serial number on record")

    config = authority.config or {}
    agent_id = config.get("agent_id")
    if not agent_id:
        raise ValidationError(f"Authority {authority_id} has no agent_id configured")

    job = ScanJob(
        job_type="adcs_revoke",
        status="pending",
        triggered_by="manual",
        triggered_by_user=current_user.id,
        scope_config={
            "agent_id": agent_id,
            "authority_id": authority_id,
            "certificate_id": body.certificate_id,
            "serial_number": certificate.serial_number,
            "ca_server": config.get("ca_server", ""),
            "ca_name": config.get("ca_name", ""),
            "reason_code": body.reason_code,
        },
    )
    db.add(job)
    await db.flush()
    await db.refresh(job)

    return {
        "data": {
            "scan_job_id": str(job.id),
            "authority_id": authority_id,
            "status": "pending",
            "message": "Certificate revocation queued. The agent will pick this up on its next poll cycle.",
        }
    }


@router.get("/key-bundles/{bundle_id}/download")
async def download_acme_key_bundle(
    bundle_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("certificates", "download_key")),
):
    """Download an issued/renewed certificate's private key + chain.

    Gated by an explicit `certificates:download_key` permission check —
    deliberately NOT the automatic path-derived RBAC rule (which would
    otherwise grant this to anyone with blanket authorities:read/create).
    Admin-only unless that permission is explicitly granted to another
    role. Time-boxed: 410 once past the bundle's expiry.
    """
    from fastapi import HTTPException

    from certmanager.core.crypto import decrypt_value
    from certmanager.core.models import Certificate, CertificateKeyBundle

    result = await db.execute(
        select(CertificateKeyBundle).where(CertificateKeyBundle.id == bundle_id)
    )
    bundle = result.scalar_one_or_none()
    if not bundle:
        raise NotFoundError(f"Key bundle {bundle_id} not found")

    now = datetime.now(UTC)
    expires_at = bundle.expires_at if bundle.expires_at.tzinfo else bundle.expires_at.replace(tzinfo=UTC)
    if expires_at < now:
        raise HTTPException(
            status_code=410,
            detail="This key bundle has expired and been purged from secure storage. "
            "Trigger a new issuance/renewal to get a fresh one.",
        )

    cert_result = await db.execute(
        select(Certificate).where(Certificate.id == bundle.certificate_id)
    )
    certificate = cert_result.scalar_one_or_none()
    source_detail = (certificate.source_detail or {}) if certificate else {}

    private_key_pem = decrypt_value(bundle.encrypted_private_key)

    if bundle.downloaded_at is None:
        bundle.downloaded_at = now
        await db.flush()

    cert_pem = source_detail.get("cert_pem", "")
    chain_pem = source_detail.get("chain_pem", "")
    # Reconstructed rather than stored (cert_pem + chain_pem is all it is) —
    # falls back to an already-stored copy for certs issued before this
    # stopped being persisted separately.
    fullchain_pem = source_detail.get("fullchain_pem") or f"{cert_pem}\n{chain_pem}".strip()

    return {
        "data": {
            "private_key_pem": private_key_pem,
            "certificate_pem": cert_pem,
            "chain_pem": chain_pem,
            "fullchain_pem": fullchain_pem,
        }
    }
