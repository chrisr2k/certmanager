"""Certificate Authority management router."""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from certmanager.api.dependencies import get_current_active_user, get_db
from certmanager.connectors.secrets import encrypt_sensitive_values, redact_for_display
from certmanager.core.exceptions import ConflictError, NotFoundError
from certmanager.core.models import CertificateAuthority, User

router = APIRouter()


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
