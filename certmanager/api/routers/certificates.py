"""Certificate management router: CRUD, search, stats, chain, revocation."""

from __future__ import annotations

from datetime import datetime, timedelta, UTC
from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from certmanager.api.dependencies import get_current_active_user, get_db
from certmanager.api.schemas.certificates import (
    CertificateCreate,
    CertificateListResponse,
    CertificateResponse,
    CertStats,
    CertificateUpdate,
)
from certmanager.api.schemas.common import PaginationParams
from certmanager.core.exceptions import NotFoundError
from certmanager.core.models import Certificate, User

router = APIRouter()


@router.get("", response_model=CertificateListResponse)
async def list_certificates(
    q: Optional[str] = Query(default=None, description="Full-text search query"),
    status: Optional[str] = Query(default=None, description="Filter by status"),
    cert_type: Optional[str] = Query(default=None, description="Filter by cert type"),
    source_type: Optional[str] = Query(default=None, description="Filter by source"),
    dc_id: Optional[str] = Query(default=None, description="Filter by datacenter"),
    ca_id: Optional[str] = Query(default=None, description="Filter by CA"),
    expiring_in_days: Optional[int] = Query(default=None, description="Expiring within N days"),
    owner: Optional[str] = Query(default=None, description="Filter by owner"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=250),
    sort_by: str = Query(default="not_after"),
    sort_dir: str = Query(default="asc"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """List certificates with full-text search, filtering, and pagination."""
    query = select(Certificate)

    # Full-text search
    if q:
        tsquery = func.plainto_tsquery("english", q)
        query = query.where(
            func.to_tsvector(
                "english",
                func.coalesce(Certificate.common_name, "")
                .concat(" ")
                .concat(func.coalesce(Certificate.subject, ""))
                .concat(" ")
                .concat(func.coalesce(Certificate.issuer, "")),
            ).match(tsquery, postgresql_regconfig="english")
        )

    # Filters
    if status:
        query = query.where(Certificate.status == status)
    if cert_type:
        query = query.where(Certificate.cert_type == cert_type)
    if source_type:
        query = query.where(Certificate.source_type == source_type)
    if dc_id:
        query = query.where(Certificate.datacenter_id == dc_id)
    if ca_id:
        query = query.where(Certificate.source_ca_id == ca_id)
    if owner:
        query = query.where(Certificate.owner == owner)
    if expiring_in_days is not None:
        cutoff = datetime.now(UTC) + timedelta(days=expiring_in_days)
        query = query.where(
            Certificate.not_after <= cutoff,
            Certificate.not_after >= datetime.now(UTC),
            Certificate.status == "active",
        )

    # Count total
    count_query = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_query)).scalar()

    # Sort
    sort_col = getattr(Certificate, sort_by, Certificate.not_after)
    if sort_dir == "desc":
        query = query.order_by(sort_col.desc())
    else:
        query = query.order_by(sort_col.asc())

    # Paginate
    offset = (page - 1) * page_size
    query = query.offset(offset).limit(page_size)

    result = await db.execute(query)
    certificates = result.scalars().all()

    return CertificateListResponse(
        items=[CertificateResponse.model_validate(c) for c in certificates],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/stats", response_model=CertStats)
async def certificate_stats(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Get aggregated certificate statistics."""
    now = datetime.now(UTC)

    # Total counts by status
    status_result = await db.execute(
        select(Certificate.status, func.count(Certificate.id)).group_by(Certificate.status)
    )
    status_counts = dict(status_result.all())

    # Expiring counts
    expiring_30 = (
        await db.execute(
            select(func.count(Certificate.id)).where(
                Certificate.not_after <= now + timedelta(days=30),
                Certificate.not_after > now,
                Certificate.status == "active",
            )
        )
    ).scalar() or 0

    expiring_60 = (
        await db.execute(
            select(func.count(Certificate.id)).where(
                Certificate.not_after <= now + timedelta(days=60),
                Certificate.not_after > now,
                Certificate.status == "active",
            )
        )
    ).scalar() or 0

    expiring_90 = (
        await db.execute(
            select(func.count(Certificate.id)).where(
                Certificate.not_after <= now + timedelta(days=90),
                Certificate.not_after > now,
                Certificate.status == "active",
            )
        )
    ).scalar() or 0

    # By datacenter (joined)
    dc_result = await db.execute(
        select(Certificate.datacenter_id, func.count(Certificate.id))
        .where(Certificate.datacenter_id.isnot(None))
        .group_by(Certificate.datacenter_id)
    )
    by_datacenter = {str(dc) if dc else "unknown": count for dc, count in dc_result.all()}

    # By CA type
    ca_result = await db.execute(
        select(Certificate.source_type, func.count(Certificate.id)).group_by(
            Certificate.source_type
        )
    )
    by_ca_type = dict(ca_result.all())

    # By cert type
    type_result = await db.execute(
        select(Certificate.cert_type, func.count(Certificate.id)).group_by(
            Certificate.cert_type
        )
    )
    by_cert_type = {ct if ct else "unknown": count for ct, count in type_result.all()}

    return CertStats(
        total=sum(status_counts.values()),
        active=status_counts.get("active", 0),
        expired=status_counts.get("expired", 0),
        revoked=status_counts.get("revoked", 0),
        expiring_in_30_days=expiring_30,
        expiring_in_60_days=expiring_60,
        expiring_in_90_days=expiring_90,
        by_datacenter=by_datacenter,
        by_ca_type=by_ca_type,
        by_cert_type=by_cert_type,
    )


@router.get("/{cert_id}", response_model=CertificateResponse)
async def get_certificate(
    cert_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Get a single certificate by ID, including chain and metadata."""
    result = await db.execute(select(Certificate).where(Certificate.id == cert_id))
    cert = result.scalar_one_or_none()
    if not cert:
        raise NotFoundError(f"Certificate {cert_id} not found")
    return CertificateResponse.model_validate(cert)


@router.post("", response_model=CertificateResponse, status_code=201)
async def create_certificate(
    data: CertificateCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Manually register a certificate (metadata only — no private key)."""
    cert = Certificate(
        **data.model_dump(),
        first_seen_at=datetime.now(UTC),
        last_seen_at=datetime.now(UTC),
        discovered_by="manual",
    )
    db.add(cert)
    await db.flush()
    await db.refresh(cert)
    return CertificateResponse.model_validate(cert)


@router.patch("/{cert_id}", response_model=CertificateResponse)
async def update_certificate(
    cert_id: str,
    data: CertificateUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Update certificate metadata (owner, tags, status, datacenter)."""
    result = await db.execute(select(Certificate).where(Certificate.id == cert_id))
    cert = result.scalar_one_or_none()
    if not cert:
        raise NotFoundError(f"Certificate {cert_id} not found")

    update_data = data.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(cert, key, value)

    await db.flush()
    await db.refresh(cert)
    return CertificateResponse.model_validate(cert)


@router.delete("/{cert_id}", status_code=204)
async def delete_certificate(
    cert_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Soft-delete a certificate (deactivate)."""
    result = await db.execute(select(Certificate).where(Certificate.id == cert_id))
    cert = result.scalar_one_or_none()
    if not cert:
        raise NotFoundError(f"Certificate {cert_id} not found")
    cert.status = "revoked"
    await db.flush()


@router.get("/{cert_id}/chain")
async def get_certificate_chain(
    cert_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Get the certificate chain for a given certificate."""
    result = await db.execute(select(Certificate).where(Certificate.id == cert_id))
    cert = result.scalar_one_or_none()
    if not cert:
        raise NotFoundError(f"Certificate {cert_id} not found")

    return {
        "certificate_id": cert_id,
        "chain": [
            {
                "order": c.chain_order,
                "thumbprint": c.cert_pem_sha256,
                "subject": c.cert_subject,
                "issuer": c.cert_issuer,
                "not_after": c.not_after.isoformat() if c.not_after else None,
            }
            for c in sorted(cert.chain_certs, key=lambda x: x.chain_order)
        ],
    }
