"""Datacenter topology management router."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from certmanager.api.dependencies import get_current_active_user, get_db
from certmanager.core.exceptions import ConflictError, NotFoundError
from certmanager.core.models import Datacenter, User

router = APIRouter()


class DatacenterCreate(BaseModel):
    """Body for registering a datacenter."""

    name: str
    code: str
    location: str | None = None
    timezone: str = "UTC"


class DatacenterUpdate(BaseModel):
    """Body for updating a datacenter — all fields optional."""

    name: str | None = None
    location: str | None = None
    timezone: str | None = None
    is_active: bool | None = None


@router.get("")
async def list_datacenters(
    is_active: bool | None = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """List all datacenters with certificate counts."""
    query = select(Datacenter)
    if is_active is not None:
        query = query.where(Datacenter.is_active == is_active)

    result = await db.execute(query.order_by(Datacenter.name))
    datacenters = result.scalars().all()

    return {
        "data": [
            {
                "id": dc.id,
                "name": dc.name,
                "code": dc.code,
                "location": dc.location,
                "timezone": dc.timezone,
                "is_active": dc.is_active,
                "ca_count": len(dc.certificate_authorities),
                "agent_count": len(dc.agents),
                "cert_count": len(dc.certificates),
                "created_at": dc.created_at.isoformat(),
            }
            for dc in datacenters
        ]
    }


@router.post("", status_code=201)
async def create_datacenter(
    body: DatacenterCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Register a new datacenter."""
    existing = await db.execute(
        select(Datacenter).where(
            (Datacenter.name == body.name) | (Datacenter.code == body.code)
        )
    )
    if existing.scalar_one_or_none():
        raise ConflictError(f"Datacenter '{body.name}' or code '{body.code}' already exists")

    dc = Datacenter(
        name=body.name, code=body.code, location=body.location, timezone=body.timezone
    )
    db.add(dc)
    await db.flush()
    await db.refresh(dc)
    return {"data": {"id": dc.id, "name": dc.name, "code": dc.code}}


@router.get("/{dc_id}")
async def get_datacenter(
    dc_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Get datacenter detail with child CAs and agents."""
    result = await db.execute(select(Datacenter).where(Datacenter.id == dc_id))
    dc = result.scalar_one_or_none()
    if not dc:
        raise NotFoundError(f"Datacenter {dc_id} not found")

    return {
        "data": {
            "id": dc.id,
            "name": dc.name,
            "code": dc.code,
            "location": dc.location,
            "timezone": dc.timezone,
            "is_active": dc.is_active,
            "certificate_authorities": [
                {
                    "id": ca.id,
                    "name": ca.name,
                    "ca_type": ca.ca_type,
                    "health_status": ca.health_status,
                }
                for ca in dc.certificate_authorities
            ],
            "agents": [
                {"id": a.id, "name": a.name, "agent_type": a.agent_type, "status": a.status}
                for a in dc.agents
            ],
        }
    }


@router.patch("/{dc_id}")
async def update_datacenter(
    dc_id: str,
    body: DatacenterUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Update a datacenter."""
    result = await db.execute(select(Datacenter).where(Datacenter.id == dc_id))
    dc = result.scalar_one_or_none()
    if not dc:
        raise NotFoundError(f"Datacenter {dc_id} not found")

    for field in ("name", "location", "timezone", "is_active"):
        value = getattr(body, field)
        if value is not None:
            setattr(dc, field, value)

    await db.flush()
    return {"data": {"id": dc.id, "updated": True}}


@router.delete("/{dc_id}", status_code=204)
async def delete_datacenter(
    dc_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Remove a datacenter. Must have no CAs or agents."""
    result = await db.execute(select(Datacenter).where(Datacenter.id == dc_id))
    dc = result.scalar_one_or_none()
    if not dc:
        raise NotFoundError(f"Datacenter {dc_id} not found")

    if dc.certificate_authorities or dc.agents:
        raise ConflictError("Datacenter must have no CAs or agents before deletion")

    await db.delete(dc)
    await db.flush()
