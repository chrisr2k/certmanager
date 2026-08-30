"""Agent management router — datacenter agent registration, heartbeat, job dispatch."""

from __future__ import annotations

from datetime import datetime, UTC
from typing import Optional

from fastapi import APIRouter, Depends, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from certmanager.api.dependencies import get_current_active_user, get_db
from certmanager.core.exceptions import AgentRegistrationError, NotFoundError
from certmanager.core.models import Agent, User
from certmanager.core.security import create_access_token

router = APIRouter()


# --- Agent registration (uses PSK, not user JWT) ---

@router.post("/register", status_code=201)
async def register_agent(
    request: Request,
    name: str,
    agent_type: str,
    datacenter_code: str,
    hostname: Optional[str] = None,
    psk: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    """Register a new datacenter agent using a pre-shared key.

    This endpoint does NOT require a user JWT — it authenticates via PSK.
    """
    from certmanager.core.config import get_settings
    from certmanager.core.crypto import encrypt_value
    import hashlib

    settings = get_settings()

    # Validate PSK
    expected_psk = settings.agent.psk
    if not expected_psk or psk != expected_psk:
        raise AgentRegistrationError("Invalid pre-shared key")

    # Find datacenter by code
    from certmanager.core.models import Datacenter

    dc_result = await db.execute(
        select(Datacenter).where(Datacenter.code == datacenter_code)
    )
    datacenter = dc_result.scalar_one_or_none()
    if not datacenter:
        raise AgentRegistrationError(f"Datacenter '{datacenter_code}' not found. Create it first.")

    # Check for duplicate agent
    existing = await db.execute(select(Agent).where(Agent.name == name))
    if existing.scalar_one_or_none():
        raise AgentRegistrationError(f"Agent '{name}' already registered")

    # Generate agent token
    import secrets
    agent_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(agent_token.encode()).hexdigest()

    agent = Agent(
        name=name,
        agent_type=agent_type,
        datacenter_id=datacenter.id,
        hostname=hostname,
        ip_address=request.client.host if request.client else None,
        version="0.1.0",
        auth_token_hash=token_hash,
        status="unapproved",
        is_approved=False,
    )
    db.add(agent)
    await db.flush()
    await db.refresh(agent)

    # Create an agent JWT for API access
    agent_jwt = create_access_token(
        subject=agent.id,
        extra_claims={
            "type": "agent",
            "agent_name": name,
            "agent_type": agent_type,
            "datacenter_id": datacenter.id,
        },
    )

    return {
        "data": {
            "agent_id": str(agent.id),
            "name": name,
            "status": "unapproved",
            "agent_token": agent_token,  # Return ONCE — agent stores this
            "api_token": agent_jwt,
            "message": "Agent registered. Awaiting admin approval.",
        }
    }


# --- Agent heartbeat ---

@router.post("/{agent_id}/heartbeat")
async def agent_heartbeat(
    agent_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Agent heartbeat — updates last seen timestamp. Uses agent auth (set by RBAC middleware)."""
    result = await db.execute(select(Agent).where(Agent.id == agent_id))
    agent = result.scalar_one_or_none()
    if not agent:
        raise NotFoundError(f"Agent {agent_id} not found")

    agent.last_heartbeat_at = datetime.now(UTC)
    agent.status = "online" if agent.is_approved else "unapproved"
    agent.ip_address = request.client.host if request.client else agent.ip_address
    await db.flush()

    # Return any pending jobs count
    from certmanager.core.models import ScanJob
    pending = await db.execute(
        select(ScanJob).where(
            ScanJob.status == "pending",
            ScanJob.scope_config.contains({"agent_id": agent_id}),
        )
    )
    pending_count = len(pending.scalars().all())

    return {"data": {"status": agent.status, "pending_jobs": pending_count}}


# --- Agent job polling ---

@router.get("/{agent_id}/jobs")
async def fetch_agent_jobs(
    agent_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Agent polls for pending jobs."""
    result = await db.execute(select(Agent).where(Agent.id == agent_id))
    agent = result.scalar_one_or_none()
    if not agent:
        raise NotFoundError(f"Agent {agent_id} not found")

    from certmanager.core.models import ScanJob

    jobs_result = await db.execute(
        select(ScanJob)
        .where(
            ScanJob.status == "pending",
            ScanJob.scope_config.contains({"agent_id": agent_id}),
        )
        .limit(5)
    )
    jobs = jobs_result.scalars().all()

    return {
        "data": {
            "jobs": [
                {
                    "id": j.id,
                    "job_type": j.job_type,
                    "scope_config": j.scope_config,
                    "created_at": j.created_at.isoformat(),
                }
                for j in jobs
            ]
        }
    }


# --- Agent job result submission ---

@router.post("/{agent_id}/jobs/{job_id}/result")
async def submit_job_result(
    agent_id: str,
    job_id: str,
    result_data: dict,
    db: AsyncSession = Depends(get_db),
):
    """Agent submits job results."""
    from certmanager.core.models import ScanJob

    job_result = await db.execute(select(ScanJob).where(ScanJob.id == job_id))
    job = job_result.scalar_one_or_none()
    if not job:
        raise NotFoundError(f"Job {job_id} not found")

    job.status = "completed"
    job.completed_at = datetime.now(UTC)

    # Merge results: update certificate inventory
    certificates_found = result_data.get("certificates", [])
    job.total_checked = result_data.get("total_checked", 0)
    job.total_new = result_data.get("total_new", 0)
    job.total_updated = result_data.get("total_updated", 0)
    job.total_errors = result_data.get("total_errors", 0)

    await db.flush()

    return {
        "data": {
            "job_id": job_id,
            "status": "completed",
            "certificates_received": len(certificates_found),
        }
    }


# --- Admin agent management ---

@router.get("")
async def list_agents(
    status: Optional[str] = None,
    agent_type: Optional[str] = None,
    dc_id: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """List all registered agents (admin)."""
    query = select(Agent)
    if status:
        query = query.where(Agent.status == status)
    if agent_type:
        query = query.where(Agent.agent_type == agent_type)
    if dc_id:
        query = query.where(Agent.datacenter_id == dc_id)

    result = await db.execute(query.order_by(Agent.name))
    agents = result.scalars().all()

    return {
        "data": [
            {
                "id": a.id,
                "name": a.name,
                "agent_type": a.agent_type,
                "datacenter_id": a.datacenter_id,
                "hostname": a.hostname,
                "ip_address": a.ip_address,
                "version": a.version,
                "status": a.status,
                "is_approved": a.is_approved,
                "last_heartbeat_at": a.last_heartbeat_at.isoformat() if a.last_heartbeat_at else None,
            }
            for a in agents
        ]
    }


@router.patch("/{agent_id}/approve")
async def approve_agent(
    agent_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Approve a pending agent registration."""
    result = await db.execute(select(Agent).where(Agent.id == agent_id))
    agent = result.scalar_one_or_none()
    if not agent:
        raise NotFoundError(f"Agent {agent_id} not found")

    agent.is_approved = True
    agent.status = "online" if agent.last_heartbeat_at else "offline"
    await db.flush()

    return {"data": {"id": agent.id, "name": agent.name, "status": agent.status}}


@router.delete("/{agent_id}", status_code=204)
async def delete_agent(
    agent_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Remove an agent."""
    result = await db.execute(select(Agent).where(Agent.id == agent_id))
    agent = result.scalar_one_or_none()
    if not agent:
        raise NotFoundError(f"Agent {agent_id} not found")
    await db.delete(agent)
    await db.flush()


# --- TLS Scan Target Management ---

@router.get("/{agent_id}/scan-targets")
async def get_scan_targets(
    agent_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Get the TLS scan target configuration for an agent."""
    from certmanager.services.agent_service import AgentService

    svc = AgentService(db)
    targets = await svc.get_scan_targets(agent_id)
    return {"data": targets}


@router.patch("/{agent_id}/scan-targets")
async def update_scan_targets(
    agent_id: str,
    cidr_ranges: list[str] | None = None,
    ports: list[int] | None = None,
    exclude_cidrs: list[str] | None = None,
    scan_schedule: str | None = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Update TLS scan target configuration for an agent."""
    from certmanager.services.agent_service import AgentService

    svc = AgentService(db)
    targets = await svc.update_scan_targets(
        agent_id=agent_id,
        cidr_ranges=cidr_ranges,
        ports=ports,
        exclude_cidrs=exclude_cidrs,
        scan_schedule=scan_schedule,
    )
    return {"data": targets}


@router.post("/{agent_id}/scan-targets/scan", status_code=201)
async def trigger_tls_scan(
    agent_id: str,
    cidr_ranges: list[str] | None = None,
    ports: list[int] | None = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Trigger a TLS scan on a specific agent."""
    from certmanager.services.agent_service import AgentService

    svc = AgentService(db)
    job_id = await svc.create_tls_scan_job(
        agent_id=agent_id,
        cidr_ranges=cidr_ranges,
        ports=ports,
        triggered_by="manual",
        triggered_by_user=current_user.id,
    )

    return {
        "data": {
            "scan_job_id": job_id,
            "agent_id": agent_id,
            "status": "pending",
            "message": "TLS scan queued. Agent will execute on next poll cycle.",
        }
    }


@router.get("/tls-capable")
async def list_tls_capable_agents(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """List all agents capable of TLS scanning with their scan targets."""
    from certmanager.services.agent_service import AgentService

    svc = AgentService(db)
    agents = await svc.get_tls_capable_agents()
    return {"data": agents}
