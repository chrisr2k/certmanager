"""Agent management router — datacenter agent registration, heartbeat, job dispatch.

Agent-facing endpoints authenticate via agent JWTs minted at registration
(validated by the RBAC middleware, which sets request.state.actor_type ==
"agent" and actor_id == agent UUID). Every agent-facing endpoint re-verifies
that the authenticated agent matches the {agent_id} in the URL and enforces
approval status — one agent may never read or submit another agent's jobs.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from certmanager.api.dependencies import get_current_active_user, get_db
from certmanager.core.exceptions import (
    AgentRegistrationError,
    AuthorizationError,
    NotFoundError,
)
from certmanager.core.models import Agent, Datacenter, ScanJob, User
from certmanager.core.security import create_access_token

router = APIRouter()

# Agent JWTs are long-lived; agents re-register (idempotently, with the PSK)
# before expiry instead of running a refresh-token flow.
AGENT_TOKEN_TTL = timedelta(days=30)

SENSITIVE_PSK_HINT = "[REDACTED]"


# --- Request bodies ---


class AgentRegisterRequest(BaseModel):
    """Agent registration payload (PSK handshake)."""

    name: str
    agent_type: str
    datacenter_code: str
    hostname: str | None = None
    psk: str | None = None


class ScanTargetsUpdate(BaseModel):
    """Body for updating an agent's TLS scan targets."""

    cidr_ranges: list[str] | None = None
    ports: list[int] | None = None
    exclude_cidrs: list[str] | None = None
    scan_schedule: str | None = None


class TLSScanRequest(BaseModel):
    """Body for triggering a manual TLS scan on an agent."""

    cidr_ranges: list[str] | None = None
    ports: list[int] | None = None


# --- Helpers ---


async def _require_agent(
    request: Request,
    agent_id: str,
    db: AsyncSession,
    *,
    require_approved: bool,
) -> Agent:
    """Resolve the agent named in the URL and verify the caller owns it.

    The RBAC middleware has already validated the JWT signature. Here we
    enforce that the token belongs to THIS agent (no cross-agent IDOR) and
    that the agent is approved before it may touch jobs or results.
    """
    if (
        getattr(request.state, "actor_type", None) != "agent"
        or getattr(request.state, "actor_id", None) != agent_id
    ):
        raise AuthorizationError("Agent token does not match the requested agent")

    result = await db.execute(select(Agent).where(Agent.id == agent_id))
    agent = result.scalar_one_or_none()
    if not agent:
        raise NotFoundError(f"Agent {agent_id} not found")

    if require_approved and not agent.is_approved:
        raise AuthorizationError("Agent is not approved by an administrator")

    return agent


# --- Agent registration (uses PSK, not user JWT) ---


@router.post("/register", status_code=201)
async def register_agent(
    request: Request,
    body: AgentRegisterRequest,
    db: AsyncSession = Depends(get_db),
):
    """Register a new datacenter agent using a pre-shared key.

    This endpoint does NOT require a user JWT — it authenticates via PSK.
    Re-registration (e.g. after a restart or expired token) is idempotent:
    an existing agent with the same name receives a fresh JWT but keeps its
    permanent agent_token hash.
    """
    from certmanager.core.config import get_settings

    settings = get_settings()

    # Constant-time PSK comparison
    expected_psk = settings.agent.psk
    if not expected_psk or body.psk is None or not hmac.compare_digest(expected_psk, body.psk):
        raise AgentRegistrationError("Invalid pre-shared key")

    # Find datacenter by code
    dc_result = await db.execute(select(Datacenter).where(Datacenter.code == body.datacenter_code))
    datacenter = dc_result.scalar_one_or_none()
    if not datacenter:
        raise AgentRegistrationError(
            f"Datacenter '{body.datacenter_code}' not found. Create it first."
        )

    # Idempotent: reuse the existing agent on re-registration
    existing_result = await db.execute(select(Agent).where(Agent.name == body.name))
    agent = existing_result.scalar_one_or_none()

    agent_token: str | None = None  # returned only on FIRST registration

    if agent is None:
        agent_token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(agent_token.encode()).hexdigest()

        agent = Agent(
            name=body.name,
            agent_type=body.agent_type,
            datacenter_id=datacenter.id,
            hostname=body.hostname,
            ip_address=request.client.host if request.client else None,
            version="0.1.0",
            auth_token_hash=token_hash,
            status="unapproved",
            is_approved=False,
        )
        db.add(agent)
        await db.flush()
        await db.refresh(agent)
    else:
        # Refresh mutable identity fields on re-registration
        agent.datacenter_id = datacenter.id
        agent.hostname = body.hostname or agent.hostname
        agent.ip_address = request.client.host if request.client else agent.ip_address
        agent.version = "0.1.0"
        await db.flush()

    # Mint a long-lived agent JWT for API access
    agent_jwt = create_access_token(
        subject=agent.id,
        extra_claims={
            "type": "agent",
            "agent_name": agent.name,
            "agent_type": agent.agent_type,
            "datacenter_id": agent.datacenter_id,
        },
        expires_delta=AGENT_TOKEN_TTL,
    )
    expires_at = datetime.now(UTC) + AGENT_TOKEN_TTL

    response: dict = {
        "agent_id": str(agent.id),
        "name": agent.name,
        "status": agent.status,
        "api_token": agent_jwt,
        "api_token_expires_at": expires_at.isoformat(),
        "message": "Agent registered. Awaiting admin approval."
        if not agent.is_approved
        else "Agent re-registered.",
    }
    if agent_token is not None:
        # Return the permanent agent token ONCE — the agent stores it for
        # the connector listener; only a hash is kept server-side.
        response["agent_token"] = agent_token
        response["message"] = (
            "Agent registered. Store the agent_token — it will not be shown again."
        )

    return {"data": response}


# --- Agent heartbeat ---


@router.post("/{agent_id}/heartbeat")
async def agent_heartbeat(
    agent_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Agent heartbeat — updates last seen timestamp. Uses agent auth (set by RBAC middleware)."""
    agent = await _require_agent(request, agent_id, db, require_approved=False)

    agent.last_heartbeat_at = datetime.now(UTC)
    agent.status = "online" if agent.is_approved else "unapproved"
    agent.ip_address = request.client.host if request.client else agent.ip_address
    await db.flush()

    # Return any pending jobs count
    pending = await db.execute(
        select(ScanJob).where(
            ScanJob.status == "pending",
            # Portable JSON path lookup (->> on PG, json_extract on SQLite)
            ScanJob.scope_config["agent_id"].as_string() == agent_id,
        )
    )
    pending_count = len(pending.scalars().all())

    return {"data": {"status": agent.status, "pending_jobs": pending_count}}


# --- Agent job polling ---


@router.get("/{agent_id}/jobs")
async def fetch_agent_jobs(
    agent_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Agent polls for pending jobs."""
    await _require_agent(request, agent_id, db, require_approved=True)

    jobs_result = await db.execute(
        select(ScanJob)
        .where(
            ScanJob.status == "pending",
            # Portable JSON path lookup (->> on PG, json_extract on SQLite)
            ScanJob.scope_config["agent_id"].as_string() == agent_id,
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
    request: Request,
    result_data: dict,
    db: AsyncSession = Depends(get_db),
):
    """Agent submits job results. Discovered certificates are persisted to inventory."""
    agent = await _require_agent(request, agent_id, db, require_approved=True)

    job_result = await db.execute(select(ScanJob).where(ScanJob.id == job_id))
    job = job_result.scalar_one_or_none()
    if not job:
        raise NotFoundError(f"Job {job_id} not found")

    # The job must belong to this agent
    if job.scope_config.get("agent_id") != agent_id:
        raise AuthorizationError(f"Job {job_id} is not assigned to agent {agent_id}")

    job.status = "completed"
    job.completed_at = datetime.now(UTC)
    job.total_checked = result_data.get("total_checked", 0)
    job.total_new = result_data.get("total_new", 0)
    job.total_updated = result_data.get("total_updated", 0)
    job.total_errors = result_data.get("total_errors", 0)
    agent.last_job_at = datetime.now(UTC)

    # Merge results: persist discovered certificates into the inventory
    cert_dicts = result_data.get("certificates", [])
    upsert_stats = {"new": 0, "updated": 0, "unchanged": 0, "errors": 0}
    if cert_dicts:
        from certmanager.services.certificate_service import CertificateService

        records = [_certificate_record_from_agent_data(d) for d in cert_dicts]
        records = [r for r in records if r is not None]

        source_type = "tls_scan" if job.job_type == "tls_scan" else "adcs"
        service = CertificateService(db)
        upsert_stats = await service.upsert_from_discovery(
            records=records,
            source_ca_id=None,  # agent-discovered certs may have no central CA row
            source_type=source_type,
            datacenter_id=agent.datacenter_id,
            scan_job_id=job_id,
        )

        # Reflect what actually got persisted
        job.total_new = upsert_stats["new"]
        job.total_updated = upsert_stats["updated"]
        job.total_errors += upsert_stats["errors"]

    await db.flush()

    return {
        "data": {
            "job_id": job_id,
            "status": "completed",
            "certificates_received": len(cert_dicts),
            "persisted": upsert_stats,
        }
    }


def _certificate_record_from_agent_data(data: dict):
    """Convert an agent-reported certificate dict into a CertificateRecord.

    Agent payloads use the same normalized shape as the AD CS scanner's
    API result (see certmanager/agent/scanners/adcs_scanner.py).
    """
    from certmanager.connectors.base import CertificateRecord

    if not isinstance(data, dict) or not data.get("common_name"):
        return None

    not_before = data.get("not_before")
    not_after = data.get("not_after")
    try:
        not_before = (
            datetime.fromisoformat(not_before) if not_before else datetime.min.replace(tzinfo=UTC)
        )
        not_after = (
            datetime.fromisoformat(not_after) if not_after else datetime.max.replace(tzinfo=UTC)
        )
    except ValueError:
        return None

    if not_after.tzinfo is None:
        not_after = not_after.replace(tzinfo=UTC)
    if not_before.tzinfo is None:
        not_before = not_before.replace(tzinfo=UTC)

    source_id = data.get("request_id") or data.get("serial_number") or data.get("source_id", "")
    thumbprint = data.get("thumbprint") or data.get("thumbprint_sha256", "")

    return CertificateRecord(
        common_name=data["common_name"],
        subject=data.get("subject") or f"CN={data['common_name']}",
        issuer=data.get("issuer", ""),
        serial_number=data.get("serial_number", ""),
        thumbprint_sha256=thumbprint,
        not_before=not_before,
        not_after=not_after,
        validity_days=(
            int((not_after - not_before).total_seconds() / 86400)
            if not_before != datetime.min.replace(tzinfo=UTC)
            and not_after != datetime.max.replace(tzinfo=UTC)
            else None
        ),
        key_algorithm=data.get("key_algorithm", "unknown"),
        signature_algorithm=data.get("signature_algorithm", "unknown"),
        sans=data.get("sans", []),
        cert_type=data.get("cert_type", "server"),
        is_wildcard=data.get("is_wildcard", False),
        source_detail={
            k: v
            for k, v in data.items()
            if k in ("request_id", "template", "ca_server", "ca_name", "host", "port")
        },
        source_id=source_id,
        status=data.get("status", "active"),
    )


# --- Admin agent management ---


@router.get("")
async def list_agents(
    status: str | None = None,
    agent_type: str | None = None,
    dc_id: str | None = None,
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
                "last_heartbeat_at": a.last_heartbeat_at.isoformat()
                if a.last_heartbeat_at
                else None,
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
    body: ScanTargetsUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Update TLS scan target configuration for an agent."""
    from certmanager.services.agent_service import AgentService

    svc = AgentService(db)
    targets = await svc.update_scan_targets(
        agent_id=agent_id,
        cidr_ranges=body.cidr_ranges,
        ports=body.ports,
        exclude_cidrs=body.exclude_cidrs,
        scan_schedule=body.scan_schedule,
    )
    return {"data": targets}


@router.post("/{agent_id}/scan-targets/scan", status_code=201)
async def trigger_tls_scan(
    agent_id: str,
    body: TLSScanRequest | None = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Trigger a TLS scan on a specific agent.

    With no body (or omitted ranges/ports), the agent's stored scan
    targets are used — this is how the UI's Scan Now button behaves.
    """
    from certmanager.services.agent_service import AgentService

    svc = AgentService(db)
    job_id = await svc.create_tls_scan_job(
        agent_id=agent_id,
        cidr_ranges=body.cidr_ranges if body else None,
        ports=body.ports if body else None,
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
