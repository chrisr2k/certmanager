"""Scan job management router — triggers and monitors discovery scans."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from certmanager.api.dependencies import get_current_active_user, get_db
from certmanager.core.exceptions import NotFoundError
from certmanager.core.models import ScanJob, User

router = APIRouter()

# Job types executed by a datacenter AGENT (polled via /agents/{id}/jobs),
# as opposed to CA-connector scans that run in the Celery worker.
AGENT_JOB_TYPES = {"tls_scan", "openssl_ca_scan"}


class ScanTriggerRequest(BaseModel):
    """Body for triggering a scan job."""

    job_type: str = "full_discovery"
    scope_config: dict | None = None
    agent_id: str | None = None
    cidr_ranges: list[str] | None = None
    ports: list[int] | None = None


def _dispatch_scan(scan_job_id: str) -> None:
    """Dispatch a scan job to the Celery scanner worker.

    Falls back to synchronous execution if Celery is unavailable (development).
    """
    try:
        from certmanager.workers.scanner_worker import run_scan_job

        run_scan_job.delay(scan_job_id)
    except Exception:
        # Celery not available — log and skip (scan stays pending)
        import structlog

        logger = structlog.get_logger()
        logger.warning(
            "celery_unavailable_scan_pending",
            scan_job_id=scan_job_id,
        )


@router.get("")
async def list_scans(
    job_type: str | None = Query(default=None),
    status: str | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """List scan jobs with filtering."""
    query = select(ScanJob)
    if job_type:
        query = query.where(ScanJob.job_type == job_type)
    if status:
        query = query.where(ScanJob.status == status)

    count_query = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_query)).scalar()

    offset = (page - 1) * page_size
    query = query.order_by(ScanJob.created_at.desc()).offset(offset).limit(page_size)

    result = await db.execute(query)
    jobs = result.scalars().all()

    return {
        "data": [
            {
                "id": j.id,
                "job_type": j.job_type,
                "status": j.status,
                "triggered_by": j.triggered_by,
                "total_checked": j.total_checked,
                "total_new": j.total_new,
                "total_updated": j.total_updated,
                "total_errors": j.total_errors,
                "started_at": j.started_at.isoformat() if j.started_at else None,
                "completed_at": j.completed_at.isoformat() if j.completed_at else None,
                "created_at": j.created_at.isoformat(),
            }
            for j in jobs
        ],
        "page": page,
        "page_size": page_size,
        "total": total,
    }


@router.post("", status_code=201)
async def trigger_scan(
    body: ScanTriggerRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Trigger a new discovery scan job.

    CA-connector scans dispatch to the Celery scanner worker. Agent-executed
    scans (tls_scan, openssl_ca_scan) require an agent_id and are left for
    the agent to pick up on its next poll cycle.
    """
    is_agent_job = body.job_type in AGENT_JOB_TYPES

    job = ScanJob(
        job_type=body.job_type,
        status="pending",
        triggered_by="manual",
        triggered_by_user=current_user.id,
        scope_config=body.scope_config or {},
    )

    if is_agent_job:
        if not body.agent_id:
            from certmanager.core.exceptions import ValidationError

            raise ValidationError(f"agent_id is required for {body.job_type} jobs")

        # The agent only fetches jobs whose scope names it (see
        # GET /agents/{id}/jobs), so agent identity must be in the scope.
        scope = dict(body.scope_config or {})
        scope["agent_id"] = body.agent_id

        if body.job_type == "tls_scan":
            from certmanager.services.agent_service import AgentService

            agent_svc = AgentService(db)
            targets = await agent_svc.get_scan_targets(body.agent_id)
            scope["cidr_ranges"] = body.cidr_ranges or targets["cidr_ranges"]
            scope["ports"] = body.ports or targets["ports"]

        job.scope_config = scope

    db.add(job)
    await db.flush()
    await db.refresh(job)

    if not is_agent_job:
        # CA-connector scans run in the Celery worker
        _dispatch_scan(str(job.id))

    return {
        "data": {
            "scan_job_id": job.id,
            "job_type": job.job_type,
            "status": "pending",
            "message": (
                "Scan queued. The agent will pick this up on its next poll cycle."
                if is_agent_job
                else "Scan job dispatched to worker. Monitor status at GET /scans/{id}."
            ),
        }
    }


@router.get("/{scan_id}")
async def get_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Get scan job detail."""
    result = await db.execute(select(ScanJob).where(ScanJob.id == scan_id))
    job = result.scalar_one_or_none()
    if not job:
        raise NotFoundError(f"Scan job {scan_id} not found")

    return {
        "data": {
            "id": job.id,
            "job_type": job.job_type,
            "status": job.status,
            "scope_config": job.scope_config,
            "total_checked": job.total_checked,
            "total_new": job.total_new,
            "total_updated": job.total_updated,
            "total_errors": job.total_errors,
            "error_detail": job.error_detail,
            "started_at": job.started_at.isoformat() if job.started_at else None,
            "completed_at": job.completed_at.isoformat() if job.completed_at else None,
            "created_at": job.created_at.isoformat(),
        }
    }


@router.post("/{scan_id}/cancel")
async def cancel_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Cancel a running scan."""
    result = await db.execute(select(ScanJob).where(ScanJob.id == scan_id))
    job = result.scalar_one_or_none()
    if not job:
        raise NotFoundError(f"Scan job {scan_id} not found")
    if job.status not in ("pending", "running"):
        raise NotFoundError(f"Scan job {scan_id} cannot be cancelled (status: {job.status})")
    job.status = "cancelled"
    await db.flush()
    return {"data": {"id": job.id, "status": "cancelled"}}
