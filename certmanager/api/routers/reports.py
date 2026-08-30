"""Compliance reports router."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from certmanager.api.dependencies import get_current_active_user, get_db
from certmanager.core.exceptions import NotFoundError
from certmanager.core.models import ComplianceReport, User

router = APIRouter()

VALID_REPORT_TYPES = {"expiry_summary", "full_inventory", "change_report", "audit_export"}
VALID_FORMATS = {"pdf", "csv", "json"}


class ReportRequest(BaseModel):
    """Body for requesting a compliance report."""

    report_type: str = Field(
        description="expiry_summary | full_inventory | change_report | audit_export"
    )
    parameters: dict | None = None
    file_format: str = Field(default="pdf")


@router.get("")
async def list_reports(
    report_type: str | None = Query(default=None),
    status: str | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """List generated reports."""
    query = select(ComplianceReport)
    if report_type:
        query = query.where(ComplianceReport.report_type == report_type)
    if status:
        query = query.where(ComplianceReport.status == status)

    count_query = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_query)).scalar()

    offset = (page - 1) * page_size
    query = query.order_by(ComplianceReport.created_at.desc()).offset(offset).limit(page_size)

    result = await db.execute(query)
    reports = result.scalars().all()

    return {
        "data": [
            {
                "id": r.id,
                "report_type": r.report_type,
                "status": r.status,
                "file_format": r.file_format,
                "generated_at": r.generated_at.isoformat() if r.generated_at else None,
                "created_at": r.created_at.isoformat(),
            }
            for r in reports
        ],
        "page": page,
        "page_size": page_size,
        "total": total,
    }


@router.post("", status_code=201)
async def request_report(
    body: ReportRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Request generation of a compliance report. Dispatches to Celery."""
    from fastapi import HTTPException

    if body.report_type not in VALID_REPORT_TYPES:
        raise HTTPException(status_code=422, detail=f"Invalid report_type: {body.report_type}")
    if body.file_format not in VALID_FORMATS:
        raise HTTPException(status_code=422, detail=f"Invalid file_format: {body.file_format}")

    report = ComplianceReport(
        report_type=body.report_type,
        status="pending",
        parameters=body.parameters or {},
        file_format=body.file_format,
        generated_by=current_user.id,
    )
    db.add(report)
    await db.flush()
    await db.refresh(report)

    # Dispatch to Celery worker
    try:
        from certmanager.workers.report_worker import generate_report

        generate_report.delay(str(report.id))
    except Exception:
        import structlog

        structlog.get_logger().warning(
            "celery_unavailable_report_pending", report_id=str(report.id)
        )

    return {
        "data": {
            "id": report.id,
            "report_type": report.report_type,
            "status": "pending",
            "message": "Report generation dispatched. Check status for progress.",
        }
    }


@router.get("/{report_id}")
async def get_report(
    report_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Get report status and metadata."""
    result = await db.execute(select(ComplianceReport).where(ComplianceReport.id == report_id))
    report = result.scalar_one_or_none()
    if not report:
        raise NotFoundError(f"Report {report_id} not found")

    return {
        "data": {
            "id": report.id,
            "report_type": report.report_type,
            "status": report.status,
            "parameters": report.parameters,
            "file_format": report.file_format,
            "generated_at": report.generated_at.isoformat() if report.generated_at else None,
            "created_at": report.created_at.isoformat(),
        }
    }


@router.get("/{report_id}/download")
async def download_report(
    report_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Download a generated report file."""
    from pathlib import Path

    from fastapi.responses import FileResponse

    result = await db.execute(select(ComplianceReport).where(ComplianceReport.id == report_id))
    report = result.scalar_one_or_none()
    if not report:
        raise NotFoundError(f"Report {report_id} not found")

    if report.status != "completed":
        return {"data": {"status": report.status, "message": "Report not yet ready"}}

    if not report.file_path or not Path(report.file_path).exists():
        raise NotFoundError("Report file not found on disk")

    ext = report.file_format or "pdf"
    media_types = {"pdf": "application/pdf", "csv": "text/csv", "json": "application/json"}
    return FileResponse(
        path=report.file_path,
        filename=f"certmanager-{report.report_type}-{report_id[:8]}.{ext}",
        media_type=media_types.get(ext, "application/octet-stream"),
    )
