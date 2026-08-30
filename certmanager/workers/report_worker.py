"""Report worker — generates compliance reports via Celery.

Tasks:
- generate_report: Generate a specific report by ID
- scheduled_weekly_report: Weekly expiry summary (runs Mondays)
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from pathlib import Path

import structlog
from celery import shared_task
from celery.utils.log import get_task_logger

from certmanager.core.database import get_session_factory

logger = structlog.get_logger()
task_logger = get_task_logger(__name__)

REPORT_STORAGE = Path("reports")


def _run_async(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


@shared_task(
    name="certmanager.workers.report_worker.generate_report",
    bind=True,
    max_retries=2,
    default_retry_delay=30,
)
def generate_report(self, report_id: str):
    """Generate a specific compliance report by its ID.

    Args:
        report_id: UUID of the ComplianceReport to generate.
    """
    from sqlalchemy import select
    from certmanager.core.models import ComplianceReport
    from certmanager.services.reporting_service import ReportingService

    async def _run():
        factory = get_session_factory()
        async with factory() as db:
            result = await db.execute(
                select(ComplianceReport).where(ComplianceReport.id == report_id)
            )
            report = result.scalar_one_or_none()

            if not report:
                task_logger.error(f"Report {report_id} not found")
                return None

            # Mark as generating
            report.status = "generating"
            await db.flush()

            try:
                service = ReportingService(db)
                file_bytes, mime_type = await service.generate_report(
                    report_type=report.report_type,
                    parameters=report.parameters or {},
                    output_format=report.file_format or "pdf",
                )

                # Save to file storage
                REPORT_STORAGE.mkdir(parents=True, exist_ok=True)
                ext = report.file_format or "pdf"
                file_path = REPORT_STORAGE / f"{report_id}.{ext}"
                file_path.write_bytes(file_bytes)

                report.status = "completed"
                report.file_path = str(file_path)
                report.generated_at = datetime.now(timezone.utc)
                await db.flush()
                await db.commit()

                task_logger.info(
                    f"Report {report_id} generated: "
                    f"type={report.report_type}, size={len(file_bytes)} bytes"
                )
                return {"report_id": report_id, "status": "completed", "size": len(file_bytes)}

            except Exception as e:
                report.status = "failed"
                await db.flush()
                await db.commit()
                task_logger.error(f"Report {report_id} failed: {e}")
                raise

    try:
        return _run_async(_run())
    except Exception as exc:
        raise self.retry(exc=exc)


@shared_task(
    name="certmanager.workers.report_worker.scheduled_weekly_report",
    bind=True,
)
def scheduled_weekly_report(self):
    """Scheduled task: generate a weekly expiry summary report.

    Runs every Monday at 08:00 UTC.
    """
    from certmanager.core.models import ComplianceReport

    async def _run():
        factory = get_session_factory()
        async with factory() as db:
            report = ComplianceReport(
                report_type="expiry_summary",
                status="pending",
                parameters={"days": 30},
                file_format="pdf",
            )
            db.add(report)
            await db.flush()
            await db.refresh(report)
            await db.commit()

            # Dispatch to self synchronously
            generate_report(str(report.id))

            return {"report_id": str(report.id), "status": "dispatched"}

    try:
        result = _run_async(_run())
        task_logger.info(f"Weekly report queued: {result['report_id']}")
        return result
    except Exception as exc:
        task_logger.error(f"Weekly report failed: {exc}")
        raise
