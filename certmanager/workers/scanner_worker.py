"""Scanner worker — executes certificate discovery scans as Celery tasks.

Tasks:
- run_scan_job: Execute a specific ScanJob by ID
- run_full_discovery: Scan all active CAs (scheduled task)
- run_health_checks: Health check all active CAs (scheduled task)
- auto_expire_certificates: Mark expired certs (scheduled task)
"""

from __future__ import annotations

import asyncio

import structlog
from celery import shared_task
from celery.utils.log import get_task_logger

from certmanager.core.database import get_session_factory

logger = structlog.get_logger()
task_logger = get_task_logger(__name__)


def _run_async(coro):
    """Helper to run an async coroutine from a synchronous Celery task."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


@shared_task(
    name="certmanager.workers.scanner_worker.run_scan_job",
    bind=True,
    max_retries=3,
    default_retry_delay=60,
)
def run_scan_job(self, scan_job_id: str):
    """Execute a discovery scan for a specific ScanJob.

    Called when a user triggers a scan via API or CLI.

    Args:
        scan_job_id: UUID of the ScanJob to execute.
    """
    from certmanager.services.discovery_service import DiscoveryService

    async def _run():
        factory = get_session_factory()
        async with factory() as db:
            service = DiscoveryService(db)
            result = await service.run_discovery(scan_job_id)
            await db.commit()
            return result

    try:
        result = _run_async(_run())
        task_logger.info(
            f"Scan job {scan_job_id} completed: "
            f"{result['total_new']} new, "
            f"{result['total_updated']} updated, "
            f"{result['total_errors']} errors"
        )
        return result
    except Exception as exc:
        task_logger.error(f"Scan job {scan_job_id} failed: {exc}")
        # Retry with exponential backoff
        raise self.retry(exc=exc, countdown=60 * (2**self.request.retries)) from exc


@shared_task(
    name="certmanager.workers.scanner_worker.run_full_discovery",
    bind=True,
)
def run_full_discovery(self):
    """Scheduled task: run full discovery on all active CAs.

    Creates a new ScanJob and executes it. Runs daily at 03:00 UTC.
    """
    from certmanager.core.models import ScanJob
    from certmanager.services.discovery_service import DiscoveryService

    async def _run():
        factory = get_session_factory()
        async with factory() as db:
            # Create a scan job
            job = ScanJob(
                job_type="full_discovery",
                status="pending",
                triggered_by="schedule",
            )
            db.add(job)
            await db.flush()
            await db.refresh(job)

            service = DiscoveryService(db)
            result = await service.run_discovery(str(job.id))
            await db.commit()
            return result

    try:
        result = _run_async(_run())
        task_logger.info(
            f"Scheduled full discovery completed: "
            f"{result['total_new']} new, "
            f"{result['total_updated']} updated"
        )
        return result
    except Exception as exc:
        task_logger.error(f"Scheduled full discovery failed: {exc}")
        raise


@shared_task(
    name="certmanager.workers.scanner_worker.run_health_checks",
    bind=True,
)
def run_health_checks(self):
    """Scheduled task: run health checks on all active CAs.

    Runs every 15 minutes. Updates CA health_status in the database.
    """
    from certmanager.services.discovery_service import DiscoveryService

    async def _run():
        factory = get_session_factory()
        async with factory() as db:
            service = DiscoveryService(db)
            results = await service.run_health_checks()
            await db.commit()
            return results

    try:
        results = _run_async(_run())
        healthy = sum(1 for v in results.values() if v == "healthy")
        unhealthy = sum(1 for v in results.values() if v == "unhealthy")
        task_logger.info(f"CA health checks complete: {healthy} healthy, {unhealthy} unhealthy")
        return results
    except Exception as exc:
        task_logger.error(f"Health checks failed: {exc}")
        raise


@shared_task(
    name="certmanager.workers.scanner_worker.auto_expire_certificates",
    bind=True,
)
def auto_expire_certificates(self):
    """Scheduled task: mark expired certificates.

    Runs daily at 07:00 UTC.
    """
    from certmanager.services.certificate_service import CertificateService

    async def _run():
        factory = get_session_factory()
        async with factory() as db:
            service = CertificateService(db)
            count = await service.auto_expire_certificates()
            await db.commit()
            return count

    try:
        count = _run_async(_run())
        task_logger.info(f"Auto-expired {count} certificates")
        return count
    except Exception as exc:
        task_logger.error(f"Auto-expire failed: {exc}")
        raise


@shared_task(
    name="certmanager.workers.scanner_worker.scheduled_tls_scans",
    bind=True,
)
def scheduled_tls_scans(self):
    """Scheduled task: create TLS scan jobs for all TLS-capable agents.

    Runs weekly (Sunday 02:00 UTC). Each agent picks up its job on next poll.
    """
    from certmanager.services.agent_service import AgentService

    async def _run():
        factory = get_session_factory()
        async with factory() as db:
            svc = AgentService(db)
            agents = await svc.get_tls_capable_agents()

            created = 0
            for agent in agents:
                schedule = agent["scan_targets"].get("scan_schedule", "weekly")
                # Only create jobs for agents whose schedule matches
                if schedule in ("daily", "weekly"):
                    await svc.create_tls_scan_job(
                        agent_id=agent["id"],
                        triggered_by="schedule",
                    )
                    created += 1

            await db.commit()
            return {"created": created}

    try:
        result = _run_async(_run())
        task_logger.info(f"Scheduled TLS scans created: {result['created']} jobs")
        return result
    except Exception as exc:
        task_logger.error(f"Scheduled TLS scans failed: {exc}")
        raise


@shared_task(
    name="certmanager.workers.scanner_worker.scan_single_authority",
    bind=True,
    max_retries=2,
    default_retry_delay=30,
)
def scan_single_authority(self, authority_id: str):
    """On-demand task: scan a single Certificate Authority.

    Args:
        authority_id: UUID of the CertificateAuthority to scan.
    """
    from certmanager.core.models import ScanJob
    from certmanager.services.discovery_service import DiscoveryService

    async def _run():
        factory = get_session_factory()
        async with factory() as db:
            # Create a quick scan job for tracking
            job = ScanJob(
                job_type="ca_sync",
                status="pending",
                triggered_by="api",
                scope_config={"ca_ids": [authority_id]},
            )
            db.add(job)
            await db.flush()
            await db.refresh(job)

            service = DiscoveryService(db)
            stats = await service.scan_authority(
                authority_id=authority_id,
                scan_job_id=str(job.id),
            )

            # Mark job complete
            job.status = "completed"
            job.total_checked = stats["total"]
            job.total_new = stats["new"]
            job.total_updated = stats["updated"]
            job.total_errors = stats["errors"]
            await db.commit()

            return stats

    try:
        result = _run_async(_run())
        task_logger.info(
            f"Authority {authority_id} scanned: {result['new']} new, {result['updated']} updated"
        )
        return result
    except Exception as exc:
        task_logger.error(f"Authority scan failed for {authority_id}: {exc}")
        raise self.retry(exc=exc) from exc
