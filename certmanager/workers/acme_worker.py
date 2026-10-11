"""ACME worker — issues/renews certificates and purges expired key bundles.

Tasks:
- issue_or_renew_task: Execute a specific acme_issue/acme_renew ScanJob
- auto_renew_expiring_acme_certs: Renew ACME certs nearing expiry (scheduled)
- purge_expired_key_bundles: Delete expired CertificateKeyBundle rows (scheduled)
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import structlog
from celery import shared_task
from celery.utils.log import get_task_logger
from sqlalchemy import delete, select

from certmanager.core.database import get_session_factory

logger = structlog.get_logger()
task_logger = get_task_logger(__name__)

# Days before expiry that a scheduled renewal is triggered.
DEFAULT_RENEWAL_WINDOW_DAYS = 30


def _run_async(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _friendly_error_detail(exc: Exception) -> str:
    """Distinguish a DNS-validation timeout from other failures so an
    operator isn't left guessing from a raw stack string."""
    text = str(exc).lower()
    if "propagat" in text or ("authoriz" in text and "timeout" in text):
        return (
            f"DNS validation timeout — check the TXT record propagated and no CAA record "
            f"blocks the CA: {exc}"
        )
    return str(exc)


@shared_task(
    name="certmanager.workers.acme_worker.issue_or_renew_task",
    bind=True,
    max_retries=2,
    default_retry_delay=60,
)
def issue_or_renew_task(self, job_id: str):
    """Execute an acme_issue/acme_renew ScanJob."""
    from certmanager.core.models import ScanJob
    from certmanager.services.acme_service import AcmeService

    async def _run():
        factory = get_session_factory()
        async with factory() as db:
            result = await db.execute(select(ScanJob).where(ScanJob.id == job_id))
            job = result.scalar_one_or_none()
            if job is None:
                task_logger.error(f"ACME job {job_id} not found")
                return None

            job.status = "running"
            job.started_at = datetime.now(UTC)
            await db.flush()

            scope = job.scope_config or {}
            service = AcmeService(db)

            try:
                outcome = await service.issue_or_renew(
                    authority_id=scope["authority_id"],
                    mode="issue" if job.job_type == "acme_issue" else "renew",
                    scan_job_id=job_id,
                    common_name=scope.get("common_name"),
                    sans=scope.get("sans"),
                    key_algorithm=scope.get("key_algorithm", "RSA-2048"),
                    cert_type=scope.get("cert_type", "server"),
                    renew_certificate_id=scope.get("certificate_id"),
                )
                job.status = "completed"
                job.total_new = 1
                job.completed_at = datetime.now(UTC)
                await db.commit()
                return outcome
            except Exception as e:
                job.status = "failed"
                job.total_errors = 1
                job.error_detail = [_friendly_error_detail(e)]
                job.completed_at = datetime.now(UTC)
                await db.commit()
                raise

    try:
        return _run_async(_run())
    except Exception as exc:
        task_logger.error(f"ACME job {job_id} failed: {exc}")
        raise self.retry(exc=exc) from exc


@shared_task(
    name="certmanager.workers.acme_worker.auto_renew_expiring_acme_certs",
    bind=True,
)
def auto_renew_expiring_acme_certs(self, window_days: int = DEFAULT_RENEWAL_WINDOW_DAYS):
    """Scheduled task: create renewal jobs for ACME certs nearing expiry.

    Runs daily. Each matching certificate gets its own acme_renew ScanJob,
    dispatched the same way a manual renewal would be.
    """
    from certmanager.core.models import Certificate, ScanJob

    async def _run():
        factory = get_session_factory()
        async with factory() as db:
            cutoff = datetime.now(UTC) + timedelta(days=window_days)
            result = await db.execute(
                select(Certificate).where(
                    Certificate.source_type == "acme",
                    Certificate.status == "active",
                    Certificate.not_after <= cutoff,
                    Certificate.source_ca_id.is_not(None),
                )
            )
            certs = result.scalars().all()

            created = 0
            for cert in certs:
                job = ScanJob(
                    job_type="acme_renew",
                    status="pending",
                    triggered_by="schedule",
                    scope_config={
                        "authority_id": cert.source_ca_id,
                        "certificate_id": cert.id,
                    },
                )
                db.add(job)
                await db.flush()
                issue_or_renew_task.delay(str(job.id))
                created += 1

            await db.commit()
            return {"renewal_jobs_created": created}

    try:
        result = _run_async(_run())
        task_logger.info(f"ACME auto-renewal: {result['renewal_jobs_created']} jobs created")
        return result
    except Exception as exc:
        task_logger.error(f"ACME auto-renewal failed: {exc}")
        raise


@shared_task(
    name="certmanager.workers.acme_worker.purge_expired_key_bundles",
    bind=True,
)
def purge_expired_key_bundles(self):
    """Scheduled task: hard-delete CertificateKeyBundle rows past expires_at,
    whether or not they were ever downloaded."""
    from certmanager.core.models import CertificateKeyBundle

    async def _run():
        factory = get_session_factory()
        async with factory() as db:
            result = await db.execute(
                delete(CertificateKeyBundle).where(
                    CertificateKeyBundle.expires_at < datetime.now(UTC)
                )
            )
            await db.commit()
            return result.rowcount or 0

    try:
        count = _run_async(_run())
        task_logger.info(f"Purged {count} expired ACME key bundles")
        return count
    except Exception as exc:
        task_logger.error(f"Key bundle purge failed: {exc}")
        raise
