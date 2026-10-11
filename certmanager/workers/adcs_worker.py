"""AD CS scheduling — creates renewal jobs for certs nearing expiry.

Unlike acme_worker, there is no Celery execution task here: AD CS
lifecycle ops are executed entirely by the datacenter agent's existing
poll loop (certmanager/agent/agent.py), never by a central worker process
reaching out to anything. This task's only job is to create a pending
`adcs_renew` ScanJob — the agent picks it up on its next poll cycle.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import structlog
from celery import shared_task
from celery.utils.log import get_task_logger
from sqlalchemy import select

from certmanager.core.database import get_session_factory

logger = structlog.get_logger()
task_logger = get_task_logger(__name__)

DEFAULT_RENEWAL_WINDOW_DAYS = 30


def _run_async(coro):
    import asyncio

    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


@shared_task(
    name="certmanager.workers.adcs_worker.auto_renew_expiring_adcs_certs",
    bind=True,
)
def auto_renew_expiring_adcs_certs(self, window_days: int = DEFAULT_RENEWAL_WINDOW_DAYS):
    """Scheduled task: create renewal jobs for AD CS certs nearing expiry.

    Runs daily. Each matching certificate gets its own adcs_renew ScanJob,
    carrying the certificate's own template/common_name/SANs (not a
    CA-level default — a single CA/agent can issue under more than one
    template). Status "superseded" (set by agents.py's submit_job_result
    once a renewal completes) is excluded by the active-status filter
    below, so a completed renewal is never re-selected on the next run.
    """
    from certmanager.core.models import Certificate, CertificateAuthority, ScanJob

    async def _run():
        factory = get_session_factory()
        async with factory() as db:
            cutoff = datetime.now(UTC) + timedelta(days=window_days)
            result = await db.execute(
                select(Certificate).where(
                    Certificate.source_type == "adcs",
                    Certificate.status == "active",
                    Certificate.not_after <= cutoff,
                    Certificate.source_ca_id.is_not(None),
                )
            )
            certs = result.scalars().all()

            created = 0
            skipped = 0
            for cert in certs:
                authority_result = await db.execute(
                    select(CertificateAuthority).where(
                        CertificateAuthority.id == cert.source_ca_id
                    )
                )
                authority = authority_result.scalar_one_or_none()
                if authority is None or authority.ca_type != "adcs":
                    skipped += 1
                    continue

                config = authority.config or {}
                agent_id = config.get("agent_id")
                if not agent_id:
                    skipped += 1
                    continue

                cert_detail = cert.source_detail or {}
                job = ScanJob(
                    job_type="adcs_renew",
                    status="pending",
                    triggered_by="schedule",
                    scope_config={
                        "agent_id": agent_id,
                        "authority_id": authority.id,
                        "certificate_id": cert.id,
                        "common_name": cert.common_name,
                        "sans": cert.sans or [],
                        "template": cert_detail.get("template") or config.get("template", ""),
                        "deployment_target": config.get("deployment_target", "store"),
                        "deployment_path": config.get("deployment_path", ""),
                        "post_install_hook": config.get("post_install_hook", ""),
                        "deliver_key_to_central": bool(
                            config.get("deliver_key_to_central", False)
                        ),
                    },
                )
                db.add(job)
                created += 1

            await db.commit()
            return {"renewal_jobs_created": created, "skipped": skipped}

    try:
        result = _run_async(_run())
        task_logger.info(
            f"AD CS auto-renewal: {result['renewal_jobs_created']} jobs created, "
            f"{result['skipped']} skipped (no agent_id configured)"
        )
        return result
    except Exception as exc:
        task_logger.error(f"AD CS auto-renewal failed: {exc}")
        raise
