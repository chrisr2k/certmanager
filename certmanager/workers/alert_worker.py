"""Alert worker — evaluates alert rules against the certificate inventory.

Tasks:
- evaluate_all_rules: Runs on a schedule (every 5 min), evaluates all enabled rules
- evaluate_single_rule: Evaluate a specific rule (on-demand)
- check_ct_logs: Monitor Certificate Transparency logs for shadow certs (daily)
"""

from __future__ import annotations

import asyncio

import structlog
from celery import shared_task
from celery.utils.log import get_task_logger

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
    name="certmanager.workers.alert_worker.evaluate_all_rules",
    bind=True,
)
def evaluate_all_rules(self):
    """Scheduled task: evaluate all enabled alert rules.

    Runs every 5 minutes via Celery beat. Queries the certificate
    inventory for matches, creates alert events, and dispatches
    notifications through configured channels.
    """
    from certmanager.core.database import get_session_factory
    from certmanager.services.alerting_service import AlertingService

    async def _run():
        factory = get_session_factory()
        async with factory() as db:
            service = AlertingService(db)
            result = await service.evaluate_all_rules()
            await db.commit()
            return result

    try:
        result = _run_async(_run())
        task_logger.info(
            f"Alert evaluation complete: {result['evaluated']} evaluated, "
            f"{result['triggered']} triggered, {result['errors']} errors"
        )
        return result
    except Exception as exc:
        task_logger.error(f"Alert evaluation failed: {exc}")
        raise


@shared_task(
    name="certmanager.workers.alert_worker.evaluate_single_rule",
    bind=True,
)
def evaluate_single_rule(self, rule_id: str):
    """Evaluate a single alert rule on demand.

    Args:
        rule_id: UUID of the alert rule to evaluate.
    """
    from sqlalchemy import select

    from certmanager.core.database import get_session_factory
    from certmanager.core.models import AlertRule
    from certmanager.services.alerting_service import AlertingService

    async def _run():
        factory = get_session_factory()
        async with factory() as db:
            result = await db.execute(select(AlertRule).where(AlertRule.id == rule_id))
            rule = result.scalar_one_or_none()

            if not rule:
                task_logger.warning(f"Alert rule {rule_id} not found")
                return {"rule_id": rule_id, "triggered": False, "error": "not_found"}

            if not rule.is_enabled:
                return {"rule_id": rule_id, "triggered": False, "error": "disabled"}

            service = AlertingService(db)
            triggered = await service.evaluate_rule(rule)
            await db.commit()
            return {"rule_id": rule_id, "triggered": triggered}

    try:
        result = _run_async(_run())
        task_logger.info(f"Rule {rule_id} evaluated: triggered={result.get('triggered')}")
        return result
    except Exception as exc:
        task_logger.error(f"Rule evaluation failed for {rule_id}: {exc}")
        raise


@shared_task(
    name="certmanager.workers.alert_worker.check_ct_logs",
    bind=True,
)
def check_ct_logs(self):
    """Check Certificate Transparency logs for unknown certificates."""
    from certmanager.workers.ct_log_worker import check_ct_logs as ct_check

    return ct_check()
