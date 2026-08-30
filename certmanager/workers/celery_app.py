"""Celery application configuration for CertManager background workers.

Workers:
- ScannerWorker: Executes certificate discovery scans
- AlertWorker: Evaluates alert rules against current certificate state
- ReportWorker: Generates compliance reports (Phase 6)
- CTLogWorker: Monitors Certificate Transparency logs (Phase 5)

Usage:
    celery -A certmanager.workers.celery_app worker --loglevel=info
    celery -A certmanager.workers.celery_app beat --loglevel=info  # scheduler
"""

from __future__ import annotations

from celery import Celery
from celery.schedules import crontab

from certmanager.core.config import get_settings

settings = get_settings()


# Create Celery app
app = Celery(
    "certmanager",
    broker=settings.redis.url,
    backend=settings.redis.url,
    include=[
        "certmanager.workers.scanner_worker",
        "certmanager.workers.alert_worker",
        "certmanager.workers.report_worker",
        "certmanager.workers.ct_log_worker",
    ],
)

# Optional configuration
app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=30 * 60,  # 30 minutes max per task
    task_soft_time_limit=25 * 60,  # 25 minutes soft limit
    worker_max_tasks_per_child=200,
    worker_prefetch_multiplier=1,
)


# --- Periodic beat schedule ---
app.conf.beat_schedule = {
    # Certificate expiry check — runs daily at 07:00 UTC
    "auto-expire-certificates": {
        "task": "certmanager.workers.scanner_worker.auto_expire_certificates",
        "schedule": crontab(hour=7, minute=0),
    },
    # CA health checks — runs every 15 minutes
    "ca-health-check": {
        "task": "certmanager.workers.scanner_worker.run_health_checks",
        "schedule": crontab(minute="*/15"),
    },
    # Full discovery scan — runs daily at 03:00 UTC
    "daily-discovery-scan": {
        "task": "certmanager.workers.scanner_worker.run_full_discovery",
        "schedule": crontab(hour=3, minute=0),
    },
    # Alert evaluation — runs every 5 minutes
    "evaluate-alert-rules": {
        "task": "certmanager.workers.alert_worker.evaluate_all_rules",
        "schedule": crontab(minute="*/5"),
    },
    # CT log monitoring — runs daily at 06:00 UTC
    "ct-log-monitor": {
        "task": "certmanager.workers.ct_log_worker.check_ct_logs",
        "schedule": crontab(hour=6, minute=0),
    },
    # Weekly compliance report — runs Sunday 04:00 UTC
    "weekly-compliance-report": {
        "task": "certmanager.workers.report_worker.scheduled_weekly_report",
        "schedule": crontab(hour=4, minute=0, day_of_week=0),
    },
    # Scheduled TLS network scans — runs weekly Sunday 02:00 UTC
    "scheduled-tls-scans": {
        "task": "certmanager.workers.scanner_worker.scheduled_tls_scans",
        "schedule": crontab(hour=2, minute=0, day_of_week=0),
    },
}
