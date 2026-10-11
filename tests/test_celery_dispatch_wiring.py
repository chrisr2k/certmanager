"""Regression test for a production bug: every direct Celery dispatch from
the API process (full_discovery, ca_sync, compliance reports, ACME
issue/renew) was silently failing in production.

Root cause: @shared_task's .delay()/.apply_async() resolves against
whatever Celery app is "current" at call time. Nothing in the API process
previously imported certmanager.workers.celery_app (the module that
actually configures broker=redis://...), so Celery fell back to its
library default (amqp://guest@localhost) — connection refused, silently
swallowed by each dispatch call site's try/except, job stuck in
"pending" forever. Confirmed live against the deployed container before
the fix; see certmanager/api/app.py's side-effecting import.

Must run in a subprocess: Celery's "current app" is global per-process
state, and importing certmanager.workers.celery_app anywhere else in the
test suite would mask a regression here.
"""

from __future__ import annotations

import os
import subprocess
import sys


def test_importing_api_app_configures_celery_as_current():
    script = (
        "import certmanager.api.app\n"
        "from celery import current_app\n"
        "print('BROKER:' + str(current_app.conf.broker_url))\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        env=os.environ.copy(),
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert "BROKER:redis://" in result.stdout, (
        f"Expected the redis broker to be current after importing certmanager.api.app, "
        f"got stdout={result.stdout!r} stderr={result.stderr[-500:]!r}"
    )


def test_delay_without_importing_api_app_would_use_wrong_broker():
    """Documents the bug directly: importing only a task module (the
    pattern every dispatch call site uses) does NOT configure the broker
    on its own — this is exactly what made the bug possible."""
    script = (
        "from certmanager.workers.scanner_worker import run_scan_job\n"
        "from celery import current_app\n"
        "print('BROKER:' + str(current_app.conf.broker_url))\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        env=os.environ.copy(),
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    # Celery's built-in default when no app has configured a broker yet.
    assert "BROKER:amqp://" in result.stdout or "BROKER:None" in result.stdout
