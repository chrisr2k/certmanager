"""Datacenter Agent — main event loop.

The agent runs in each datacenter and:
1. Registers with the central API (PSK-based handshake)
2. Polls for pending scan jobs
3. Executes jobs using scanner plugins
4. Submits results back to the central API
5. Buffers results locally if the central API is unreachable
6. Supports air-gapped operation (export/import)

Three communication modes:
- Mode A (polling): Agent polls central API. Outbound HTTPS only. Default.
- Mode B (push): Unused currently — central pushes to agent API.
- Mode C (air-gap): Export signed JSON files. No network needed.
"""

from __future__ import annotations

import asyncio
import signal
import sys
import time
from pathlib import Path
from typing import Optional

import structlog

logger = structlog.get_logger()

# Load scanners based on agent type
from certmanager.agent.scanners.adcs_scanner import ADCSLocalScanner
from certmanager.agent.scanners.base import ScannerPlugin
from certmanager.agent.scanners.tls_scanner import TLSScanner


class CertManagerAgent:
    """Main agent process for datacenter certificate discovery.

    Usage:
        agent = CertManagerAgent(settings)
        await agent.run()
    """

    def __init__(self, settings):
        """Initialize the agent.

        Args:
            settings: AgentSettings from config module.
        """
        self.settings = settings
        self._running = False
        self._scanners: list[ScannerPlugin] = []
        self._api_client = None
        self._local_db = None

    async def initialize(self) -> bool:
        """Set up the agent: load scanners, register with central API.

        Returns:
            True if initialization was successful.
        """
        from certmanager.agent.api_client import AgentAPIClient
        from certmanager.agent.local_db import LocalDB

        # Local database for offline buffering
        self._local_db = LocalDB(self.settings.local_db_path)

        # API client
        self._api_client = AgentAPIClient(
            api_url=self.settings.api_url,
            agent_name=self.settings.agent_name,
            psk=self.settings.psk,
        )

        # Restore persistent state
        saved_id = self._local_db.get_state("agent_id")
        saved_token = self._local_db.get_state("api_token")
        if saved_id:
            self._api_client.agent_id = saved_id
        if saved_token:
            self._api_client.api_token = saved_token

        # Register if not already registered
        if not self._api_client.agent_id or not self._api_client.api_token:
            logger.info("agent_not_registered", name=self.settings.agent_name)
            success = await self._api_client.register(
                agent_type=self.settings.agent_type,
                datacenter_code=self.settings.datacenter_code,
                hostname=self.settings.agent_name,
            )

            if not success:
                logger.error("registration_failed")
                return False

            # Persist tokens
            self._local_db.set_state("agent_id", self._api_client.agent_id)
            self._local_db.set_state("api_token", self._api_client.api_token)

            # Save to config file for CLI usage
            from certmanager.agent.config import save_agent_config

            self.settings.agent_id = self._api_client.agent_id
            self.settings.api_token = self._api_client.api_token
            save_agent_config(self.settings)

            logger.info(
                "agent_registered_and_persisted",
                agent_id=self._api_client.agent_id,
                name=self.settings.agent_name,
            )

        # Load scanner plugins
        self._load_scanners()

        logger.info(
            "agent_initialized",
            name=self.settings.agent_name,
            agent_id=self._api_client.agent_id,
            agent_type=self.settings.agent_type,
            scanners=[s.name for s in self._scanners],
        )

        return True

    def _load_scanners(self) -> None:
        """Load scanner plugins based on agent_type configuration."""
        agent_type = self.settings.agent_type

        if agent_type == "adcs":
            self._scanners.append(
                ADCSLocalScanner(
                    ca_server=self.settings.adcs_ca_server,
                    ca_name=self.settings.adcs_ca_name,
                    use_winrm=self.settings.adcs_use_winrm,
                )
            )

        if agent_type in ("tls_scanner", "generic"):
            self._scanners.append(
                TLSScanner(
                    cidr_ranges=self.settings.tls_cidr_ranges,
                    ports=self.settings.tls_ports,
                    timeout=self.settings.tls_timeout,
                )
            )

        if agent_type == "generic":
            # Generic agent loads all available scanners
            self._scanners.append(
                ADCSLocalScanner(
                    ca_server=self.settings.adcs_ca_server,
                    ca_name=self.settings.adcs_ca_name,
                )
            )

    async def run(self) -> None:
        """Main agent event loop.

        Runs until SIGTERM/SIGINT is received. Each cycle:
        1. Send heartbeat
        2. Flush any buffered results
        3. Poll for pending jobs
        4. Execute each job
        5. Submit results
        6. Sleep for poll_interval
        """
        self._running = True

        # Setup signal handlers
        loop = asyncio.get_event_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, self.shutdown)
            except NotImplementedError:
                # Windows doesn't support add_signal_handler for SIGTERM
                pass

        logger.info("agent_loop_starting", poll_interval=self.settings.poll_interval)

        while self._running:
            try:
                # 1. Heartbeat
                await self._heartbeat()

                # 2. Flush buffered results
                await self._flush_buffer()

                # 3. Poll for jobs
                jobs = await self._api_client.fetch_jobs()

                # 4. Execute jobs
                for job in jobs:
                    if not self._running:
                        break
                    await self._execute_job(job)

                # 5. Run local health checks
                await self._run_health_checks()

            except Exception as e:
                logger.error("agent_loop_error", error=str(e))
                # Buffer a heartbeat locally
                self._local_db.buffer_heartbeat("degraded")

            # 6. Sleep
            await asyncio.sleep(self.settings.poll_interval)

        await self._cleanup()

    async def _heartbeat(self) -> None:
        """Send heartbeat to central API."""
        result = await self._api_client.send_heartbeat()
        pending = result.get("pending_jobs", 0)

        if result.get("status") == "not_registered":
            logger.warning("heartbeat_not_registered")
        elif pending > 0:
            logger.info("heartbeat", pending_jobs=pending)
        else:
            logger.debug("heartbeat", status=result.get("status"))

    async def _flush_buffer(self) -> None:
        """Flush buffered results that were stored during offline periods."""
        pending = self._local_db.get_pending_results(limit=50)
        if not pending:
            return

        logger.info("flushing_buffer", count=len(pending))

        for entry in pending:
            success = await self._api_client.submit_result(
                job_id=entry["job_id"],
                result=entry["result"],
            )
            if success:
                self._local_db.mark_result_submitted(entry["row_id"])
            else:
                self._local_db.mark_result_failed(
                    entry["row_id"], "Submission failed during flush"
                )

        # Purge hopeless entries
        purged = self._local_db.purge_failed(max_retries=10)
        if purged:
            logger.info("purged_failed_results", count=purged)

    async def _execute_job(self, job: dict) -> None:
        """Execute a scan job using the appropriate scanner.

        Args:
            job: Job dict from central API with job_type, scope_config, etc.
        """
        job_id = job.get("id", "unknown")
        job_type = job.get("job_type", "ca_sync")
        scope = job.get("scope_config", {})

        logger.info("job_starting", job_id=job_id, job_type=job_type)

        # Find the right scanner for this job type
        scanner: Optional[ScannerPlugin] = None
        if job_type in ("ca_sync", "adcs_scan", "full_discovery"):
            scanner = next(
                (s for s in self._scanners if s.name == "adcs"),
                None,
            )
        elif job_type in ("tls_scan",):
            scanner = next(
                (s for s in self._scanners if s.name == "tls_scanner"),
                None,
            )
        else:
            # Use the first available scanner for unknown job types
            scanner = self._scanners[0] if self._scanners else None

        if not scanner:
            logger.error(
                "no_scanner_for_job",
                job_id=job_id,
                job_type=job_type,
                available=[s.name for s in self._scanners],
            )
            await self._api_client.submit_result(
                job_id,
                {
                    "total_checked": 0,
                    "total_new": 0,
                    "total_updated": 0,
                    "total_errors": 1,
                    "certificates": [],
                    "errors": [f"No scanner available for job type: {job_type}"],
                },
            )
            return

        # Execute scan
        try:
            result = await scanner.scan(scope)
            api_result = result.to_api_result()
        except Exception as e:
            logger.error("scan_failed", job_id=job_id, error=str(e))
            api_result = {
                "total_checked": 0,
                "total_new": 0,
                "total_updated": 0,
                "total_errors": 1,
                "certificates": [],
                "errors": [str(e)],
            }

        # Submit result
        success = await self._api_client.submit_result(job_id, api_result)

        if not success:
            # Buffer locally for later submission
            self._local_db.buffer_result(job_id, api_result)
            logger.info("result_buffered_locally", job_id=job_id)

    async def _run_health_checks(self) -> None:
        """Run local scanner health checks silently."""
        for scanner in self._scanners:
            try:
                health = await scanner.health_check()
                if health.status != "ok":
                    logger.warning(
                        "scanner_health_issue",
                        scanner=scanner.name,
                        status=health.status,
                        message=health.message,
                    )
            except Exception as e:
                logger.error(
                    "health_check_error",
                    scanner=scanner.name,
                    error=str(e),
                )

    def shutdown(self) -> None:
        """Graceful shutdown."""
        logger.info("shutdown_signalled")
        self._running = False

    async def _cleanup(self) -> None:
        """Cleanup resources on shutdown."""
        logger.info("agent_stopping")

        if self._api_client:
            try:
                # Send final heartbeat
                await self._api_client.send_heartbeat()
            except Exception:
                pass
            await self._api_client.close()

        logger.info("agent_stopped")


async def run_agent(settings=None) -> int:
    """Entry point: create and run the agent.

    Args:
        settings: AgentSettings instance. If None, loaded from config.

    Returns:
        Exit code (0 = success, 1 = error).
    """
    if settings is None:
        from certmanager.agent.config import load_agent_config

        settings = load_agent_config()

    # Configure logging
    from certmanager.core.logging import configure_logging

    configure_logging()

    agent = CertManagerAgent(settings)

    try:
        ok = await agent.initialize()
        if not ok:
            logger.error("agent_initialization_failed")
            return 1

        await agent.run()
        return 0
    except Exception as e:
        logger.exception("agent_fatal_error", error=str(e))
        return 1


def main() -> int:
    """Synchronous entry point for setuptools console_scripts."""
    return asyncio.run(run_agent())


if __name__ == "__main__":
    sys.exit(main())
