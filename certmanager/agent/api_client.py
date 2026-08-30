"""Agent HTTP client for communicating with the central CertManager API.

Handles:
- Registration (PSK-based handshake)
- Heartbeat (periodic health pulse)
- Job polling (fetch pending scan jobs)
- Result submission (POST scan results)
- Air-gap export/import (signed JSON files)
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Optional

import structlog

logger = structlog.get_logger()


class AgentAPIClient:
    """HTTP client for the central CertManager API from the agent's perspective."""

    def __init__(self, api_url: str, agent_name: str, psk: str):
        self.api_url = api_url.rstrip("/")
        self.agent_name = agent_name
        self.psk = psk
        self.agent_id: Optional[str] = None
        self.api_token: Optional[str] = None
        self._session = None

    async def _get_session(self):
        """Lazy-create aiohttp session."""
        import aiohttp

        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": f"CertManager-Agent/1.0 ({self.agent_name})",
                },
                timeout=aiohttp.ClientTimeout(total=60),
            )
        return self._session

    async def _request(self, method: str, path: str, json_data: dict = None) -> dict:
        """Make an HTTP request to the central API."""
        import aiohttp

        session = await self._get_session()
        url = f"{self.api_url}/api/v1{path}"
        headers = {}

        if self.api_token:
            headers["Authorization"] = f"Bearer {self.api_token}"

        try:
            if method == "GET":
                async with session.get(url, headers=headers) as resp:
                    resp.raise_for_status()
                    return await resp.json()
            elif method == "POST":
                async with session.post(url, headers=headers, json=json_data) as resp:
                    resp.raise_for_status()
                    return await resp.json()
        except aiohttp.ClientResponseError as e:
            logger.error("api_error", url=url, status=e.status, message=str(e))
            raise
        except aiohttp.ClientError as e:
            logger.error("api_connection_error", url=url, error=str(e))
            raise

    async def register(self, agent_type: str, datacenter_code: str, hostname: str = "") -> bool:
        """Register this agent with the central API using the PSK.

        On success, stores agent_id and api_token.

        Returns:
            True if registration was successful.
        """
        try:
            response = await self._request(
                "POST",
                "/agents/register",
                json_data={
                    "name": self.agent_name,
                    "agent_type": agent_type,
                    "datacenter_code": datacenter_code,
                    "hostname": hostname or self.agent_name,
                    "psk": self.psk,
                },
            )

            data = response.get("data", {})
            self.agent_id = data.get("agent_id")
            self.api_token = data.get("api_token")
            # Also get the permanent agent token
            agent_token = data.get("agent_token")

            logger.info(
                "agent_registered",
                agent_id=self.agent_id,
                name=self.agent_name,
                status=data.get("status"),
            )

            return True

        except Exception as e:
            logger.error("agent_registration_failed", error=str(e))
            return False

    async def send_heartbeat(self) -> dict:
        """Send a heartbeat pulse to the central API.

        Returns:
            Heartbeat response with pending job count.
        """
        if not self.agent_id:
            logger.warning("heartbeat_skipped", reason="not_registered")
            return {"status": "not_registered", "pending_jobs": 0}

        try:
            response = await self._request("POST", f"/agents/{self.agent_id}/heartbeat")
            data = response.get("data", {})
            return data
        except Exception as e:
            logger.warning("heartbeat_failed", error=str(e))
            return {"status": "offline", "pending_jobs": 0}

    async def fetch_jobs(self) -> list[dict]:
        """Poll for pending scan jobs.

        Returns:
            List of pending job dicts.
        """
        if not self.agent_id:
            return []

        try:
            response = await self._request("GET", f"/agents/{self.agent_id}/jobs")
            data = response.get("data", {})
            return data.get("jobs", [])
        except Exception as e:
            logger.warning("fetch_jobs_failed", error=str(e))
            return []

    async def submit_result(self, job_id: str, result: dict) -> bool:
        """Submit job execution results back to the central API.

        Args:
            job_id: UUID of the scan job.
            result: Result dict with certificates, stats, errors.

        Returns:
            True if submission was accepted.
        """
        if not self.agent_id:
            return False

        try:
            await self._request(
                "POST",
                f"/agents/{self.agent_id}/jobs/{job_id}/result",
                json_data=result,
            )
            logger.info("result_submitted", job_id=job_id)
            return True
        except Exception as e:
            logger.error("result_submit_failed", job_id=job_id, error=str(e))
            return False

    async def close(self):
        """Close the HTTP session."""
        if self._session and not self._session.closed:
            await self._session.close()

    # --- Air-gap methods (no network) ---

    @staticmethod
    def export_results(
        results: list[dict],
        output_path: str,
        agent_name: str,
        secret: str = "",
    ) -> str:
        """Export buffered job results to a signed JSON file.

        Used in air-gapped environments where the agent cannot reach
        the central API. The file is signed with an HMAC for integrity.

        Args:
            results: List of result dicts to export.
            output_path: Path to write the JSON file.
            agent_name: Name of this agent (for metadata).
            secret: Pre-shared key for HMAC integrity.

        Returns:
            The output file path.
        """
        import hashlib
        import hmac

        payload = {
            "agent_name": agent_name,
            "exported_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "results": results,
        }

        payload_json = json.dumps(payload, indent=2, default=str)

        # Sign with HMAC-SHA256
        if secret:
            mac = hmac.new(
                secret.encode(), payload_json.encode(), hashlib.sha256
            ).hexdigest()
            payload["hmac"] = mac
            payload_json = json.dumps(payload, indent=2, default=str)

        Path(output_path).write_text(payload_json)
        logger.info("results_exported", path=output_path, count=len(results))

        return output_path

    @staticmethod
    def import_job_file(job_file_path: str) -> dict:
        """Parse a job definition file (air-gap mode).

        The job file tells the agent what to do:
        {
            "job_type": "ca_sync",
            "scope_config": {"ca_server": "...", "templates": ["WebServer"]},
            ...
        }

        Args:
            job_file_path: Path to the job JSON file.

        Returns:
            Parsed job dict.
        """
        data = json.loads(Path(job_file_path).read_text())
        logger.info("job_file_loaded", path=job_file_path, job_type=data.get("job_type"))
        return data

    @staticmethod
    def verify_export(export_path: str, secret: str = "") -> dict | None:
        """Verify the integrity of an air-gap export file.

        Args:
            export_path: Path to the exported JSON file.
            secret: Pre-shared key for HMAC verification.

        Returns:
            Parsed payload if valid, None if tampered or invalid.
        """
        import hashlib
        import hmac

        raw = Path(export_path).read_text()
        data = json.loads(raw)

        if secret and "hmac" in data:
            expected_hmac = data.pop("hmac")
            # Recompute without the hmac field
            recomputed = json.dumps(data, indent=2, default=str)
            actual_hmac = hmac.new(
                secret.encode(), recomputed.encode(), hashlib.sha256
            ).hexdigest()

            if not hmac.compare_digest(actual_hmac, expected_hmac):
                logger.error("export_hmac_mismatch", path=export_path)
                return None

            # Put hmac back
            data["hmac"] = expected_hmac

        logger.info("export_verified", path=export_path)
        return data
