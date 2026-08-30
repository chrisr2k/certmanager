"""Agent HTTP client for communicating with the central CertManager API.

Handles:
- Registration (PSK-based handshake, idempotent re-registration)
- Heartbeat (periodic health pulse)
- Job polling (fetch pending scan jobs)
- Result submission (POST scan results)
- Air-gap export/import (HMAC-signed JSON files)

Auth model: registration returns a long-lived agent JWT (30 days). When a
request fails with 401/403 (e.g. token expired or agent revoked server-side),
the client clears its token and re-registers with the PSK once, then retries.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import structlog

logger = structlog.get_logger()


class AgentAuthError(Exception):
    """The central API rejected the agent's credentials (401/403)."""


class AgentAPIClient:
    """HTTP client for the central CertManager API from the agent's perspective."""

    def __init__(
        self,
        api_url: str,
        agent_name: str,
        psk: str,
        agent_type: str = "",
        datacenter_code: str = "",
    ):
        self.api_url = api_url.rstrip("/")
        self.agent_name = agent_name
        self.psk = psk
        self.agent_type = agent_type
        self.datacenter_code = datacenter_code
        self.agent_id: str | None = None
        self.api_token: str | None = None
        self.agent_token: str | None = None  # permanent token (connector listener)
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

    async def _request(
        self, method: str, path: str, json_data: dict = None, auth: bool = True
    ) -> dict:
        """Make an HTTP request to the central API.

        Raises:
            AgentAuthError: on 401/403 — the caller should re-register.
            aiohttp.ClientError: on transport-level failures (offline).
        """
        import aiohttp

        session = await self._get_session()
        url = f"{self.api_url}/api/v1{path}"
        headers = {}

        if auth and self.api_token:
            headers["Authorization"] = f"Bearer {self.api_token}"

        try:
            if method == "GET":
                async with session.get(url, headers=headers) as resp:
                    if resp.status in (401, 403):
                        raise AgentAuthError(f"Auth rejected ({resp.status}) on {path}")
                    resp.raise_for_status()
                    return await resp.json()
            elif method == "POST":
                async with session.post(url, headers=headers, json=json_data) as resp:
                    if resp.status in (401, 403):
                        raise AgentAuthError(f"Auth rejected ({resp.status}) on {path}")
                    resp.raise_for_status()
                    return await resp.json()
        except AgentAuthError:
            raise
        except aiohttp.ClientResponseError as e:
            logger.error("api_error", url=url, status=e.status, message=str(e))
            raise
        except aiohttp.ClientError as e:
            logger.error("api_connection_error", url=url, error=str(e))
            raise

    async def register(self, hostname: str = "") -> bool:
        """Register this agent with the central API using the PSK.

        Idempotent: re-registering an existing agent returns a fresh JWT.

        On success, stores agent_id, api_token and (first time only) the
        permanent agent_token.

        Returns:
            True if registration was successful.
        """
        try:
            response = await self._request(
                "POST",
                "/agents/register",
                json_data={
                    "name": self.agent_name,
                    "agent_type": self.agent_type,
                    "datacenter_code": self.datacenter_code,
                    "hostname": hostname or self.agent_name,
                    "psk": self.psk,
                },
                auth=False,
            )

            data = response.get("data", {})
            agent_id = data.get("agent_id")
            api_token = data.get("api_token")
            if not agent_id or not api_token:
                logger.error(
                    "agent_registration_malformed_response", response_keys=list(data.keys())
                )
                return False

            self.agent_id = agent_id
            self.api_token = api_token
            # The permanent agent token is only returned on first registration
            if data.get("agent_token"):
                self.agent_token = data["agent_token"]

            logger.info(
                "agent_registered",
                agent_id=self.agent_id,
                name=self.agent_name,
                status=data.get("status"),
                token_expires=data.get("api_token_expires_at"),
            )
            return True

        except Exception as e:
            logger.error("agent_registration_failed", error=str(e))
            return False

    async def _reauthenticate(self) -> bool:
        """Re-register after an auth failure and retry-ability signal."""
        logger.warning("agent_auth_failure_reregistering", agent_id=self.agent_id)
        self.agent_id = None
        self.api_token = None
        return await self.register()

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
        except AgentAuthError:
            if await self._reauthenticate():
                try:
                    response = await self._request("POST", f"/agents/{self.agent_id}/heartbeat")
                    return response.get("data", {})
                except Exception as e:
                    logger.warning("heartbeat_failed_after_reauth", error=str(e))
            return {"status": "offline", "pending_jobs": 0}
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
        except AgentAuthError:
            if await self._reauthenticate():
                try:
                    response = await self._request("GET", f"/agents/{self.agent_id}/jobs")
                    data = response.get("data", {})
                    return data.get("jobs", [])
                except Exception as e:
                    logger.warning("fetch_jobs_failed_after_reauth", error=str(e))
            return []
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
        except AgentAuthError:
            if await self._reauthenticate():
                try:
                    await self._request(
                        "POST",
                        f"/agents/{self.agent_id}/jobs/{job_id}/result",
                        json_data=result,
                    )
                    logger.info("result_submitted_after_reauth", job_id=job_id)
                    return True
                except Exception as e:
                    logger.error("result_submit_failed_after_reauth", job_id=job_id, error=str(e))
            return False
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
        secret: str,
    ) -> str:
        """Export buffered job results to a signed JSON file.

        Used in air-gapped environments where the agent cannot reach the
        central API. The file is signed with an HMAC for integrity; the
        secret is REQUIRED — unsigned exports would be forgeable.

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

        if not secret:
            raise ValueError("export_results requires a non-empty HMAC secret")

        payload = {
            "agent_name": agent_name,
            "exported_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "results": results,
        }

        payload_json = json.dumps(payload, indent=2, default=str)

        # Sign with HMAC-SHA256
        mac = hmac.new(secret.encode(), payload_json.encode(), hashlib.sha256).hexdigest()
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
    def verify_export(export_path: str, secret: str) -> dict | None:
        """Verify the integrity of an air-gap export file.

        Args:
            export_path: Path to the exported JSON file.
            secret: Pre-shared key for HMAC verification (REQUIRED).

        Returns:
            Parsed payload if valid, None if tampered, invalid, or unsigned.
        """
        import hashlib
        import hmac

        if not secret:
            logger.error("export_verification_refused", path=export_path, reason="no secret")
            return None

        raw = Path(export_path).read_text()
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            logger.error("export_parse_failed", path=export_path)
            return None

        if "hmac" not in data:
            logger.error("export_unsigned", path=export_path)
            return None

        expected_hmac = data.pop("hmac")
        # Recompute without the hmac field
        recomputed = json.dumps(data, indent=2, default=str)
        actual_hmac = hmac.new(secret.encode(), recomputed.encode(), hashlib.sha256).hexdigest()

        if not hmac.compare_digest(actual_hmac, expected_hmac):
            logger.error("export_hmac_mismatch", path=export_path)
            return None

        # Put hmac back
        data["hmac"] = expected_hmac

        logger.info("export_verified", path=export_path)
        return data
