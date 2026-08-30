"""Active Directory Certificate Services (AD CS) connector.

Delegates to a datacenter agent's REST API for all operations.
The agent runs PowerShell/CertUtil commands against the local AD CS server.

This connector is a thin client — it sends requests to the agent API
and normalizes the responses into CertificateRecord objects.
"""

from __future__ import annotations

import hashlib
import time
from datetime import UTC, datetime

import structlog

from certmanager.connectors.base import (
    CAConnector,
    CAHealthResult,
    CAHealthStatus,
    CertificateRecord,
    ConnectorError,
    ConnectorTimeoutError,
    IssueRequest,
    IssueResult,
)

logger = structlog.get_logger()


class ADCSConnector(CAConnector):
    """Connector for Active Directory Certificate Services.

    All AD CS operations are delegated to a datacenter agent running
    on a Windows server with access to the CA. This connector is
    an HTTP client that communicates with the agent via its REST API.

    Configuration (from CertificateAuthority.config JSONB):
        {
            "agent_id": "uuid-of-agent",
            "ca_server": "ca-server.internal.example.com",
            "ca_name": "Enterprise CA",
            "agent_base_url": "https://dc1-agent.internal:8443"
        }
    """

    connector_type = "adcs"

    def __init__(
        self,
        agent_id: str,
        ca_server: str,
        ca_name: str,
        base_url: str,
        api_token: str,
    ):
        """Initialize the AD CS connector.

        Args:
            agent_id: UUID of the registered agent in CertManager.
            ca_server: Hostname of the AD CS server.
            ca_name: Name of the Certificate Authority.
            base_url: Base URL of the agent REST API.
            api_token: Agent authentication token (the permanent agent_token).
        """
        self.agent_id = agent_id
        self.ca_server = ca_server
        self.ca_name = ca_name
        self.base_url = base_url.rstrip("/")
        self.api_token = api_token
        self._session = None

    async def _get_session(self):
        """Lazy-create a shared aiohttp session for this connector."""
        import aiohttp

        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(
                headers={
                    "Authorization": f"Bearer {self.api_token}",
                    "Content-Type": "application/json",
                }
            )
        return self._session

    async def close(self) -> None:
        """Close the underlying HTTP session (callers manage connector lifecycle)."""
        if self._session is not None and not self._session.closed:
            await self._session.close()

    async def _agent_request(self, method: str, path: str, json_data: dict = None) -> dict:
        """Make an HTTP request to the datacenter agent API.

        Args:
            method: HTTP method (GET, POST).
            path: API path relative to base_url.
            json_data: Optional JSON body for POST requests.

        Returns:
            Response JSON as dict.

        Raises:
            ConnectorTimeoutError: If the agent doesn't respond.
            ConnectorError: For other agent communication errors (including
                401 auth failures and 501 not-supported responses).
        """
        import aiohttp

        url = f"{self.base_url}{path}"
        session = await self._get_session()

        try:
            if method == "GET":
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                    return await self._handle_response(resp)
            elif method == "POST":
                async with session.post(
                    url, json=json_data, timeout=aiohttp.ClientTimeout(total=60)
                ) as resp:
                    return await self._handle_response(resp)
            raise ConnectorError(f"Unsupported HTTP method: {method}")
        except ConnectorError:
            raise
        except aiohttp.ClientError as e:
            if "timeout" in str(e).lower():
                raise ConnectorTimeoutError(f"Agent {self.agent_id} timed out: {e}") from e
            raise ConnectorError(f"Agent {self.agent_id} request failed: {e}") from e

    @staticmethod
    async def _handle_response(resp) -> dict:
        """Decode an agent response, mapping error statuses to ConnectorError."""

        try:
            body = await resp.json()
        except Exception:
            body = None

        if resp.status == 401:
            raise ConnectorError(
                "Agent rejected the connector token — check the agent_token in the CA config"
            )
        if resp.status == 501:
            message = (
                (body or {}).get("message", "not supported")
                if isinstance(body, dict)
                else "not supported"
            )
            raise ConnectorError(f"Operation not supported by this agent: {message}")
        if resp.status >= 400:
            message = (
                (body or {}).get("message", resp.reason) if isinstance(body, dict) else resp.reason
            )
            raise ConnectorError(f"Agent returned HTTP {resp.status}: {message}")
        if not isinstance(body, dict):
            raise ConnectorError("Agent returned a non-JSON response")
        return body

    async def health_check(self) -> CAHealthResult:
        """Check agent health and AD CS connectivity."""
        start = time.monotonic()

        try:
            # The agent listener accepts both GET and POST on /health
            result = await self._agent_request("GET", "/health")
            latency_ms = (time.monotonic() - start) * 1000

            if result.get("adcs_status") == "ok":
                return CAHealthResult(
                    status=CAHealthStatus.HEALTHY,
                    message=f"AD CS healthy via agent {self.agent_id}",
                    latency_ms=round(latency_ms, 2),
                    detail=result,
                )
            else:
                return CAHealthResult(
                    status=CAHealthStatus.DEGRADED,
                    message=f"AD CS degraded: {result.get('message', 'unknown')}",
                    latency_ms=round(latency_ms, 2),
                    detail=result,
                )
        except ConnectorError as e:
            latency_ms = (time.monotonic() - start) * 1000
            return CAHealthResult(
                status=CAHealthStatus.UNHEALTHY,
                message=str(e),
                latency_ms=round(latency_ms, 2),
            )

    async def discover_certificates(self, scope: dict | None = None) -> list[CertificateRecord]:
        """Discover certificates from AD CS via the agent.

        The agent runs certutil -view or the PKI PowerShell module
        to enumerate issued certificates and returns them as JSON.

        Args:
            scope: Optional filter dict:
                {"templates": ["WebServer", "User"], "since": "2026-01-01"}

        Returns:
            List of normalized CertificateRecord objects.
        """
        try:
            result = await self._agent_request(
                "POST",
                "/scanners/adcs/discover",
                json_data={
                    "ca_server": self.ca_server,
                    "ca_name": self.ca_name,
                    "scope": scope or {},
                },
            )

            records = []
            for cert_data in result.get("certificates", []):
                records.append(self._parse_agent_cert(cert_data))

            logger.info(
                "adcs_discovery_complete",
                agent_id=self.agent_id,
                ca_server=self.ca_server,
                cert_count=len(records),
            )
            return records

        except ConnectorError:
            raise
        except Exception as e:
            raise ConnectorError(f"AD CS discovery failed: {e}") from e

    def _parse_agent_cert(self, data: dict) -> CertificateRecord:
        """Parse agent-returned certificate data into a CertificateRecord."""
        not_before = (
            datetime.fromisoformat(data["not_before"])
            if data.get("not_before")
            else datetime.min.replace(tzinfo=UTC)
        )
        not_after = (
            datetime.fromisoformat(data["not_after"])
            if data.get("not_after")
            else datetime.max.replace(tzinfo=UTC)
        )
        source_id = data.get("request_id", data.get("serial_number", ""))

        return CertificateRecord(
            common_name=data.get("common_name", "Unknown"),
            subject=data.get("subject", ""),
            issuer=data.get("issuer", ""),
            serial_number=data.get("serial_number", ""),
            thumbprint_sha256=data.get(
                "thumbprint", hashlib.sha256(source_id.encode()).hexdigest()
            ),
            not_before=not_before,
            not_after=not_after,
            validity_days=(
                int((not_after - not_before).total_seconds() / 86400)
                if not_after != datetime.max.replace(tzinfo=UTC)
                and not_before != datetime.min.replace(tzinfo=UTC)
                else None
            ),
            key_algorithm=data.get("key_algorithm", "unknown"),
            signature_algorithm=data.get("signature_algorithm", "unknown"),
            sans=data.get("sans", []),
            cert_type=data.get("cert_type", "server"),
            is_wildcard=data.get("is_wildcard", False),
            is_ca=False,
            source_detail={
                "request_id": data.get("request_id"),
                "template": data.get("template"),
                "ca_server": self.ca_server,
                "ca_name": self.ca_name,
            },
            source_id=source_id,
            status=data.get("status", "active"),
        )

    async def get_certificate(self, source_id: str) -> CertificateRecord | None:
        """Get a single AD CS certificate by request ID or serial number."""
        try:
            result = await self._agent_request("GET", f"/scanners/adcs/certificates/{source_id}")
            return self._parse_agent_cert(result)
        except ConnectorError:
            return None

    async def issue_certificate(self, request: IssueRequest) -> IssueResult:
        """Issue a new certificate via AD CS through the agent.

        The agent submits the CSR to the CA and returns the issued
        certificate with the private key.
        """
        result = await self._agent_request(
            "POST",
            "/scanners/adcs/issue",
            json_data={
                "common_name": request.common_name,
                "sans": request.sans,
                "key_algorithm": request.key_algorithm,
                "validity_days": request.validity_days,
                "cert_type": request.cert_type,
                "ca_server": self.ca_server,
                "ca_name": self.ca_name,
            },
        )

        record = self._parse_agent_cert(result["certificate"])
        return IssueResult(
            certificate=record,
            private_key_pem=result.get("private_key_pem"),
            password=result.get("password"),
        )

    async def renew_certificate(self, source_id: str) -> IssueResult:
        """Renew an AD CS certificate via the agent."""
        result = await self._agent_request(
            "POST",
            f"/scanners/adcs/certificates/{source_id}/renew",
        )

        record = self._parse_agent_cert(result["certificate"])
        return IssueResult(
            certificate=record,
            private_key_pem=result.get("private_key_pem"),
            password=result.get("password"),
        )

    async def revoke_certificate(self, source_id: str, reason: str = "unspecified") -> bool:
        """Revoke an AD CS certificate via the agent.

        The agent runs certutil -revoke against the CA.
        """
        result = await self._agent_request(
            "POST",
            f"/scanners/adcs/certificates/{source_id}/revoke",
            json_data={"reason": reason},
        )
        return result.get("revoked", False)

    async def get_certificate_chain(self, source_id: str) -> list[CertificateRecord]:
        """Get the certificate chain from AD CS."""
        try:
            result = await self._agent_request(
                "GET", f"/scanners/adcs/certificates/{source_id}/chain"
            )
            return [self._parse_agent_cert(cert_data) for cert_data in result.get("chain", [])]
        except ConnectorError:
            return []
