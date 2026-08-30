"""Connector listener — serves the central platform's CA connectors.

The central AD CS connector (certmanager/connectors/adcs.py) calls this
listener over HTTP(S) instead of talking to the datacenter directly. The
listener:

- Authenticates callers with the agent's permanent token (Bearer) —
  the token a connector admin pastes into the CA config. Compared with
  hmac.compare_digest against the token this agent received at first
  registration.
- Optionally terminates TLS with REQUIRED client certificates when
  listener_ssl_ca is configured (mutual TLS mode).
- Executes scanner plugins locally and returns normalized JSON.

Supported endpoints (match connector expectations):
    POST /health
    POST /scanners/adcs/discover
Everything else (issue/renew/revoke) returns 501 — local issuance is not
implemented yet; connectors surface that as a clear ConnectorError.
"""

from __future__ import annotations

import asyncio
import hmac
import ssl
from typing import Optional

import structlog

logger = structlog.get_logger()


class AgentListener:
    """HTTP listener exposing scanner plugins to the central connectors."""

    def __init__(self, settings, scanners: list, agent_token: str):
        self.settings = settings
        self.scanners = scanners
        self.agent_token = agent_token
        self._runner = None
        self._site = None

    # --- Auth ---

    def _authorize(self, request) -> bool:
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer ") or not self.agent_token:
            return False
        supplied = header[7:]
        return hmac.compare_digest(supplied, self.agent_token)

    def _get_scanner(self, name: str):
        return next((s for s in self.scanners if s.name == name), None)

    # --- Handlers ---

    async def _handle_health(self, request):
        """POST /health — used by connector health_check."""
        if not self._authorize(request):
            return self._json_response({"status": "unauthorized"}, status=401)

        adcs = self._get_scanner("adcs")
        result = {"status": "ok", "adcs_status": "ok", "scanners": [s.name for s in self.scanners]}

        if adcs is None:
            result["adcs_status"] = "not_configured"
            return self._json_response(result, status=200)

        try:
            health = await adcs.health_check()
            result["adcs_status"] = health.status
            result["message"] = health.message
            if health.status != "ok":
                result["status"] = "degraded"
        except Exception as e:
            logger.error("listener_health_check_failed", error=str(e))
            result["status"] = "degraded"
            result["adcs_status"] = "error"
            result["message"] = str(e)

        return self._json_response(result, status=200)

    async def _handle_discover(self, request):
        """POST /scanners/adcs/discover — run AD CS discovery."""
        if not self._authorize(request):
            return self._json_response({"status": "unauthorized"}, status=401)

        scanner = self._get_scanner("adcs")
        if scanner is None:
            return self._json_response(
                {"status": "error", "message": "AD CS scanner not configured on this agent"},
                status=400,
            )

        scope = {}
        try:
            body = await request.json()
            if isinstance(body, dict):
                scope = body.get("scope") or body.get("scope_config") or {}
        except Exception:
            pass  # Empty body is fine

        try:
            result = await scanner.scan(scope)
        except Exception as e:
            logger.error("listener_discover_failed", error=str(e))
            return self._json_response({"status": "error", "message": str(e)}, status=500)

        payload = result.to_api_result()
        payload["status"] = "ok"
        return self._json_response(payload, status=200)

    async def _handle_not_supported(self, request):
        """Issue/renew/revoke and other lifecycle ops are not yet local."""
        if not self._authorize(request):
            return self._json_response({"status": "unauthorized"}, status=401)
        return self._json_response(
            {
                "status": "not_supported",
                "message": "Lifecycle operations (issue/renew/revoke) are not implemented on this agent",
            },
            status=501,
        )

    # --- Server plumbing ---

    @staticmethod
    def _json_response(data: dict, status: int = 200):
        from aiohttp import web

        return web.json_response(data, status=status)

    def _build_app(self):
        from aiohttp import web

        app = web.Application()
        app.router.add_get("/health", self._handle_health)
        app.router.add_post("/health", self._handle_health)
        app.router.add_post("/scanners/adcs/discover", self._handle_discover)
        # Everything else the connector may call → explicit 501
        for route in (
            "/scanners/adcs/issue",
            "/scanners/adcs/renew",
            "/scanners/adcs/revoke",
            "/scanners/adcs/cert/{source_id}",
            "/scanners/adcs/cert/{source_id}/chain",
            "/scanners/adcs/certificates/{source_id}",
            "/scanners/adcs/certificates/{source_id}/renew",
            "/scanners/adcs/certificates/{source_id}/revoke",
            "/scanners/adcs/certificates/{source_id}/chain",
        ):
            app.router.add_post(route, self._handle_not_supported)
            app.router.add_get(route, self._handle_not_supported)
        return app

    def _ssl_context(self) -> Optional[ssl.SSLContext]:
        """Build the server TLS context; require client certs when a CA is set."""
        if not self.settings.listener_ssl_cert or not self.settings.listener_ssl_key:
            return None

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(self.settings.listener_ssl_cert, self.settings.listener_ssl_key)
        if self.settings.listener_ssl_ca:
            # Mutual TLS: only accept client certificates signed by this CA
            ctx.verify_mode = ssl.CERT_REQUIRED
            ctx.load_verify_locations(self.settings.listener_ssl_ca)
        return ctx

    async def start(self) -> None:
        """Start the listener as a background task."""
        from aiohttp import web

        if not self.agent_token:
            logger.warning(
                "listener_starting_without_token",
                message=(
                    "No agent_token available (re-registration of an existing agent) — "
                    "listener will reject all connector requests. Re-provision the CA "
                    "config with the original agent_token from first registration."
                ),
            )

        runner = web.AppRunner(self._build_app())
        await runner.setup()

        scheme = "https" if self.settings.listener_ssl_cert else "http"
        try:
            site = web.TCPSite(
                runner,
                host=self.settings.listener_host,
                port=self.settings.listener_port,
                ssl_context=self._ssl_context(),
            )
            await site.start()
        except OSError as e:
            # Port in use is fatal for the listener only — the poll loop continues
            logger.error(
                "listener_start_failed",
                error=str(e),
                host=self.settings.listener_host,
                port=self.settings.listener_port,
            )
            await runner.cleanup()
            return

        self._runner = runner
        self._site = site
        logger.info(
            "listener_started",
            url=f"{scheme}://{self.settings.listener_host}:{self.settings.listener_port}",
            mtls=bool(self.settings.listener_ssl_ca),
        )

    async def stop(self) -> None:
        """Stop the listener."""
        if self._runner is not None:
            await self._runner.cleanup()
            self._runner = None
            self._site = None
            logger.info("listener_stopped")
