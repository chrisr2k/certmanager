"""Audit logging middleware.

Logs every API call to the audit_log table. Runs after RBAC so we know
who the authenticated actor is. Skips health check and OPTIONS requests.

Uses a fire-and-forget pattern: the request is not blocked on audit log
write latency. If the audit write fails, it logs a warning but does not
fail the request.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

import structlog
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

logger = structlog.get_logger()

# Paths to skip auditing
AUDIT_SKIP_PATHS = {"/api/health", "/api/docs", "/api/redoc", "/api/openapi.json"}

# Query parameter names whose values must never be written to the audit log
SENSITIVE_QUERY_PARAMS = {
    "password",
    "psk",
    "token",
    "api_key",
    "secret",
    "mfa_code",
    "code",
    "recovery_code",
    "refresh_token",
}


def _redacted_query_string(request: Request) -> str:
    """Serialize query params with sensitive values replaced."""
    parts = []
    for key, value in request.query_params.multi_items():
        if key.lower() in SENSITIVE_QUERY_PARAMS:
            parts.append(f"{key}=[REDACTED]")
        else:
            parts.append(f"{key}={value}")
    return "&".join(parts)


class AuditLogMiddleware(BaseHTTPMiddleware):
    """Logs API requests to the audit trail.

    Attaches actor information from request.state (set by RBACMiddleware)
    and request/response metadata. Request bodies are deliberately NOT
    captured — credentials travel in bodies and must never hit the audit
    trail; sensitive query params are redacted.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        # Skip non-API paths and health checks
        path = request.url.path
        if path in AUDIT_SKIP_PATHS or request.method == "OPTIONS":
            return await call_next(request)

        start_time = datetime.now(UTC)

        # Process the request
        response = await call_next(request)

        # Build audit entry
        actor_type = getattr(request.state, "actor_type", "anonymous")
        actor_id = getattr(request.state, "actor_id", None)
        actor_email = getattr(request.state, "actor_email", None)
        correlation_id = getattr(request.state, "correlation_id", None)

        audit_entry = {
            "event_type": f"api.{request.method.lower()}",
            "actor_type": actor_type,
            "actor_id": actor_id,
            "actor_email": actor_email,
            "resource_type": _guess_resource_type(path),
            "action": request.method.lower(),
            "details": {
                "method": request.method,
                "path": path,
                "query_string": _redacted_query_string(request),
                "status_code": response.status_code,
                "latency_ms": int((datetime.now(UTC) - start_time).total_seconds() * 1000),
            },
            "ip_address": request.client.host if request.client else None,
            "user_agent": request.headers.get("User-Agent"),
            "correlation_id": correlation_id,
        }

        # Fire-and-forget: write audit entry without blocking the response
        asyncio.create_task(self._write_audit(audit_entry))

        return response

    async def _write_audit(self, entry: dict) -> None:
        """Write audit entry to database. Swallows errors to avoid breaking requests."""
        try:
            from certmanager.core.database import get_session_factory

            factory = get_session_factory()
            async with factory() as session:
                from certmanager.core.models import AuditLog

                log_entry = AuditLog(
                    event_type=entry["event_type"],
                    actor_type=entry["actor_type"],
                    actor_id=entry.get("actor_id"),
                    actor_email=entry.get("actor_email"),
                    resource_type=entry.get("resource_type"),
                    action=entry["action"],
                    details=entry["details"],
                    ip_address=entry.get("ip_address"),
                    user_agent=entry.get("user_agent"),
                    correlation_id=entry.get("correlation_id"),
                )
                session.add(log_entry)
                await session.commit()
        except Exception:
            logger.warning("failed to write audit log entry", exc_info=True)


def _guess_resource_type(path: str) -> str:
    """Guess the resource type from the URL path."""
    segments = path.strip("/").split("/")
    # /api/v1/certificates/... -> certificates
    if len(segments) >= 3 and segments[0] == "api" and segments[1] == "v1":
        return segments[2] if len(segments) >= 3 else "unknown"
    return "unknown"
