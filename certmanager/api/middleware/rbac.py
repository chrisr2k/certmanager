"""Role-Based Access Control (RBAC) middleware.

Validates JWTs (user + agent) and X-API-Key credentials, checks user
permissions against requested resources, and sets request.state with actor
information for downstream use (audit logging).

Public paths (health, docs, auth, agent registration) skip authentication.
All other paths require a valid credential with appropriate permissions.

Permission model:
- Writes always require {resource}:{action}.
- Reads require {resource}:read only for resources that HAVE read
  permissions in the seed matrix (so admin-ish data like agents and audit
  logs is gated, while everyday dashboards stay open to any authenticated
  user).
- Wildcards: "*:manage" (admin role) grants everything; an exact
  "{resource}:{action}" match is otherwise required.
"""

from __future__ import annotations

import hashlib
from typing import Set

import structlog
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from certmanager.core.security import decode_token

logger = structlog.get_logger()

# Paths that do not require authentication. Only the EXACT unauthenticated
# endpoints are listed — never the whole /api/v1/auth prefix, which would
# wrongly expose /auth/me, /auth/logout, and MFA setup to anonymous callers
# (and would also have matched /api/v1/authorities with naive prefix logic).
PUBLIC_PATH_PREFIXES: Set[str] = {
    "/api/health",
    "/api/docs",
    "/api/redoc",
    "/api/openapi.json",
    "/api/v1/auth/login",
    "/api/v1/auth/refresh",
    "/api/v1/auth/mfa/recover",
    "/api/v1/agents/register",  # Only registration is public (uses PSK)
}

# Paths that use agent authentication (not user JWT)
AGENT_PATH_PREFIXES: Set[str] = {
    "/api/v1/agents/",
}

# Resources that have seeded read permissions — GETs on these require the
# corresponding {resource}:read permission. Derived from core.seed so the
# two can never drift.
from certmanager.core.seed import ROLE_PERMISSIONS  # noqa: E402

READ_PROTECTED_RESOURCES: Set[str] = {
    resource
    for perms in ROLE_PERMISSIONS.values()
    for resource, action in perms
    if action == "read" and resource != "*"
}

SENSITIVE_HEADER_NAMES = {"authorization", "x-api-key"}


def _path_is_public(path: str) -> bool:
    return any(path == prefix or path.startswith(prefix + "/") for prefix in PUBLIC_PATH_PREFIXES)


class RBACMiddleware(BaseHTTPMiddleware):
    """JWT + API-key validation and RBAC enforcement middleware."""

    async def dispatch(self, request: Request, call_next) -> Response:
        path = request.url.path

        # Skip middleware for public paths and OPTIONS
        if request.method == "OPTIONS":
            return await call_next(request)

        if _path_is_public(path):
            # Still set anonymous state for audit
            request.state.actor_type = "anonymous"
            request.state.actor_id = None
            request.state.actor_email = None
            return await call_next(request)

        # --- API key auth (X-API-Key header) ---
        api_key = request.headers.get("X-API-Key")
        if api_key:
            response = await self._handle_api_key(request, api_key)
            if response is not None:
                return response
            if request.state.actor_type == "api_key":
                return await self._check_api_key_permission(request, call_next)

        # --- Bearer token auth ---
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return JSONResponse(
                status_code=401,
                content={"error": "AuthenticationError", "message": "Missing or invalid Authorization header"},
            )

        token = auth_header[7:]  # Remove "Bearer " prefix

        try:
            payload = decode_token(token)
        except Exception:
            return JSONResponse(
                status_code=401,
                content={"error": "AuthenticationError", "message": "Invalid or expired token"},
            )

        token_type = payload.get("type")

        is_agent_path = any(path.startswith(prefix) for prefix in AGENT_PATH_PREFIXES)

        if is_agent_path and token_type == "agent":
            # Agent token: set agent actor info. Ownership + approval checks
            # are enforced in the agents router (it has the DB context).
            request.state.actor_type = "agent"
            request.state.actor_id = payload.get("sub")
            request.state.actor_email = payload.get("agent_name")
            request.state.agent_datacenter = payload.get("datacenter_id")
            return await call_next(request)

        if token_type != "access":
            return JSONResponse(
                status_code=401,
                content={"error": "AuthenticationError", "message": "Access token required"},
            )

        # User token: extract user info and check permissions
        user_id = payload.get("sub")
        user_roles = payload.get("roles", [])
        user_permissions = payload.get("permissions", [])

        request.state.actor_type = "user"
        request.state.actor_id = user_id
        request.state.actor_email = payload.get("email")
        request.state.user_roles = user_roles
        request.state.user_permissions = user_permissions

        # Superusers bypass RBAC checks
        if payload.get("is_superuser"):
            return await call_next(request)

        # Check required permission for this path
        required_permission = _get_required_permission(path, request.method)
        if required_permission and not _has_permission(user_permissions, required_permission):
            return JSONResponse(
                status_code=403,
                content={
                    "error": "AuthorizationError",
                    "message": f"Missing required permission: {required_permission}",
                },
            )

        return await call_next(request)

    # --- API key handling ---

    async def _handle_api_key(self, request: Request, api_key: str) -> Response | None:
        """Validate an X-API-Key header. Returns a 401 response on failure,
        None on success (actor state is set on the request)."""
        from datetime import UTC, datetime

        from sqlalchemy import select

        from certmanager.core.database import get_session_factory
        from certmanager.core.models import APIKey

        key_hash = hashlib.sha256(api_key.encode()).hexdigest()

        factory = get_session_factory()
        async with factory() as db:
            result = await db.execute(
                select(APIKey).where(APIKey.key_hash == key_hash)
            )
            key = result.scalar_one_or_none()

            if key is None or not key.is_active:
                return JSONResponse(
                    status_code=401,
                    content={"error": "AuthenticationError", "message": "Invalid API key"},
                )

            if key.expires_at is not None and key.expires_at < datetime.now(UTC):
                return JSONResponse(
                    status_code=401,
                    content={"error": "AuthenticationError", "message": "API key expired"},
                )

            # Set actor state (scope enforcement happens in the permission check)
            request.state.actor_type = "api_key"
            request.state.actor_id = key.user_id
            request.state.actor_email = None
            request.state.api_key_id = key.id
            request.state.api_key_name = key.name
            request.state.user_permissions = key.scopes or []

            key.last_used_at = datetime.now(UTC)
            await db.commit()

        return None

    async def _check_api_key_permission(self, request: Request, call_next) -> Response:
        """Enforce API key scopes against the required permission."""
        required = _get_required_permission(request.url.path, request.method)
        scopes = getattr(request.state, "user_permissions", [])

        # "*" scope grants everything; otherwise the required permission
        # must be listed explicitly.
        if required and "*" not in scopes and required not in scopes:
            return JSONResponse(
                status_code=403,
                content={
                    "error": "AuthorizationError",
                    "message": f"API key lacks required scope: {required}",
                },
            )
        return await call_next(request)


def _has_permission(user_permissions: list[str], required: str) -> bool:
    """Check a permission against the user's list, honoring wildcards."""
    if "*:manage" in user_permissions or "*:*" in user_permissions:
        return True
    if required in user_permissions:
        return True
    # Resource wildcard: e.g. "certificates:*"
    resource, _action = required.split(":", 1)
    return f"{resource}:*" in user_permissions


def _get_required_permission(path: str, method: str) -> str | None:
    """Map HTTP method + URL path to a required permission string.

    Returns None if no specific permission is needed.
    """
    segments = path.strip("/").split("/")

    # Extract resource name from /api/v1/{resource}/...
    if len(segments) < 3:
        return None
    resource = segments[2].replace("-", "_")  # audit-logs -> audit_logs

    # Map HTTP method to action
    method_to_action = {
        "GET": "read",
        "POST": "create",
        "PUT": "update",
        "PATCH": "update",
        "DELETE": "delete",
    }
    action = method_to_action.get(method, "read")

    # Reads only require a permission for resources with seeded read perms
    if action == "read" and resource not in READ_PROTECTED_RESOURCES:
        return None

    return f"{resource}:{action}"
