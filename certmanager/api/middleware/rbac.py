"""Role-Based Access Control (RBAC) middleware.

Validates JWT tokens and checks user permissions against requested resources.
Sets request.state with actor information for downstream use (audit logging).

Public paths (auth, health) skip authentication.
All other paths require a valid JWT with appropriate permissions.
"""

from __future__ import annotations

from typing import Set

import structlog
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from certmanager.core.security import decode_token

logger = structlog.get_logger()

# Paths that do not require authentication
PUBLIC_PATH_PREFIXES: Set[str] = {
    "/api/health",
    "/api/docs",
    "/api/redoc",
    "/api/openapi.json",
    "/api/v1/auth",
    "/api/v1/agents/register",  # Only registration is public (uses PSK)
}

# Paths that use agent authentication (not user JWT)
AGENT_PATH_PREFIXES: Set[str] = {
    "/api/v1/agents/",
}


class RBACMiddleware(BaseHTTPMiddleware):
    """JWT validation and RBAC enforcement middleware."""

    async def dispatch(self, request: Request, call_next) -> Response:
        path = request.url.path

        # Skip middleware for public paths and OPTIONS
        if request.method == "OPTIONS":
            return await call_next(request)

        if any(path.startswith(prefix) for prefix in PUBLIC_PATH_PREFIXES):
            # Still set anonymous state for audit
            request.state.actor_type = "anonymous"
            request.state.actor_id = None
            request.state.actor_email = None
            return await call_next(request)

        # Determine auth type
        is_agent_path = any(path.startswith(prefix) for prefix in AGENT_PATH_PREFIXES)

        # Extract token from Authorization header
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

        if is_agent_path and token_type == "agent":
            # Agent token: set agent actor info
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
        if required_permission:
            if required_permission not in user_permissions:
                return JSONResponse(
                    status_code=403,
                    content={
                        "error": "AuthorizationError",
                        "message": f"Missing required permission: {required_permission}",
                    },
                )

        return await call_next(request)


def _get_required_permission(path: str, method: str) -> str | None:
    """Map HTTP method + URL path to a required permission string.

    Returns None if no specific permission is needed (e.g., read-only ops
    that any authenticated user can perform).
    """
    segments = path.strip("/").split("/")

    # Extract resource name from /api/v1/{resource}/...
    if len(segments) < 3:
        return None
    resource = segments[2]

    # Map HTTP method to action
    method_to_action = {
        "GET": "read",
        "POST": "create",
        "PUT": "update",
        "PATCH": "update",
        "DELETE": "delete",
    }
    action = method_to_action.get(method, "read")

    # Read access is the default — only check for write operations
    if action == "read":
        return None

    return f"{resource}:{action}"
