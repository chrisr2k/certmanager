"""FastAPI dependency injection.

Provides:
- get_db: async database session
- get_current_user: authenticated user from JWT
- get_current_active_user: authenticated + active user
- require_permission: permission check dependency
- require_superuser: admin-only dependency
"""

from __future__ import annotations

from typing import AsyncGenerator

from fastapi import Depends, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from certmanager.core.database import get_db
from certmanager.core.exceptions import AuthenticationError, AuthorizationError
from certmanager.core.models import User


async def get_current_user(
    request: Request, db: AsyncSession = Depends(get_db)
) -> User:
    """Dependency: extract and validate the current user from the request state.

    The RBAC middleware has already validated the JWT (or X-API-Key) and set
    request.state. This dependency fetches the full User ORM object. API-key
    requests resolve to their owning user (scopes are enforced by the RBAC
    middleware before the router runs).
    """
    user_id = getattr(request.state, "actor_id", None)
    actor_type = getattr(request.state, "actor_type", None)

    if not user_id or actor_type not in ("user", "api_key"):
        raise AuthenticationError("Authentication required")

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if user is None:
        raise AuthenticationError("User not found")

    if not user.is_active:
        raise AuthenticationError("User account is deactivated")

    return user


async def get_current_active_user(
    current_user: User = Depends(get_current_user),
) -> User:
    """Dependency: ensure the current user is active (handled by get_current_user)."""
    return current_user


def require_superuser(
    current_user: User = Depends(get_current_active_user),
) -> User:
    """Dependency: require superuser privileges."""
    if not current_user.is_superuser:
        raise AuthorizationError("Superuser privileges required")
    return current_user


def require_permission(resource: str, action: str):
    """Dependency factory: require a specific permission.

    Usage:
        @router.post("/certificates")
        async def create_cert(
            user: User = Depends(require_permission("certificates", "create"))
        ):
            ...
    """

    async def _check(
        current_user: User = Depends(get_current_active_user),
        request: Request = None,
    ) -> User:
        if current_user.is_superuser:
            return current_user

        # Check if user has the required permission via their roles
        # (permissions are embedded in the JWT, set by RBAC middleware)
        user_permissions = getattr(request.state, "user_permissions", [])
        required = f"{resource}:{action}"

        if required not in user_permissions:
            raise AuthorizationError(f"Missing permission: {required}")

        return current_user

    return _check
