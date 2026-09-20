"""User management router (admin-only operations)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from certmanager.api.dependencies import get_db, require_superuser
from certmanager.core.exceptions import ConflictError, NotFoundError
from certmanager.core.models import Role, User, UserRole
from certmanager.core.security import hash_password

router = APIRouter()


class UserCreate(BaseModel):
    """Body for creating a user. Password travels in the body — never as a
    query param, which would leak into access logs and audit records."""

    email: str
    password: str
    full_name: str | None = None
    is_superuser: bool = False
    role_ids: list[str] | None = None


class UserUpdate(BaseModel):
    """Body for updating a user — all fields optional."""

    full_name: str | None = None
    is_active: bool | None = None
    is_superuser: bool | None = None


@router.get("")
async def list_users(
    is_active: bool | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=250),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_superuser),
):
    """List all users (admin only)."""
    query = select(User)
    if is_active is not None:
        query = query.where(User.is_active == is_active)

    count_query = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_query)).scalar()

    offset = (page - 1) * page_size
    query = query.order_by(User.email).offset(offset).limit(page_size)

    result = await db.execute(query)
    users = result.scalars().all()

    return {
        "data": [
            {
                "id": u.id,
                "email": u.email,
                "full_name": u.full_name,
                "is_active": u.is_active,
                "is_superuser": u.is_superuser,
                "mfa_enabled": u.mfa_enabled,
                "roles": [r.name for r in u.roles],
                "created_at": u.created_at.isoformat(),
            }
            for u in users
        ],
        "page": page,
        "page_size": page_size,
        "total": total,
    }


@router.post("", status_code=201)
async def create_user(
    body: UserCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_superuser),
):
    """Create a new user (admin only)."""
    existing = await db.execute(select(User).where(User.email == body.email))
    if existing.scalar_one_or_none():
        raise ConflictError(f"User with email '{body.email}' already exists")

    user = User(
        email=body.email,
        password_hash=hash_password(body.password),
        full_name=body.full_name,
        is_superuser=body.is_superuser,
    )
    db.add(user)
    await db.flush()

    # Assign roles
    if body.role_ids:
        for role_id in body.role_ids:
            db.add(UserRole(user_id=user.id, role_id=role_id))
    else:
        # Default: assign "viewer" role
        viewer = await db.execute(select(Role).where(Role.name == "viewer"))
        viewer_role = viewer.scalar_one_or_none()
        if viewer_role:
            db.add(UserRole(user_id=user.id, role_id=viewer_role.id))

    await db.flush()
    await db.refresh(user)

    return {
        "data": {
            "id": user.id,
            "email": user.email,
            "full_name": user.full_name,
            "is_superuser": user.is_superuser,
        }
    }


@router.get("/roles")
async def list_roles(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_superuser),
):
    """List all RBAC roles (admin only). Used by the user-creation form."""
    result = await db.execute(select(Role).order_by(Role.name))
    roles = result.scalars().all()
    return {
        "data": [
            {"id": role.id, "name": role.name, "description": role.description}
            for role in roles
        ]
    }


@router.get("/{user_id}")
async def get_user(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_superuser),
):
    """Get a user's details."""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise NotFoundError(f"User {user_id} not found")

    return {
        "data": {
            "id": user.id,
            "email": user.email,
            "full_name": user.full_name,
            "is_active": user.is_active,
            "is_superuser": user.is_superuser,
            "mfa_enabled": user.mfa_enabled,
            "roles": [{"id": r.id, "name": r.name} for r in user.roles],
        }
    }


@router.patch("/{user_id}")
async def update_user(
    user_id: str,
    body: UserUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_superuser),
):
    """Update a user."""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise NotFoundError(f"User {user_id} not found")

    if body.full_name is not None:
        user.full_name = body.full_name
    if body.is_active is not None:
        user.is_active = body.is_active
    if body.is_superuser is not None:
        user.is_superuser = body.is_superuser

    await db.flush()
    return {"data": {"id": user.id, "updated": True}}


@router.post("/{user_id}/roles")
async def assign_role(
    user_id: str,
    role_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_superuser),
):
    """Assign a role to a user."""
    user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if not user:
        raise NotFoundError(f"User {user_id} not found")

    role = (await db.execute(select(Role).where(Role.id == role_id))).scalar_one_or_none()
    if not role:
        raise NotFoundError(f"Role {role_id} not found")

    existing = await db.execute(
        select(UserRole).where(UserRole.user_id == user_id, UserRole.role_id == role_id)
    )
    if existing.scalar_one_or_none():
        return {"data": {"message": "Role already assigned"}}

    db.add(UserRole(user_id=user_id, role_id=role_id))
    await db.flush()
    return {"data": {"assigned": True, "role": role.name}}


@router.delete("/{user_id}/roles/{role_id}", status_code=204)
async def remove_role(
    user_id: str,
    role_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_superuser),
):
    """Remove a role from a user."""
    result = await db.execute(
        select(UserRole).where(UserRole.user_id == user_id, UserRole.role_id == role_id)
    )
    mapping = result.scalar_one_or_none()
    if not mapping:
        raise NotFoundError("Role assignment not found")
    await db.delete(mapping)
    await db.flush()
