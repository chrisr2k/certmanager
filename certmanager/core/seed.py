"""Seed RBAC roles and permissions.

Run once after initial migration to populate the permission model:
    certmanager seed

Creates 4 roles:
- admin: Full access to all resources
- operator: Can manage certificates, CAs, scans, and alerts
- viewer: Read-only access to certificates and reports
- auditor: Read-only access to audit logs and reports
"""

from __future__ import annotations

import os

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from certmanager.core.models import Permission, Role, User, UserRole
from certmanager.core.security import hash_password

# Permission matrix: (resource, action) pairs per role
ROLE_PERMISSIONS = {
    "admin": [
        # Admins get ALL permissions
        ("*", "manage"),
    ],
    "operator": [
        ("certificates", "read"),
        ("certificates", "create"),
        ("certificates", "update"),
        ("certificates", "delete"),
        ("authorities", "read"),
        ("authorities", "create"),
        ("authorities", "update"),
        ("authorities", "delete"),
        ("alerts", "read"),
        ("alerts", "create"),
        ("alerts", "update"),
        ("alerts", "delete"),
        ("scans", "read"),
        ("scans", "create"),
        ("scans", "update"),
        ("reports", "read"),
        ("reports", "create"),
        ("datacenters", "read"),
        ("agents", "read"),
        ("agents", "create"),
        ("agents", "update"),
    ],
    "viewer": [
        ("certificates", "read"),
        ("authorities", "read"),
        ("alerts", "read"),
        ("scans", "read"),
        ("reports", "read"),
        ("datacenters", "read"),
        ("agents", "read"),
    ],
    "auditor": [
        ("certificates", "read"),
        ("reports", "read"),
        ("audit_logs", "read"),
        ("alerts", "read"),
    ],
}

DEFAULT_ADMIN_EMAIL = "admin@certmanager.local"
DEFAULT_ADMIN_PASSWORD = "changeme123"  # Should be changed on first login


async def seed_roles_and_permissions(db: AsyncSession) -> dict[str, Role]:
    """Create all roles and permissions. Idempotent — skips existing."""
    created_roles = {}

    for role_name, perm_tuples in ROLE_PERMISSIONS.items():
        # Check if role already exists
        result = await db.execute(select(Role).where(Role.name == role_name))
        role = result.scalar_one_or_none()

        if role is None:
            role = Role(
                name=role_name,
                description=f"Auto-generated {role_name} role",
            )
            db.add(role)
            await db.flush()
            await db.refresh(role)

        # Create permissions and assign to role
        for resource, action in perm_tuples:
            # Find or create permission
            perm_result = await db.execute(
                select(Permission).where(
                    Permission.resource == resource, Permission.action == action
                )
            )
            perm = perm_result.scalar_one_or_none()

            if perm is None:
                perm = Permission(resource=resource, action=action)
                db.add(perm)
                await db.flush()

            # Assign to role if not already
            from certmanager.core.models import RolePermission

            rp_result = await db.execute(
                select(RolePermission).where(
                    RolePermission.role_id == role.id,
                    RolePermission.permission_id == perm.id,
                )
            )
            if rp_result.scalar_one_or_none() is None:
                db.add(RolePermission(role_id=role.id, permission_id=perm.id))

        created_roles[role_name] = role

    await db.flush()
    return created_roles


async def seed_admin_user(db: AsyncSession, email: str = None, password: str = None) -> User:
    """Create the default admin user. Idempotent — skips if exists."""
    email = email or DEFAULT_ADMIN_EMAIL
    # Production deployments must supply CERTMGMT_SEED_ADMIN_PASSWORD —
    # never seed a public instance with the well-known default.
    password = (
        password
        or os.environ.get("CERTMGMT_SEED_ADMIN_PASSWORD")
        or DEFAULT_ADMIN_PASSWORD
    )

    result = await db.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()

    if user is None:
        user = User(
            email=email,
            password_hash=hash_password(password),
            full_name="System Administrator",
            is_superuser=True,
            is_active=True,
        )
        db.add(user)
        await db.flush()
        await db.refresh(user)

    # Assign admin role
    admin_role = await db.execute(select(Role).where(Role.name == "admin"))
    admin_role = admin_role.scalar_one_or_none()

    if admin_role:
        existing = await db.execute(
            select(UserRole).where(UserRole.user_id == user.id, UserRole.role_id == admin_role.id)
        )
        if not existing.scalar_one_or_none():
            db.add(UserRole(user_id=user.id, role_id=admin_role.id))
            await db.flush()

    return user


async def seed_all(
    db: AsyncSession,
    admin_email: str = None,
    admin_password: str = None,
) -> dict:
    """Run all seed operations. Returns summary."""
    roles = await seed_roles_and_permissions(db)
    admin = await seed_admin_user(db, email=admin_email, password=admin_password)

    await db.commit()

    return {
        "roles_created": list(roles.keys()),
        "admin_user": admin.email,
        "permissions_total": sum(len(perms) for perms in ROLE_PERMISSIONS.values()),
    }
