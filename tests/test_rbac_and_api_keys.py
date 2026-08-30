"""RBAC middleware + API key auth tests.

Covers the security gaps found in review:
- read enforcement on protected resources (audit logs, agents)
- wildcard permissions (*:manage)
- segment-aware public path matching (/api/v1/auth vs /api/v1/authorities)
- X-API-Key authentication with scope enforcement
"""

from __future__ import annotations

import hashlib

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from certmanager.api.middleware.rbac import (
    _get_required_permission,
    _has_permission,
    _path_is_public,
)
from certmanager.core.models import APIKey
from tests.conftest import ADMIN_EMAIL, ADMIN_PASSWORD


class TestPermissionLogic:
    def test_public_path_matching_is_segment_aware(self):
        # Only the exact unauthenticated endpoints are public
        assert _path_is_public("/api/v1/auth/login") is True
        assert _path_is_public("/api/v1/auth/refresh") is True
        # The bare /auth prefix must NOT be public — and neither may
        # authenticated endpoints under it (me, logout, mfa/setup)
        assert _path_is_public("/api/v1/auth") is False
        assert _path_is_public("/api/v1/auth/me") is False
        # The classic prefix bug: authorities must NOT be public
        assert _path_is_public("/api/v1/authorities") is False
        assert _path_is_public("/api/v1/agents/register") is True
        assert _path_is_public("/api/v1/agents/abc/heartbeat") is False

    def test_write_permissions_required(self):
        assert _get_required_permission("/api/v1/certificates", "POST") == "certificates:create"
        assert _get_required_permission("/api/v1/alerts/rules", "PATCH") == "alerts:update"
        assert _get_required_permission("/api/v1/agents/abc/approve", "PATCH") == "agents:update"

    def test_read_permissions_on_protected_resources(self):
        # audit-logs normalizes to audit_logs (seed permission name)
        assert _get_required_permission("/api/v1/audit-logs", "GET") == "audit_logs:read"
        assert _get_required_permission("/api/v1/agents", "GET") == "agents:read"
        # Unseeded resources stay open to any authenticated user
        assert _get_required_permission("/api/v1/dashboard/topology", "GET") is None

    def test_wildcard_permissions(self):
        assert _has_permission(["*:manage"], "certificates:create") is True
        assert _has_permission(["certificates:*"], "certificates:create") is True
        assert _has_permission(["alerts:read"], "certificates:read") is False


class TestReadEnforcement:
    async def test_non_admin_cannot_read_audit_logs(self, client: AsyncClient, seeded_db: AsyncSession):
        # Create a plain user with the viewer role (no audit_logs:read)
        from certmanager.core.security import hash_password
        from certmanager.core.models import Role, User, UserRole

        viewer_role = (
            await seeded_db.execute(select(Role).where(Role.name == "viewer"))
        ).scalar_one()
        user = User(
            email="viewer@test.local",
            password_hash=hash_password("viewer-password-123"),
            is_active=True,
        )
        seeded_db.add(user)
        await seeded_db.flush()
        seeded_db.add(UserRole(user_id=user.id, role_id=viewer_role.id))
        await seeded_db.commit()

        login = await client.post(
            "/api/v1/auth/login",
            json={"email": "viewer@test.local", "password": "viewer-password-123"},
        )
        viewer_headers = {"Authorization": f"Bearer {login.json()['access_token']}"}

        resp = await client.get("/api/v1/audit-logs", headers=viewer_headers)
        assert resp.status_code == 403

    async def test_viewer_can_read_certificates(self, client: AsyncClient, seeded_db: AsyncSession):
        from certmanager.core.security import hash_password
        from certmanager.core.models import Role, User, UserRole

        viewer_role = (
            await seeded_db.execute(select(Role).where(Role.name == "viewer"))
        ).scalar_one()
        user = User(
            email="viewer2@test.local",
            password_hash=hash_password("viewer-password-123"),
            is_active=True,
        )
        seeded_db.add(user)
        await seeded_db.flush()
        seeded_db.add(UserRole(user_id=user.id, role_id=viewer_role.id))
        await seeded_db.commit()

        login = await client.post(
            "/api/v1/auth/login",
            json={"email": "viewer2@test.local", "password": "viewer-password-123"},
        )
        headers = {"Authorization": f"Bearer {login.json()['access_token']}"}

        resp = await client.get("/api/v1/certificates", headers=headers)
        assert resp.status_code == 200, resp.text


class TestAPIKeys:
    async def test_api_key_authentication_and_scopes(
        self, client: AsyncClient, seeded_db: AsyncSession, admin_headers: dict
    ):
        # Create an API key with full scope via the API
        create = await client.post(
            "/api/v1/api-keys",
            headers=admin_headers,
            json={"name": "ci-key", "scopes": ["*"]},
        )
        # The router may expect query params or a body; handle both shapes
        if create.status_code != 201:
            create = await client.post(
                "/api/v1/api-keys",
                headers=admin_headers,
                params={"name": "ci-key", "scopes": "*"},
            )
        assert create.status_code == 201, create.text
        api_key = create.json()["data"].get("api_key") or create.json()["data"].get("key")
        assert api_key, create.text

        # Authenticate with X-API-Key
        resp = await client.get(
            "/api/v1/certificates", headers={"X-API-Key": api_key}
        )
        assert resp.status_code == 200, resp.text

        # Wrong key → 401
        resp = await client.get(
            "/api/v1/certificates", headers={"X-API-Key": "wrong-key"}
        )
        assert resp.status_code == 401

        # last_used_at updated
        key_row = (
            await seeded_db.execute(
                select(APIKey).where(
                    APIKey.key_hash == hashlib.sha256(api_key.encode()).hexdigest()
                )
            )
        ).scalar_one_or_none()
        assert key_row is not None
        assert key_row.last_used_at is not None

    async def test_api_key_scope_restriction(self, client: AsyncClient, seeded_db: AsyncSession):
        from certmanager.core.models import User

        # Create a key directly with limited scopes
        admin = (
            await seeded_db.execute(select(User).where(User.email == ADMIN_EMAIL))
        ).scalar_one()
        plain_key = "cm_" + "k" * 40
        key = APIKey(
            user_id=admin.id,
            name="limited-key",
            key_hash=hashlib.sha256(plain_key.encode()).hexdigest(),
            prefix=plain_key[:8],
            scopes=["alerts:read"],
            is_active=True,
        )
        seeded_db.add(key)
        await seeded_db.commit()

        # Allowed scope: alerts read (unseeded read → hmm, alerts IS seeded;
        # alerts:read matches) — alerts:read in scopes → pass
        resp = await client.get(
            "/api/v1/alerts/rules", headers={"X-API-Key": plain_key}
        )
        assert resp.status_code == 200, resp.text

        # Required permission not in scopes → 403
        resp = await client.get(
            "/api/v1/certificates", headers={"X-API-Key": plain_key}
        )
        assert resp.status_code == 403
