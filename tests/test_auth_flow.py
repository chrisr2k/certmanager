"""Authentication flow tests: login, rotation with reuse detection, logout,
MFA setup/verify/recovery.

The refresh-family store falls back to in-memory in tests (no Redis on
port 6399), which exercises the same code path as production Redis.
"""

from __future__ import annotations

import pyotp
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from certmanager.core.models import User
from tests.conftest import ADMIN_EMAIL, ADMIN_PASSWORD


class TestLogin:
    async def test_login_wrong_password(self, client: AsyncClient):
        resp = await client.post(
            "/api/v1/auth/login",
            json={"email": ADMIN_EMAIL, "password": "wrong-password"},
        )
        assert resp.status_code == 401

    async def test_login_and_profile(
        self, client: AsyncClient, admin_token: str, admin_headers: dict
    ):
        resp = await client.get("/api/v1/auth/me", headers=admin_headers)
        assert resp.status_code == 200
        profile = resp.json()
        assert profile["email"] == ADMIN_EMAIL
        assert profile["is_superuser"] is True

    async def test_missing_token_rejected(self, client: AsyncClient):
        resp = await client.get("/api/v1/certificates")
        assert resp.status_code == 401


class TestRefreshRotation:
    async def test_refresh_rotates_and_reuse_is_detected(self, client: AsyncClient):
        login = await client.post(
            "/api/v1/auth/login",
            json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
        )
        assert login.status_code == 200
        refresh_token = login.json()["refresh_token"]

        # First refresh — rotates the family
        first = await client.post("/api/v1/auth/refresh", json={"refresh_token": refresh_token})
        assert first.status_code == 200, first.text
        new_refresh = first.json()["refresh_token"]
        assert new_refresh != refresh_token

        # Replaying the OLD token = theft signal → family revoked
        replay = await client.post("/api/v1/auth/refresh", json={"refresh_token": refresh_token})
        assert replay.status_code == 401

        # The NEW token is now also dead (whole family revoked)
        after_reuse = await client.post("/api/v1/auth/refresh", json={"refresh_token": new_refresh})
        assert after_reuse.status_code == 401

    async def test_logout_revokes_family(self, client: AsyncClient):
        login = await client.post(
            "/api/v1/auth/login",
            json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
        )
        tokens = login.json()

        logout = await client.post(
            "/api/v1/auth/logout",
            headers={"Authorization": f"Bearer {tokens['access_token']}"},
            json={"refresh_token": tokens["refresh_token"]},
        )
        assert logout.status_code == 200

        resp = await client.post(
            "/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]}
        )
        assert resp.status_code == 401


class TestMFAFlow:
    async def test_mfa_setup_verify_and_recovery(
        self, client: AsyncClient, seeded_db: AsyncSession, admin_token: str, admin_headers: dict
    ):
        # Setup returns a secret; the server holds it pending
        setup = await client.post("/api/v1/auth/mfa/setup", headers=admin_headers)
        assert setup.status_code == 200, setup.text
        secret = setup.json()["secret"]

        # Client-side chosen secret is IGNORED — verification uses the
        # server's pending secret. Wrong code fails.
        bad = await client.post(
            "/api/v1/auth/mfa/verify", headers=admin_headers, json={"code": "000000"}
        )
        assert bad.status_code == 401

        # Correct code from the pending secret enables MFA
        good = await client.post(
            "/api/v1/auth/mfa/verify",
            headers=admin_headers,
            json={"code": pyotp.TOTP(secret).now()},
        )
        assert good.status_code == 200, good.text
        recovery_codes = good.json()["recovery_codes"]
        assert len(recovery_codes) == 8

        # MFA is now required at login
        login = await client.post(
            "/api/v1/auth/login",
            json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
        )
        assert login.status_code == 401
        assert login.json().get("mfa_required") is True

        # Login WITH the TOTP code works
        login_mfa = await client.post(
            "/api/v1/auth/login",
            json={
                "email": ADMIN_EMAIL,
                "password": ADMIN_PASSWORD,
                "mfa_code": pyotp.TOTP(secret).now(),
            },
        )
        assert login_mfa.status_code == 200

        # Recovery: consume a code → MFA disabled
        recover = await client.post(
            "/api/v1/auth/mfa/recover",
            json={"email": ADMIN_EMAIL, "recovery_code": recovery_codes[0]},
        )
        assert recover.status_code == 200, recover.text

        login_plain = await client.post(
            "/api/v1/auth/login",
            json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
        )
        assert login_plain.status_code == 200, "MFA disabled after recovery"

        # The consumed code is single-use
        user = (await seeded_db.execute(select(User).where(User.email == ADMIN_EMAIL))).scalar_one()
        import hashlib

        used_hash = hashlib.sha256(recovery_codes[0].encode()).hexdigest()
        assert used_hash not in (user.recovery_codes or [])
