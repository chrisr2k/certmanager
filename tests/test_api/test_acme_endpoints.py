"""ACME API endpoint tests: issue/renew dispatch, download permission
gating (admin-only), expiry (410), and a private-key leak check against
the audit log — the download response is a new sensitive payload shape
that predates the existing redaction work, so it must not be assumed
covered."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from certmanager.core.crypto import encrypt_value
from certmanager.core.models import (
    AuditLog,
    Certificate,
    CertificateAuthority,
    CertificateKeyBundle,
    Role,
    ScanJob,
    User,
    UserRole,
)
from certmanager.core.security import hash_password


async def _make_acme_authority(seeded_db: AsyncSession) -> CertificateAuthority:
    # Celery isn't running in tests, so dispatch always falls through to the
    # "stays pending" branch — the connector is never actually built here.
    authority = CertificateAuthority(
        name="Test LE",
        ca_type="acme",
        config={"contact_email": "a@b.com", "domains": ["example.com"]},
    )
    seeded_db.add(authority)
    await seeded_db.flush()
    return authority


async def _make_cert_and_bundle(
    seeded_db: AsyncSession, authority_id: str, expires_delta: timedelta
) -> tuple[Certificate, CertificateKeyBundle]:
    cert = Certificate(
        common_name="www.example.com",
        not_before=datetime.now(UTC),
        not_after=datetime.now(UTC) + timedelta(days=90),
        validity_days=90,
        source_type="acme",
        source_ca_id=authority_id,
        source_detail={
            "cert_pem": "FAKE-CERT-PEM",
            "chain_pem": "FAKE-CHAIN-PEM",
            "fullchain_pem": "FAKE-FULLCHAIN-PEM",
        },
    )
    seeded_db.add(cert)
    await seeded_db.flush()

    bundle = CertificateKeyBundle(
        certificate_id=cert.id,
        encrypted_private_key=encrypt_value("SUPER-SECRET-PRIVATE-KEY-MATERIAL"),
        expires_at=datetime.now(UTC) + expires_delta,
    )
    seeded_db.add(bundle)
    await seeded_db.flush()
    await seeded_db.commit()
    return cert, bundle


async def _viewer_headers(client: AsyncClient, seeded_db: AsyncSession) -> dict:
    viewer_role = (await seeded_db.execute(select(Role).where(Role.name == "viewer"))).scalar_one()
    user = User(
        email="acme-viewer@test.local",
        password_hash=hash_password("viewer-password-123"),
        is_active=True,
    )
    seeded_db.add(user)
    await seeded_db.flush()
    seeded_db.add(UserRole(user_id=user.id, role_id=viewer_role.id))
    await seeded_db.commit()

    login = await client.post(
        "/api/v1/auth/login",
        json={"email": "acme-viewer@test.local", "password": "viewer-password-123"},
    )
    return {"Authorization": f"Bearer {login.json()['access_token']}"}


class TestIssueAndRenewDispatch:
    async def test_issue_requires_acme_authority(
        self, client: AsyncClient, admin_headers: dict, seeded_db: AsyncSession
    ):
        non_acme = CertificateAuthority(name="AWS", ca_type="aws_acm", config={})
        seeded_db.add(non_acme)
        await seeded_db.commit()

        resp = await client.post(
            f"/api/v1/authorities/{non_acme.id}/issue",
            headers=admin_headers,
            json={"common_name": "www.example.com"},
        )
        # ValidationError -> 422, matching the convention scans.py already
        # uses for this exact kind of precondition failure.
        assert resp.status_code == 422

    async def test_issue_dispatches_pending_job(
        self, client: AsyncClient, admin_headers: dict, seeded_db: AsyncSession
    ):
        authority = await _make_acme_authority(seeded_db)
        await seeded_db.commit()

        resp = await client.post(
            f"/api/v1/authorities/{authority.id}/issue",
            headers=admin_headers,
            json={"common_name": "www.example.com", "sans": ["api.example.com"]},
        )
        assert resp.status_code == 201, resp.text
        job_id = resp.json()["data"]["scan_job_id"]

        job = (await seeded_db.execute(select(ScanJob).where(ScanJob.id == job_id))).scalar_one()
        assert job.job_type == "acme_issue"
        assert job.scope_config["common_name"] == "www.example.com"
        assert job.scope_config["sans"] == ["api.example.com"]

    async def test_renew_dispatches_pending_job(
        self, client: AsyncClient, admin_headers: dict, seeded_db: AsyncSession
    ):
        authority = await _make_acme_authority(seeded_db)
        cert, _bundle = await _make_cert_and_bundle(seeded_db, authority.id, timedelta(hours=48))

        resp = await client.post(
            f"/api/v1/authorities/{authority.id}/renew",
            headers=admin_headers,
            json={"certificate_id": cert.id},
        )
        assert resp.status_code == 201, resp.text
        job_id = resp.json()["data"]["scan_job_id"]

        job = (await seeded_db.execute(select(ScanJob).where(ScanJob.id == job_id))).scalar_one()
        assert job.job_type == "acme_renew"
        assert job.scope_config["certificate_id"] == cert.id


class TestKeyBundleDownload:
    async def test_admin_can_download(
        self, client: AsyncClient, admin_headers: dict, seeded_db: AsyncSession
    ):
        authority = await _make_acme_authority(seeded_db)
        _cert, bundle = await _make_cert_and_bundle(seeded_db, authority.id, timedelta(hours=48))

        resp = await client.get(
            f"/api/v1/authorities/key-bundles/{bundle.id}/download", headers=admin_headers
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()["data"]
        assert body["private_key_pem"] == "SUPER-SECRET-PRIVATE-KEY-MATERIAL"
        assert body["certificate_pem"] == "FAKE-CERT-PEM"

    async def test_viewer_cannot_download(self, client: AsyncClient, seeded_db: AsyncSession):
        authority = await _make_acme_authority(seeded_db)
        _cert, bundle = await _make_cert_and_bundle(seeded_db, authority.id, timedelta(hours=48))
        viewer_headers = await _viewer_headers(client, seeded_db)

        resp = await client.get(
            f"/api/v1/authorities/key-bundles/{bundle.id}/download", headers=viewer_headers
        )
        assert resp.status_code == 403

    async def test_expired_bundle_returns_410(
        self, client: AsyncClient, admin_headers: dict, seeded_db: AsyncSession
    ):
        authority = await _make_acme_authority(seeded_db)
        _cert, bundle = await _make_cert_and_bundle(seeded_db, authority.id, timedelta(hours=-1))

        resp = await client.get(
            f"/api/v1/authorities/key-bundles/{bundle.id}/download", headers=admin_headers
        )
        assert resp.status_code == 410

    async def test_download_marks_downloaded_at(
        self, client: AsyncClient, admin_headers: dict, seeded_db: AsyncSession
    ):
        authority = await _make_acme_authority(seeded_db)
        _cert, bundle = await _make_cert_and_bundle(seeded_db, authority.id, timedelta(hours=48))
        assert bundle.downloaded_at is None

        await client.get(
            f"/api/v1/authorities/key-bundles/{bundle.id}/download", headers=admin_headers
        )

        refreshed = (
            await seeded_db.execute(
                select(CertificateKeyBundle).where(CertificateKeyBundle.id == bundle.id)
            )
        ).scalar_one()
        assert refreshed.downloaded_at is not None

    async def test_private_key_never_reaches_audit_log(
        self, client: AsyncClient, admin_headers: dict, seeded_db: AsyncSession
    ):
        authority = await _make_acme_authority(seeded_db)
        _cert, bundle = await _make_cert_and_bundle(seeded_db, authority.id, timedelta(hours=48))

        resp = await client.get(
            f"/api/v1/authorities/key-bundles/{bundle.id}/download", headers=admin_headers
        )
        assert resp.status_code == 200

        logs = (await seeded_db.execute(select(AuditLog))).scalars().all()
        for log in logs:
            assert "SUPER-SECRET-PRIVATE-KEY-MATERIAL" not in str(log.details)
            assert "SUPER-SECRET-PRIVATE-KEY-MATERIAL" not in str(log.action)
            assert "SUPER-SECRET-PRIVATE-KEY-MATERIAL" not in str(log.resource_id or "")
