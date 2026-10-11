"""AD CS lifecycle API tests: ca_type branching on issue/renew/revoke, and
the agent-result persistence branch (source_ca_id, the renewal-storm fix,
opt-in key delivery)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from certmanager.core.models import (
    Certificate,
    CertificateAuthority,
    CertificateKeyBundle,
    ScanJob,
)

AGENT_ID = "44444444-4444-4444-8444-444444444444"


async def _make_adcs_authority(
    seeded_db: AsyncSession, agent_id: str = AGENT_ID, **config_overrides
) -> CertificateAuthority:
    config = {
        "agent_id": agent_id,
        "ca_server": "ca01.corp.internal",
        "ca_name": "CORP-ROOT-CA",
        "template": "WebServer",
        "deployment_target": "store",
        "deliver_key_to_central": False,
        **config_overrides,
    }
    authority = CertificateAuthority(name="Test AD CS", ca_type="adcs", config=config)
    seeded_db.add(authority)
    await seeded_db.flush()
    return authority


async def _make_adcs_cert(
    seeded_db: AsyncSession, authority_id: str, template: str = "WebServer"
) -> Certificate:
    cert = Certificate(
        common_name="svc.corp.internal",
        sans=["svc.corp.internal"],
        serial_number="00AABBCC",
        thumbprint_sha256="aa" * 32,
        not_before=datetime.now(UTC),
        not_after=datetime.now(UTC) + timedelta(days=30),
        validity_days=365,
        source_type="adcs",
        source_ca_id=authority_id,
        source_detail={"template": template},
        status="active",
    )
    seeded_db.add(cert)
    await seeded_db.flush()
    await seeded_db.commit()
    return cert


class TestIssueRenewRevokeDispatch:
    async def test_issue_requires_agent_id_configured(
        self, client: AsyncClient, admin_headers: dict, seeded_db: AsyncSession
    ):
        authority = await _make_adcs_authority(seeded_db, agent_id=None)
        await seeded_db.commit()

        resp = await client.post(
            f"/api/v1/authorities/{authority.id}/issue",
            headers=admin_headers,
            json={"common_name": "www.corp.internal"},
        )
        assert resp.status_code == 422

    async def test_issue_creates_pending_adcs_issue_job(
        self, client: AsyncClient, admin_headers: dict, seeded_db: AsyncSession
    ):
        authority = await _make_adcs_authority(seeded_db)
        await seeded_db.commit()

        resp = await client.post(
            f"/api/v1/authorities/{authority.id}/issue",
            headers=admin_headers,
            json={"common_name": "www.corp.internal", "sans": ["api.corp.internal"]},
        )
        assert resp.status_code == 201, resp.text
        job_id = resp.json()["data"]["scan_job_id"]

        job = (await seeded_db.execute(select(ScanJob).where(ScanJob.id == job_id))).scalar_one()
        assert job.job_type == "adcs_issue"
        assert job.status == "pending"
        assert job.scope_config["agent_id"] == AGENT_ID
        assert job.scope_config["common_name"] == "www.corp.internal"
        assert job.scope_config["template"] == "WebServer"

    async def test_renew_resolves_template_from_certificate_not_ca_default(
        self, client: AsyncClient, admin_headers: dict, seeded_db: AsyncSession
    ):
        # CA's default template differs from what this specific cert was
        # actually issued under — renewal must use the certificate's own.
        authority = await _make_adcs_authority(seeded_db, template="DefaultTemplate")
        cert = await _make_adcs_cert(seeded_db, authority.id, template="ClientAuthTemplate")

        resp = await client.post(
            f"/api/v1/authorities/{authority.id}/renew",
            headers=admin_headers,
            json={"certificate_id": cert.id},
        )
        assert resp.status_code == 201, resp.text
        job_id = resp.json()["data"]["scan_job_id"]

        job = (await seeded_db.execute(select(ScanJob).where(ScanJob.id == job_id))).scalar_one()
        assert job.job_type == "adcs_renew"
        assert job.scope_config["template"] == "ClientAuthTemplate"
        assert job.scope_config["certificate_id"] == cert.id
        assert job.scope_config["common_name"] == cert.common_name

    async def test_revoke_requires_serial_number(
        self, client: AsyncClient, admin_headers: dict, seeded_db: AsyncSession
    ):
        authority = await _make_adcs_authority(seeded_db)
        cert = Certificate(
            common_name="no-serial.corp.internal",
            not_before=datetime.now(UTC),
            not_after=datetime.now(UTC) + timedelta(days=30),
            validity_days=30,
            source_type="adcs",
            source_ca_id=authority.id,
            status="active",
        )
        seeded_db.add(cert)
        await seeded_db.commit()

        resp = await client.post(
            f"/api/v1/authorities/{authority.id}/revoke",
            headers=admin_headers,
            json={"certificate_id": cert.id},
        )
        assert resp.status_code == 422

    async def test_revoke_creates_pending_job_with_serial_and_ca_config(
        self, client: AsyncClient, admin_headers: dict, seeded_db: AsyncSession
    ):
        authority = await _make_adcs_authority(seeded_db)
        cert = await _make_adcs_cert(seeded_db, authority.id)

        resp = await client.post(
            f"/api/v1/authorities/{authority.id}/revoke",
            headers=admin_headers,
            json={"certificate_id": cert.id, "reason_code": 1},
        )
        assert resp.status_code == 201, resp.text
        job_id = resp.json()["data"]["scan_job_id"]

        job = (await seeded_db.execute(select(ScanJob).where(ScanJob.id == job_id))).scalar_one()
        assert job.job_type == "adcs_revoke"
        assert job.scope_config["serial_number"] == cert.serial_number
        assert job.scope_config["ca_server"] == "ca01.corp.internal"
        assert job.scope_config["reason_code"] == 1

    async def test_acme_revoke_not_yet_supported(
        self, client: AsyncClient, admin_headers: dict, seeded_db: AsyncSession
    ):
        authority = CertificateAuthority(name="Test LE", ca_type="acme", config={})
        seeded_db.add(authority)
        await seeded_db.commit()

        resp = await client.post(
            f"/api/v1/authorities/{authority.id}/revoke",
            headers=admin_headers,
            json={"certificate_id": "does-not-matter"},
        )
        assert resp.status_code == 422


async def _approve_and_headers(client: AsyncClient, admin_headers: dict, agent_type: str = "adcs") -> dict:
    resp = await client.post(
        "/api/v1/agents/register",
        json={
            "name": f"adcs-agent-{agent_type}",
            "agent_type": agent_type,
            "datacenter_code": "tstdc",
            "psk": "test-agent-psk",
        },
    )
    data = resp.json()["data"]
    await client.patch(f"/api/v1/agents/{data['agent_id']}/approve", headers=admin_headers)
    return {"agent_id": data["agent_id"], "headers": {"Authorization": f"Bearer {data['api_token']}"}}


class TestSubmitJobResultAdcsLifecycle:
    async def test_adcs_issue_persists_with_authority_as_source_ca(
        self, client: AsyncClient, admin_headers: dict, seeded_db: AsyncSession
    ):
        agent = await _approve_and_headers(client, admin_headers)
        authority = await _make_adcs_authority(seeded_db, agent_id=agent["agent_id"])
        await seeded_db.commit()

        job = ScanJob(
            job_type="adcs_issue",
            status="pending",
            triggered_by="manual",
            scope_config={"agent_id": agent["agent_id"], "authority_id": authority.id},
        )
        seeded_db.add(job)
        await seeded_db.commit()

        resp = await client.post(
            f"/api/v1/agents/{agent['agent_id']}/jobs/{job.id}/result",
            headers=agent["headers"],
            json={
                "total_checked": 1,
                "total_new": 1,
                "certificates": [
                    {
                        "common_name": "issued.corp.internal",
                        "subject": "CN=issued.corp.internal",
                        "issuer": "CN=CORP-ROOT-CA",
                        "serial_number": "001122",
                        "thumbprint": "bb" * 32,
                        "not_before": "2026-01-01T00:00:00+00:00",
                        "not_after": "2027-01-01T00:00:00+00:00",
                        "sans": ["issued.corp.internal"],
                        "template": "WebServer",
                        "status": "active",
                    }
                ],
            },
        )
        assert resp.status_code == 200, resp.text
        assert resp.json()["data"]["persisted"]["new"] == 1

        cert = (
            await seeded_db.execute(
                select(Certificate).where(Certificate.common_name == "issued.corp.internal")
            )
        ).scalar_one()
        assert cert.source_ca_id == authority.id, "must attribute to the CA, not None"
        assert cert.source_type == "adcs"

    async def test_adcs_renew_marks_old_certificate_superseded(
        self, client: AsyncClient, admin_headers: dict, seeded_db: AsyncSession
    ):
        agent = await _approve_and_headers(client, admin_headers)
        authority = await _make_adcs_authority(seeded_db, agent_id=agent["agent_id"])
        old_cert = await _make_adcs_cert(seeded_db, authority.id)

        job = ScanJob(
            job_type="adcs_renew",
            status="pending",
            triggered_by="manual",
            scope_config={
                "agent_id": agent["agent_id"],
                "authority_id": authority.id,
                "certificate_id": old_cert.id,
            },
        )
        seeded_db.add(job)
        await seeded_db.commit()

        resp = await client.post(
            f"/api/v1/agents/{agent['agent_id']}/jobs/{job.id}/result",
            headers=agent["headers"],
            json={
                "total_checked": 1,
                "total_new": 1,
                "certificates": [
                    {
                        "common_name": "svc.corp.internal",
                        "subject": "CN=svc.corp.internal",
                        "issuer": "CN=CORP-ROOT-CA",
                        "serial_number": "99887766",  # certreq always generates a new one
                        "thumbprint": "cc" * 32,  # and a new key/thumbprint
                        "not_before": "2026-01-01T00:00:00+00:00",
                        "not_after": "2027-01-01T00:00:00+00:00",
                        "sans": ["svc.corp.internal"],
                        "template": "WebServer",
                        "status": "active",
                    }
                ],
            },
        )
        assert resp.status_code == 200, resp.text

        await seeded_db.refresh(old_cert)
        assert old_cert.status == "superseded", (
            "without this, the daily scheduler would re-select the same "
            "stale row and renew it again indefinitely"
        )

        new_cert = (
            await seeded_db.execute(
                select(Certificate).where(Certificate.thumbprint_sha256 == "cc" * 32)
            )
        ).scalar_one()
        assert new_cert.status == "active"
        assert new_cert.id != old_cert.id

    async def test_adcs_revoke_marks_certificate_revoked(
        self, client: AsyncClient, admin_headers: dict, seeded_db: AsyncSession
    ):
        agent = await _approve_and_headers(client, admin_headers)
        authority = await _make_adcs_authority(seeded_db, agent_id=agent["agent_id"])
        cert = await _make_adcs_cert(seeded_db, authority.id)

        job = ScanJob(
            job_type="adcs_revoke",
            status="pending",
            triggered_by="manual",
            scope_config={
                "agent_id": agent["agent_id"],
                "authority_id": authority.id,
                "certificate_id": cert.id,
                "serial_number": cert.serial_number,
            },
        )
        seeded_db.add(job)
        await seeded_db.commit()

        resp = await client.post(
            f"/api/v1/agents/{agent['agent_id']}/jobs/{job.id}/result",
            headers=agent["headers"],
            json={"total_checked": 1, "certificates": [], "errors": []},
        )
        assert resp.status_code == 200, resp.text

        await seeded_db.refresh(cert)
        assert cert.status == "revoked"

    async def test_adcs_issue_failure_marks_job_failed_not_completed(
        self, client: AsyncClient, admin_headers: dict, seeded_db: AsyncSession
    ):
        agent = await _approve_and_headers(client, admin_headers)
        authority = await _make_adcs_authority(seeded_db, agent_id=agent["agent_id"])
        await seeded_db.commit()

        job = ScanJob(
            job_type="adcs_issue",
            status="pending",
            triggered_by="manual",
            scope_config={"agent_id": agent["agent_id"], "authority_id": authority.id},
        )
        seeded_db.add(job)
        await seeded_db.commit()

        resp = await client.post(
            f"/api/v1/agents/{agent['agent_id']}/jobs/{job.id}/result",
            headers=agent["headers"],
            json={
                "total_checked": 0,
                "total_errors": 1,
                "certificates": [],
                "errors": ["template requires manual approval"],
            },
        )
        assert resp.status_code == 200, resp.text

        await seeded_db.refresh(job)
        assert job.status == "failed"
        assert job.error_detail == ["template requires manual approval"]

    async def test_deliver_key_to_central_creates_key_bundle(
        self, client: AsyncClient, admin_headers: dict, seeded_db: AsyncSession
    ):
        agent = await _approve_and_headers(client, admin_headers)
        authority = await _make_adcs_authority(
            seeded_db, agent_id=agent["agent_id"], deliver_key_to_central=True
        )
        await seeded_db.commit()

        job = ScanJob(
            job_type="adcs_issue",
            status="pending",
            triggered_by="manual",
            scope_config={"agent_id": agent["agent_id"], "authority_id": authority.id},
        )
        seeded_db.add(job)
        await seeded_db.commit()

        resp = await client.post(
            f"/api/v1/agents/{agent['agent_id']}/jobs/{job.id}/result",
            headers=agent["headers"],
            json={
                "total_checked": 1,
                "total_new": 1,
                "certificates": [
                    {
                        "common_name": "delivered.corp.internal",
                        "subject": "CN=delivered.corp.internal",
                        "issuer": "CN=CORP-ROOT-CA",
                        "serial_number": "001133",
                        "thumbprint": "dd" * 32,
                        "not_before": "2026-01-01T00:00:00+00:00",
                        "not_after": "2027-01-01T00:00:00+00:00",
                        "sans": ["delivered.corp.internal"],
                        "template": "WebServer",
                        "status": "active",
                        "private_key_pem": "-----BEGIN PRIVATE KEY-----\nFAKE\n-----END PRIVATE KEY-----",
                        "cert_pem": "-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----",
                        "chain_pem": "",
                    }
                ],
            },
        )
        assert resp.status_code == 200, resp.text
        assert "key_bundle_id" in resp.json()["data"]

        cert = (
            await seeded_db.execute(
                select(Certificate).where(Certificate.common_name == "delivered.corp.internal")
            )
        ).scalar_one()
        # Private key material must never land in the Certificate row itself.
        assert "private_key_pem" not in (cert.source_detail or {})
        assert cert.source_detail.get("cert_pem")

        bundle = (
            await seeded_db.execute(
                select(CertificateKeyBundle).where(CertificateKeyBundle.certificate_id == cert.id)
            )
        ).scalar_one()
        assert bundle.encrypted_private_key

    async def test_no_deliver_key_to_central_creates_no_bundle(
        self, client: AsyncClient, admin_headers: dict, seeded_db: AsyncSession
    ):
        agent = await _approve_and_headers(client, admin_headers)
        authority = await _make_adcs_authority(
            seeded_db, agent_id=agent["agent_id"], deliver_key_to_central=False
        )
        await seeded_db.commit()

        job = ScanJob(
            job_type="adcs_issue",
            status="pending",
            triggered_by="manual",
            scope_config={"agent_id": agent["agent_id"], "authority_id": authority.id},
        )
        seeded_db.add(job)
        await seeded_db.commit()

        resp = await client.post(
            f"/api/v1/agents/{agent['agent_id']}/jobs/{job.id}/result",
            headers=agent["headers"],
            json={
                "total_checked": 1,
                "total_new": 1,
                "certificates": [
                    {
                        "common_name": "local-only.corp.internal",
                        "subject": "CN=local-only.corp.internal",
                        "issuer": "CN=CORP-ROOT-CA",
                        "serial_number": "001144",
                        "thumbprint": "ee" * 32,
                        "not_before": "2026-01-01T00:00:00+00:00",
                        "not_after": "2027-01-01T00:00:00+00:00",
                        "sans": ["local-only.corp.internal"],
                        "template": "WebServer",
                        "status": "active",
                        # No private_key_pem — the default, local-only path.
                    }
                ],
            },
        )
        assert resp.status_code == 200, resp.text
        assert "key_bundle_id" not in resp.json()["data"]

        cert = (
            await seeded_db.execute(
                select(Certificate).where(Certificate.common_name == "local-only.corp.internal")
            )
        ).scalar_one()
        bundle_count = (
            await seeded_db.execute(
                select(CertificateKeyBundle).where(CertificateKeyBundle.certificate_id == cert.id)
            )
        ).scalars().all()
        assert bundle_count == []
