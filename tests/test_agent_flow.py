"""End-to-end agent flow tests: registration, auth lifecycle, job execution.

Covers the critical agent bugs found in review:
- registration protocol (JSON body + PSK)
- idempotent re-registration (no 15-minute JWT death spiral)
- ownership + approval enforcement (no cross-agent IDOR)
- result persistence into the certificate inventory
"""

from __future__ import annotations

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from certmanager.core.models import Agent, Certificate, ScanJob

AGENT_NAME = "dc1-agent-01"


async def _register(client: AsyncClient, psk: str = "test-agent-psk") -> dict:
    resp = await client.post(
        "/api/v1/agents/register",
        json={
            "name": AGENT_NAME,
            "agent_type": "adcs",
            "datacenter_code": "tstdc",
            "hostname": "dc1-agent",
            "psk": psk,
        },
    )
    return resp


class TestAgentRegistration:
    async def test_register_with_valid_psk(self, client: AsyncClient, seeded_db: AsyncSession):
        resp = await _register(client)
        assert resp.status_code == 201, resp.text
        data = resp.json()["data"]
        assert data["agent_id"]
        assert data["api_token"]
        assert data["agent_token"], "permanent agent_token returned on first registration"
        assert data["status"] == "unapproved"

    async def test_register_with_wrong_psk(self, client: AsyncClient):
        resp = await _register(client, psk="wrong-psk")
        assert resp.status_code == 400
        assert "pre-shared key" in resp.json()["message"].lower()

    async def test_register_missing_psk(self, client: AsyncClient):
        resp = await _register(client, psk=None)
        assert resp.status_code == 400 or resp.status_code == 422

    async def test_reregistration_is_idempotent(self, client: AsyncClient, seeded_db: AsyncSession):
        first = await _register(client)
        assert first.status_code == 201
        first_id = first.json()["data"]["agent_id"]
        first_token = first.json()["data"]["api_token"]

        # Re-register (e.g. agent restarted after JWT expiry)
        second = await _register(client)
        assert second.status_code == 201
        second_data = second.json()["data"]
        assert second_data["agent_id"] == first_id, "same agent reused"
        assert second_data["api_token"] != first_token, "fresh JWT issued"
        assert "agent_token" not in second_data, "permanent token only returned once"

        # Still exactly one agent row
        result = await seeded_db.execute(select(Agent).where(Agent.name == AGENT_NAME))
        agents = result.scalars().all()
        assert len(agents) == 1


class TestAgentAuthEnforcement:
    @pytest.fixture
    async def registered(self, client: AsyncClient) -> dict:
        resp = await _register(client)
        assert resp.status_code == 201
        return resp.json()["data"]

    @pytest.fixture
    async def agent_headers(self, registered: dict) -> dict:
        return {"Authorization": f"Bearer {registered['api_token']}"}

    async def test_heartbeat_works_before_approval(
        self, client: AsyncClient, registered: dict, agent_headers: dict
    ):
        resp = await client.post(
            f"/api/v1/agents/{registered['agent_id']}/heartbeat", headers=agent_headers
        )
        assert resp.status_code == 200
        assert resp.json()["data"]["status"] == "unapproved"

    async def test_unapproved_agent_cannot_fetch_jobs(
        self, client: AsyncClient, registered: dict, agent_headers: dict
    ):
        resp = await client.get(
            f"/api/v1/agents/{registered['agent_id']}/jobs", headers=agent_headers
        )
        assert resp.status_code == 403

    async def test_agent_cannot_use_another_agents_token(
        self, client: AsyncClient, registered: dict, agent_headers: dict
    ):
        # Second agent
        resp2 = await client.post(
            "/api/v1/agents/register",
            json={
                "name": "dc1-agent-02",
                "agent_type": "adcs",
                "datacenter_code": "tstdc",
                "psk": "test-agent-psk",
            },
        )
        other = resp2.json()["data"]
        other_headers = {"Authorization": f"Bearer {other['api_token']}"}

        # Agent 2 heartbeat against agent 1's ID → forbidden (IDOR fix)
        resp = await client.post(
            f"/api/v1/agents/{registered['agent_id']}/heartbeat", headers=other_headers
        )
        assert resp.status_code == 403

    async def test_submit_result_rejected_for_unapproved_agent(
        self, client: AsyncClient, seeded_db: AsyncSession, registered: dict, agent_headers: dict
    ):
        job = ScanJob(
            job_type="tls_scan",
            status="pending",
            triggered_by="manual",
            scope_config={"agent_id": registered["agent_id"]},
        )
        seeded_db.add(job)
        await seeded_db.commit()

        resp = await client.post(
            f"/api/v1/agents/{registered['agent_id']}/jobs/{job.id}/result",
            headers=agent_headers,
            json={"total_checked": 1, "certificates": []},
        )
        assert resp.status_code == 403

    async def test_submit_result_rejected_for_other_agents_job(
        self, client: AsyncClient, seeded_db: AsyncSession, registered: dict, agent_headers: dict,
        admin_headers: dict,
    ):
        # Approve agent 1
        resp = await client.patch(
            f"/api/v1/agents/{registered['agent_id']}/approve", headers=admin_headers
        )
        assert resp.status_code == 200

        # A job assigned to a DIFFERENT agent
        job = ScanJob(
            job_type="tls_scan",
            status="pending",
            triggered_by="manual",
            scope_config={"agent_id": "someone-else"},
        )
        seeded_db.add(job)
        await seeded_db.commit()

        resp = await client.post(
            f"/api/v1/agents/{registered['agent_id']}/jobs/{job.id}/result",
            headers=agent_headers,
            json={"total_checked": 1, "certificates": []},
        )
        assert resp.status_code == 403, "agent cannot submit results for another agent's job"


class TestAgentJobPersistence:
    async def test_approved_agent_result_persists_certificates(
        self, client: AsyncClient, seeded_db: AsyncSession, admin_headers: dict
    ):
        # Register + approve
        reg = await _register(client)
        assert reg.status_code == 201
        data = reg.json()["data"]
        await client.patch(f"/api/v1/agents/{data['agent_id']}/approve", headers=admin_headers)

        agent_headers = {"Authorization": f"Bearer {data['api_token']}"}

        # Create a TLS scan job for this agent
        job = ScanJob(
            job_type="tls_scan",
            status="pending",
            triggered_by="manual",
            scope_config={"agent_id": data["agent_id"], "cidr_ranges": ["10.0.0.0/24"]},
        )
        seeded_db.add(job)
        await seeded_db.commit()

        # Agent polls for jobs
        resp = await client.get(f"/api/v1/agents/{data['agent_id']}/jobs", headers=agent_headers)
        assert resp.status_code == 200
        jobs = resp.json()["data"]["jobs"]
        assert len(jobs) == 1
        assert jobs[0]["id"] == job.id

        # Agent submits a result with one certificate
        resp = await client.post(
            f"/api/v1/agents/{data['agent_id']}/jobs/{job.id}/result",
            headers=agent_headers,
            json={
                "total_checked": 1,
                "total_new": 1,
                "total_updated": 0,
                "total_errors": 0,
                "certificates": [
                    {
                        "common_name": "svc.internal.test",
                        "subject": "CN=svc.internal.test",
                        "issuer": "CN=Test CA",
                        "serial_number": "00AABB",
                        "thumbprint": "ab" * 32,
                        "not_before": "2026-01-01T00:00:00",
                        "not_after": "2027-01-01T00:00:00",
                        "key_algorithm": "RSA-2048",
                        "sans": ["svc.internal.test"],
                        "cert_type": "server",
                        "status": "active",
                    }
                ],
            },
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()["data"]
        assert body["certificates_received"] == 1
        assert body["persisted"]["new"] == 1, "certificate actually persisted"

        # Verify the certificate is in the inventory
        result = await seeded_db.execute(
            select(Certificate).where(Certificate.common_name == "svc.internal.test")
        )
        cert = result.scalar_one_or_none()
        assert cert is not None
        assert cert.validity_days == 365
        assert cert.source_type == "tls_scan"

        # Job marked complete
        result = await seeded_db.execute(select(ScanJob).where(ScanJob.id == job.id))
        stored_job = result.scalar_one()
        assert stored_job.status == "completed"
        assert stored_job.total_new == 1
