"""Scan trigger endpoint tests — agent-executed vs worker-dispatched jobs."""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from certmanager.core.models import Agent, ScanJob


async def test_openssl_ca_scan_requires_agent_id(client: AsyncClient, admin_headers: dict):
    resp = await client.post(
        "/api/v1/scans",
        headers=admin_headers,
        json={"job_type": "openssl_ca_scan"},
    )
    assert resp.status_code == 422


async def test_openssl_ca_scan_creates_agent_scoped_job(
    client: AsyncClient, admin_headers: dict, seeded_db: AsyncSession
):
    resp = await client.post(
        "/api/v1/scans",
        headers=admin_headers,
        json={
            "job_type": "openssl_ca_scan",
            "agent_id": "11111111-1111-4111-8111-111111111111",
        },
    )
    assert resp.status_code == 201, resp.text
    job_id = resp.json()["data"]["scan_job_id"]

    result = await seeded_db.execute(select(ScanJob).where(ScanJob.id == job_id))
    job = result.scalar_one()
    # Agent-executed jobs must stay pending for the agent to poll — the
    # Celery worker must not consume them.
    assert job.status == "pending"
    assert job.scope_config["agent_id"] == "11111111-1111-4111-8111-111111111111"


async def test_tls_scan_still_gets_targets(
    client: AsyncClient, admin_headers: dict, seeded_db: AsyncSession
):
    seeded_db.add(
        Agent(
            id="22222222-2222-4222-8222-222222222222",
            name="tls-test",
            agent_type="tls_scanner",
            auth_token_hash="test-hash",
            is_approved=True,
            config={"tls_cidr_ranges": ["10.0.0.0/24"], "tls_ports": [443]},
        )
    )
    await seeded_db.commit()

    resp = await client.post(
        "/api/v1/scans",
        headers=admin_headers,
        json={"job_type": "tls_scan", "agent_id": "22222222-2222-4222-8222-222222222222"},
    )
    assert resp.status_code == 201, resp.text
    job_id = resp.json()["data"]["scan_job_id"]

    result = await seeded_db.execute(select(ScanJob).where(ScanJob.id == job_id))
    job = result.scalar_one()
    assert job.status == "pending"
    assert job.scope_config["cidr_ranges"] == ["10.0.0.0/24"]
    assert job.scope_config["ports"] == [443]


async def test_full_discovery_still_worker_dispatched(
    client: AsyncClient, admin_headers: dict, seeded_db: AsyncSession
):
    resp = await client.post(
        "/api/v1/scans", headers=admin_headers, json={"job_type": "full_discovery"}
    )
    assert resp.status_code == 201, resp.text
    job_id = resp.json()["data"]["scan_job_id"]

    result = await seeded_db.execute(select(ScanJob).where(ScanJob.id == job_id))
    job = result.scalar_one()
    assert job.job_type == "full_discovery"
