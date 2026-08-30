"""Agent connector listener tests: auth, discovery, 501 lifecycle ops."""

from __future__ import annotations

import pytest_asyncio
from aiohttp.test_utils import TestClient, TestServer

from certmanager.agent.listener import AgentListener
from certmanager.agent.scanners.base import HealthStatus, ScannerPlugin, ScanResult


class StubADCSScanner(ScannerPlugin):
    name = "adcs"

    async def scan(self, scope: dict | None = None) -> ScanResult:
        return ScanResult(
            scanner_name="adcs",
            total_checked=1,
            total_new=1,
            certificates=[
                {
                    "common_name": "svc.test",
                    "subject": "CN=svc.test",
                    "issuer": "CN=TestCA",
                    "serial_number": "1234",
                    "thumbprint": "ab" * 32,
                    "not_before": "2026-01-01T00:00:00",
                    "not_after": "2027-01-01T00:00:00",
                }
            ],
        )

    async def health_check(self) -> HealthStatus:
        return HealthStatus(status="ok", message="AD CS reachable")


class FakeSettings:
    listener_ssl_cert = None
    listener_ssl_key = None
    listener_ssl_ca = None
    listener_host = "127.0.0.1"
    listener_port = 0  # ephemeral


@pytest_asyncio.fixture
async def listener_app():
    listener = AgentListener(
        settings=FakeSettings(), scanners=[StubADCSScanner()], agent_token="test-agent-token"
    )
    app = listener._build_app()
    yield app


@pytest_asyncio.fixture
async def client(listener_app):
    async with TestServer(listener_app) as server:
        async with TestClient(server) as ac:
            yield ac


AUTH = {"Authorization": "Bearer test-agent-token"}


class TestListenerAuth:
    async def test_health_without_token_rejected(self, client: TestClient):
        resp = await client.post("/health")
        assert resp.status == 401

    async def test_health_with_wrong_token_rejected(self, client: TestClient):
        resp = await client.post("/health", headers={"Authorization": "Bearer wrong"})
        assert resp.status == 401

    async def test_health_with_valid_token(self, client: TestClient):
        resp = await client.post("/health", headers=AUTH)
        assert resp.status == 200
        body = await resp.json()
        assert body["status"] == "ok"
        assert body["adcs_status"] == "ok"


class TestListenerDiscovery:
    async def test_discover_requires_auth(self, client: TestClient):
        resp = await client.post("/scanners/adcs/discover")
        assert resp.status == 401

    async def test_discover_returns_certificates(self, client: TestClient):
        resp = await client.post("/scanners/adcs/discover", headers=AUTH, json={"scope": {}})
        assert resp.status == 200
        body = await resp.json()
        assert body["status"] == "ok"
        assert len(body["certificates"]) == 1
        assert body["certificates"][0]["common_name"] == "svc.test"


class TestListenerLifecycleOps:
    async def test_issue_returns_501_not_supported(self, client: TestClient):
        resp = await client.post("/scanners/adcs/issue", headers=AUTH, json={})
        assert resp.status == 501
        body = await resp.json()
        assert body["status"] == "not_supported"

    async def test_renew_returns_501(self, client: TestClient):
        resp = await client.post("/scanners/adcs/certificates/abc/renew", headers=AUTH)
        assert resp.status == 501
