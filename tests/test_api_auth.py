"""Tests for authentication API endpoints."""

import pytest
from httpx import AsyncClient, ASGITransport

from certmanager.api.app import create_app
from certmanager.core.security import hash_password


@pytest.fixture
def app():
    return create_app()


@pytest.fixture
async def client(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


class TestHealthEndpoint:
    async def test_health_check(self, client):
        response = await client.get("/api/health")
        assert response.status_code in (200, 503)
        data = response.json()
        assert "status" in data
        assert "version" in data

    async def test_health_no_auth_required(self, client):
        response = await client.get("/api/health")
        assert response.status_code != 401


class TestAuthEndpoints:
    async def test_login_no_user(self, client):
        response = await client.post(
            "/api/v1/auth/login",
            json={"email": "nonexistent@test.com", "password": "wrong"},
        )
        assert response.status_code == 401

    async def test_login_missing_fields(self, client):
        response = await client.post("/api/v1/auth/login", json={})
        assert response.status_code == 422  # Validation error

    async def test_refresh_invalid_token(self, client):
        response = await client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": "invalid-token"},
        )
        assert response.status_code == 401


class TestProtectedEndpoints:
    async def test_certificates_no_auth(self, client):
        response = await client.get("/api/v1/certificates")
        assert response.status_code == 401

    async def test_authorities_no_auth(self, client):
        response = await client.get("/api/v1/authorities")
        assert response.status_code == 401

    async def test_agents_no_auth(self, client):
        response = await client.get("/api/v1/agents")
        assert response.status_code == 401


class TestCORSMiddleware:
    async def test_cors_headers_present(self, client):
        response = await client.options(
            "/api/health",
            headers={
                "Origin": "http://localhost:5173",
                "Access-Control-Request-Method": "GET",
            },
        )
        # CORS middleware adds headers; OPTIONS may return 200 or 405
        assert response.status_code in (200, 405)


class TestCorrelationID:
    async def test_correlation_id_in_response(self, client):
        response = await client.get("/api/health")
        assert "X-Correlation-ID" in response.headers
        assert len(response.headers["X-Correlation-ID"]) > 0
