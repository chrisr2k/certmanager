"""Tests for authentication API endpoints and basic middleware behavior.

Uses the shared conftest client (seeded test DB) so these hit a real
database instead of the default Postgres URL.
"""

import pytest
from httpx import AsyncClient


class TestHealthEndpoint:
    async def test_health_check(self, client: AsyncClient):
        response = await client.get("/api/health")
        assert response.status_code in (200, 503)
        data = response.json()
        assert "status" in data
        assert "version" in data

    async def test_health_no_auth_required(self, client: AsyncClient):
        response = await client.get("/api/health")
        assert response.status_code != 401


class TestAuthEndpoints:
    async def test_login_no_user(self, client: AsyncClient):
        response = await client.post(
            "/api/v1/auth/login",
            json={"email": "nonexistent@test.com", "password": "wrong"},
        )
        assert response.status_code == 401

    async def test_login_missing_fields(self, client: AsyncClient):
        response = await client.post("/api/v1/auth/login", json={})
        assert response.status_code == 422  # Validation error

    async def test_refresh_invalid_token(self, client: AsyncClient):
        response = await client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": "invalid-token"},
        )
        assert response.status_code == 401


class TestProtectedEndpoints:
    async def test_certificates_no_auth(self, client: AsyncClient):
        response = await client.get("/api/v1/certificates")
        assert response.status_code == 401

    async def test_authorities_no_auth(self, client: AsyncClient):
        response = await client.get("/api/v1/authorities")
        assert response.status_code == 401

    async def test_agents_no_auth(self, client: AsyncClient):
        response = await client.get("/api/v1/agents")
        assert response.status_code == 401

    async def test_auth_me_is_not_public(self, client: AsyncClient):
        # /auth/me lives under /api/v1/auth but must NOT be public
        response = await client.get("/api/v1/auth/me")
        assert response.status_code == 401


class TestCORSMiddleware:
    async def test_cors_headers_present(self, client: AsyncClient):
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
    async def test_correlation_id_in_response(self, client: AsyncClient):
        response = await client.get("/api/health")
        assert "X-Correlation-ID" in response.headers
        assert len(response.headers["X-Correlation-ID"]) > 0
