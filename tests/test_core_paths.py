"""Regression tests for the core data path + API contract fixes.

- CertificateService.upsert_from_discovery no longer crashes on missing
  validity_days (the AttributeError that broke all discovery).
- Alert rule create/update take body models (frontend contract).
- Rate limiter: Redis verdicts are final; in-memory fallback bounded.
- Audit redaction of sensitive query params.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from certmanager.connectors.base import CertificateRecord
from certmanager.core.models import Certificate
from certmanager.services.certificate_service import CertificateService


def _record(common_name: str, validity_days: int | None = None) -> CertificateRecord:
    now = datetime.now(UTC)
    return CertificateRecord(
        common_name=common_name,
        subject=f"CN={common_name}",
        issuer="CN=Test CA",
        serial_number=f"SERIAL-{common_name}",
        thumbprint_sha256=common_name[:64].ljust(64, "0"),
        not_before=now - timedelta(days=10),
        not_after=now + timedelta(days=355),
        validity_days=validity_days,
        source_detail={"test": True},
        source_id=common_name,
    )


class TestCertificateService:
    async def test_upsert_with_explicit_validity_days(self, db_session: AsyncSession):
        service = CertificateService(db_session)
        stats = await service.upsert_from_discovery(
            records=[_record("a.test", validity_days=365)],
            source_ca_id=None,
            source_type="tls_scan",
            datacenter_id=None,
            scan_job_id="job-1",
        )
        await db_session.commit()
        assert stats["new"] == 1
        assert stats["errors"] == 0

        cert = (
            await db_session.execute(select(Certificate).where(Certificate.common_name == "a.test"))
        ).scalar_one()
        assert cert.validity_days == 365

    async def test_upsert_without_validity_days_falls_back_to_computed(
        self, db_session: AsyncSession
    ):
        """The review-era AttributeError: records without validity_days must
        compute it from not_before/not_after instead of crashing."""
        service = CertificateService(db_session)
        stats = await service.upsert_from_discovery(
            records=[_record("b.test", validity_days=None)],
            source_ca_id=None,
            source_type="tls_scan",
            datacenter_id=None,
            scan_job_id="job-2",
        )
        await db_session.commit()
        assert stats["new"] == 1
        assert stats["errors"] == 0

        cert = (
            await db_session.execute(select(Certificate).where(Certificate.common_name == "b.test"))
        ).scalar_one()
        assert cert.validity_days == 365  # 355 + 10 days

    async def test_upsert_updates_existing_by_thumbprint(self, db_session: AsyncSession):
        service = CertificateService(db_session)
        await service.upsert_from_discovery(
            records=[_record("c.test")],
            source_ca_id=None,
            source_type="tls_scan",
            datacenter_id=None,
            scan_job_id="job-3",
        )
        await db_session.commit()

        stats = await service.upsert_from_discovery(
            records=[_record("c.test")],
            source_ca_id=None,
            source_type="tls_scan",
            datacenter_id=None,
            scan_job_id="job-4",
        )
        await db_session.commit()
        assert stats["unchanged"] == 1 or stats["updated"] == 1
        assert stats["new"] == 0


class TestAlertRuleContract:
    async def test_create_rule_with_body(self, client: AsyncClient, admin_headers: dict):
        resp = await client.post(
            "/api/v1/alerts/rules",
            headers=admin_headers,
            json={
                "name": "Expiry warning",
                "description": "Warn when certs expire soon",
                "condition_type": "expiry_days",
                "condition_config": {"days": 14},
                "severity": "warning",
                "cooldown_minutes": 60,
                "is_enabled": True,
            },
        )
        assert resp.status_code == 201, resp.text
        rule_id = resp.json()["data"]["id"]

        # Update via PATCH body (frontend edit flow)
        resp = await client.patch(
            f"/api/v1/alerts/rules/{rule_id}",
            headers=admin_headers,
            json={"is_enabled": False, "severity": "critical"},
        )
        assert resp.status_code == 200, resp.text

        listing = await client.get("/api/v1/alerts/rules", headers=admin_headers)
        rules = {r["name"]: r for r in listing.json()["data"]}
        assert rules["Expiry warning"]["is_enabled"] is False
        assert rules["Expiry warning"]["severity"] == "critical"

    async def test_create_channel_with_body(self, client: AsyncClient, admin_headers: dict):
        resp = await client.post(
            "/api/v1/alerts/channels",
            headers=admin_headers,
            json={
                "name": "Ops email",
                "channel_type": "email",
                "config": {"to": ["ops@example.com"]},
            },
        )
        assert resp.status_code == 201, resp.text


class TestRateLimiter:
    def test_in_memory_limit_enforced(self):
        from certmanager.api.middleware.rate_limit import RateLimitMiddleware

        async def _app(scope, receive, send):
            pass

        middleware = RateLimitMiddleware(_app)
        # 3 allowed, then blocked (window 60s)
        for _i in range(3):
            assert middleware._check_in_memory("client-1", "auth", 3, 60) is True
        assert middleware._check_in_memory("client-1", "auth", 3, 60) is False
        # Different client unaffected
        assert middleware._check_in_memory("client-2", "auth", 3, 60) is True

    def test_category_mapping_is_segment_aware(self):
        from certmanager.api.middleware.rate_limit import _get_category

        assert _get_category("/api/v1/auth/login", "POST") == "auth"
        assert _get_category("/api/v1/authorities", "POST") == "write"
        assert _get_category("/api/v1/certificates", "GET") == "read"
        assert _get_category("/api/v1/agents/abc/heartbeat", "POST") == "agent"


class TestAuditRedaction:
    def test_sensitive_query_params_redacted(self):
        from certmanager.api.middleware.audit import _redacted_query_string

        class FakeRequest:
            class _QP:
                def multi_items(self):
                    return [("page", "1"), ("psk", "hunter2"), ("token", "abc123")]

            query_params = _QP()

        result = _redacted_query_string(FakeRequest())  # type: ignore[arg-type]
        assert "psk=[REDACTED]" in result
        assert "token=[REDACTED]" in result
        assert "hunter2" not in result
        assert "abc123" not in result
        assert "page=1" in result


class TestConfigEnvelope:
    async def test_health_endpoint(self, client: AsyncClient):
        resp = await client.get("/api/health")
        assert resp.status_code == 200
        assert resp.json()["status"] in ("healthy", "degraded")
