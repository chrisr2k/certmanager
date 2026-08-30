"""Tests for CA connector implementations."""

import pytest
from datetime import datetime, timezone

from certmanager.connectors.base import (
    CAHealthStatus,
    CAHealthResult,
    CertificateRecord,
    IssueRequest,
    IssueResult,
    ConnectorError,
)
from certmanager.connectors.factory import get_connector, CredentialStore
from certmanager.connectors.adcs import ADCSConnector


class TestCertificateRecord:
    def test_default_values(self):
        record = CertificateRecord(
            common_name="test.example.com",
            subject="CN=test.example.com",
            issuer="CN=Test CA",
            serial_number="01AB",
            thumbprint_sha256="abc123",
            not_before=datetime(2026, 1, 1, tzinfo=timezone.utc),
            not_after=datetime(2027, 1, 1, tzinfo=timezone.utc),
        )
        assert record.cert_type == "unknown"
        assert record.status == "active"
        assert record.sans == []
        assert record.is_wildcard is False

    def test_with_all_fields(self):
        record = CertificateRecord(
            common_name="*.example.com",
            subject="CN=*.example.com",
            issuer="CN=Enterprise CA, DC=corp",
            serial_number="FF02",
            thumbprint_sha256="def456",
            not_before=datetime(2026, 1, 1, tzinfo=timezone.utc),
            not_after=datetime(2027, 1, 1, tzinfo=timezone.utc),
            key_algorithm="RSA-2048",
            signature_algorithm="sha256WithRSAEncryption",
            sans=["example.com", "*.example.com", "api.example.com"],
            cert_type="server",
            is_wildcard=True,
            source_detail={"aws_arn": "arn:aws:acm:..."},
            source_id="arn:aws:acm:us-east-1:123:certificate/abc",
        )
        assert record.key_algorithm == "RSA-2048"
        assert len(record.sans) == 3
        assert record.is_wildcard is True
        assert record.source_id.startswith("arn:")


class TestIssueRequest:
    def test_default_values(self):
        req = IssueRequest(common_name="test.example.com")
        assert req.key_algorithm == "RSA-2048"
        assert req.validity_days == 365
        assert req.cert_type == "server"
        assert req.sans == []

    def test_custom_values(self):
        req = IssueRequest(
            common_name="api.example.com",
            sans=["api.example.com", "api2.example.com"],
            key_algorithm="ECDSA-P256",
            validity_days=90,
            cert_type="client",
        )
        assert req.validity_days == 90
        assert req.cert_type == "client"
        assert len(req.sans) == 2


class TestCAHealthResult:
    def test_healthy(self):
        result = CAHealthResult(
            status=CAHealthStatus.HEALTHY,
            message="CA is reachable",
            latency_ms=45.2,
        )
        assert result.status == CAHealthStatus.HEALTHY
        assert result.latency_ms == 45.2

    def test_unhealthy(self):
        result = CAHealthResult(
            status=CAHealthStatus.UNHEALTHY,
            message="Connection refused",
            latency_ms=0,
            detail={"error": "ConnectionError"},
        )
        assert result.status == CAHealthStatus.UNHEALTHY
        assert "error" in result.detail


class TestIssueResult:
    def test_private_key_returned(self):
        cert = CertificateRecord(
            common_name="test.example.com",
            subject="CN=test.example.com",
            issuer="CN=Test CA",
            serial_number="01",
            thumbprint_sha256="abc",
            not_before=datetime(2026, 1, 1, tzinfo=timezone.utc),
            not_after=datetime(2027, 1, 1, tzinfo=timezone.utc),
        )
        result = IssueResult(
            certificate=cert,
            private_key_pem="-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----",
        )
        assert result.private_key_pem is not None
        assert "BEGIN PRIVATE KEY" in result.private_key_pem
        # Key is never stored — it's the caller's responsibility


class TestConnectorFactoryErrors:
    def test_unknown_ca_type_raises(self):
        from certmanager.core.models import CertificateAuthority

        ca = CertificateAuthority(
            name="Test CA",
            ca_type="unknown_type",
            config={},
        )
        with pytest.raises(ConnectorError, match="Unknown CA type"):
            get_connector(ca)

    def test_aws_missing_account_id_raises(self):
        from certmanager.core.models import CertificateAuthority

        ca = CertificateAuthority(
            name="AWS CA",
            ca_type="aws_acm",
            config={"regions": ["us-east-1"]},  # Missing account_id
        )
        with pytest.raises(ConnectorError, match="account_id"):
            get_connector(ca)

    def test_azure_missing_vault_url_raises(self):
        from certmanager.core.models import CertificateAuthority

        ca = CertificateAuthority(
            name="Azure CA",
            ca_type="azure_keyvault",
            config={},  # Missing vault_url
        )
        with pytest.raises(ConnectorError, match="vault_url"):
            get_connector(ca)


class TestCredentialStore:
    def test_get_nonexistent(self):
        store = CredentialStore()
        assert store.get("nonexistent") is None

    def test_set_and_get(self):
        store = CredentialStore()
        store.set("my-key", {"secret": "value"})
        assert store.get("my-key") == {"secret": "value"}
