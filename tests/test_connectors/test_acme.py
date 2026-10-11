"""ACME connector tests.

The `acme`/`josepy` ACME client is mocked at its own API boundary
(ClientV2's new_order/answer_challenge/poll_and_finalize) rather than
hitting a real ACME server — this exercises CertManager's own
orchestration logic (CSR building, DNS-01 TXT lifecycle, result parsing)
without depending on network access or Let's Encrypt's rate limits.
"""

from __future__ import annotations

import types
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock

import pytest
from acme import challenges
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from certmanager.connectors.acme import ACMEConnector
from certmanager.connectors.base import (
    ConnectorConfigError,
    ConnectorError,
    ConnectorRateLimitError,
    IssueRequest,
)
from certmanager.connectors.factory import ConnectorConfigError as FactoryConfigError
from certmanager.connectors.factory import get_connector
from certmanager.core.models import CertificateAuthority


def _make_self_signed_pem(cn: str) -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=90))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM)


class _FakeDNSProvider:
    def __init__(self):
        self.created: list[tuple[str, str]] = []
        self.deleted: list[tuple[str, str]] = []

    async def create_txt_record(self, domain: str, value: str) -> str:
        self.created.append((domain, value))
        return "record-1"

    async def delete_txt_record(self, domain: str, record_id: str) -> None:
        self.deleted.append((domain, record_id))


def _make_connector(dns_provider=None) -> ACMEConnector:
    return ACMEConnector(
        directory_url="https://acme-staging-v02.api.letsencrypt.org/directory",
        contact_email="admin@example.com",
        domains=["example.com"],
        dns_provider=dns_provider or _FakeDNSProvider(),
        account_key_pem=None,
        account_url=None,
    )


class TestFactoryValidation:
    def test_missing_contact_email_raises(self):
        authority = CertificateAuthority(
            name="Test ACME", ca_type="acme", config={"domains": ["example.com"], "dns_provider_api_token": "x"}
        )
        with pytest.raises(FactoryConfigError, match="contact_email"):
            get_connector(authority)

    def test_missing_domains_raises(self):
        authority = CertificateAuthority(
            name="Test ACME",
            ca_type="acme",
            config={"contact_email": "a@b.com", "dns_provider_api_token": "x"},
        )
        with pytest.raises(FactoryConfigError, match="domains"):
            get_connector(authority)

    def test_missing_dns_token_raises(self):
        authority = CertificateAuthority(
            name="Test ACME",
            ca_type="acme",
            config={"contact_email": "a@b.com", "domains": ["example.com"]},
        )
        with pytest.raises(FactoryConfigError, match="dns_provider_api_token"):
            get_connector(authority)

    def test_valid_config_builds_connector(self):
        authority = CertificateAuthority(
            name="Test ACME",
            ca_type="acme",
            config={
                "contact_email": "a@b.com",
                "domains": ["example.com"],
                "dns_provider_api_token": "tok",
            },
        )
        connector = get_connector(authority)
        assert connector.connector_type == "acme"


class TestCSRBuilding:
    def test_csr_includes_cn_and_sans(self):
        connector = _make_connector()
        private_key, csr_pem = connector._build_csr(
            "www.example.com", ["www.example.com", "example.com"], "RSA-2048"
        )
        csr = x509.load_pem_x509_csr(csr_pem)
        sans = csr.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value.get_values_for_type(x509.DNSName)
        assert "www.example.com" in sans
        assert "example.com" in sans
        assert isinstance(private_key, rsa.RSAPrivateKey)
        assert private_key.key_size == 2048

    def test_csr_ecdsa_key(self):
        connector = _make_connector()
        private_key, _ = connector._build_csr("example.com", ["example.com"], "ECDSA-P256")
        from cryptography.hazmat.primitives.asymmetric import ec

        assert isinstance(private_key, ec.EllipticCurvePrivateKey)

    def test_csr_rsa_4096(self):
        connector = _make_connector()
        private_key, _ = connector._build_csr("example.com", ["example.com"], "RSA-4096")
        assert private_key.key_size == 4096


class TestParseX509AndRenewRevokeSourceId:
    def test_parse_x509_extracts_fields(self):
        pem = _make_self_signed_pem("leaf.example.com")
        cert = x509.load_pem_x509_certificate(pem)
        record = ACMEConnector._parse_x509(cert, "server", {"cert_pem": pem.decode()})
        assert record.common_name == "leaf.example.com"
        assert record.key_algorithm == "RSA-2048"
        assert record.is_wildcard is False
        assert len(record.thumbprint_sha256) == 64

    async def test_renew_certificate_parses_domains_from_pem(self, monkeypatch):
        connector = _make_connector()
        pem = _make_self_signed_pem("renew-me.example.com").decode()

        captured = {}

        async def fake_issue(request: IssueRequest):
            captured["request"] = request
            return MagicMock()

        monkeypatch.setattr(connector, "issue_certificate", fake_issue)
        await connector.renew_certificate(pem)

        assert captured["request"].common_name == "renew-me.example.com"
        assert "renew-me.example.com" in captured["request"].sans

    async def test_renew_certificate_invalid_pem_raises_config_error(self):
        connector = _make_connector()
        with pytest.raises(ConnectorConfigError):
            await connector.renew_certificate("not a pem")

    async def test_get_certificate_not_supported(self):
        connector = _make_connector()
        with pytest.raises(Exception, match="not support"):
            await connector.get_certificate("anything")


class TestMapAcmeError:
    def test_rate_limited_maps_to_rate_limit_error(self):
        err = ACMEConnector._map_acme_error(Exception("urn:ietf:params:acme:error:rateLimited: too many"))
        assert isinstance(err, ConnectorRateLimitError)

    def test_unauthorized_maps_to_auth_error(self):
        from certmanager.connectors.base import ConnectorAuthError

        err = ACMEConnector._map_acme_error(Exception("401 unauthorized"))
        assert isinstance(err, ConnectorAuthError)

    def test_generic_error_maps_to_connector_error(self):
        from certmanager.connectors.base import ConnectorError

        err = ACMEConnector._map_acme_error(Exception("something else broke"))
        assert isinstance(err, ConnectorError)


class TestIssueCertificateHappyPath:
    async def test_issue_certificate_full_flow(self, monkeypatch):
        dns_provider = _FakeDNSProvider()
        connector = _make_connector(dns_provider=dns_provider)

        leaf_key_cn = "www.example.com"
        leaf_pem = _make_self_signed_pem(leaf_key_cn)
        chain_pem = _make_self_signed_pem("Fake Intermediate CA")
        fullchain_pem = (leaf_pem + chain_pem).decode()

        fake_account_key = MagicMock()
        fake_acme_client = MagicMock()

        # Build a fake order with one authorization carrying a real DNS01
        # challenge instance (isinstance checks need the real type).
        dns01 = MagicMock(spec=challenges.DNS01)
        dns01.response_and_validation.return_value = (MagicMock(), "txt-validation-value")
        challb = types.SimpleNamespace(chall=dns01)
        authzr = types.SimpleNamespace(
            body=types.SimpleNamespace(
                identifier=types.SimpleNamespace(value="www.example.com"),
                challenges=[challb],
            )
        )
        order = types.SimpleNamespace(authorizations=[authzr], uri="https://acme.test/order/1")
        finalized = types.SimpleNamespace(fullchain_pem=fullchain_pem)

        fake_acme_client.new_order.return_value = order
        fake_acme_client.poll_and_finalize.return_value = finalized

        monkeypatch.setattr(
            connector, "_build_client", lambda: (fake_account_key, fake_acme_client)
        )
        monkeypatch.setattr(
            ACMEConnector, "_wait_for_dns_propagation", AsyncMock(return_value=True)
        )

        result = await connector.issue_certificate(
            IssueRequest(common_name=leaf_key_cn, sans=[], key_algorithm="RSA-2048")
        )

        assert result.certificate.common_name == leaf_key_cn
        assert result.private_key_pem is not None
        assert "BEGIN PRIVATE KEY" in result.private_key_pem
        assert result.certificate.source_detail["acme_order_url"] == "https://acme.test/order/1"

        # TXT record created then always cleaned up
        assert dns_provider.created == [("www.example.com", "txt-validation-value")]
        assert dns_provider.deleted == [("www.example.com", "record-1")]

        fake_acme_client.answer_challenge.assert_called_once()

    async def test_issue_certificate_cleans_up_txt_on_failure(self, monkeypatch):
        dns_provider = _FakeDNSProvider()
        connector = _make_connector(dns_provider=dns_provider)

        fake_account_key = MagicMock()
        fake_acme_client = MagicMock()

        dns01 = MagicMock(spec=challenges.DNS01)
        dns01.response_and_validation.return_value = (MagicMock(), "txt-validation-value")
        challb = types.SimpleNamespace(chall=dns01)
        authzr = types.SimpleNamespace(
            body=types.SimpleNamespace(
                identifier=types.SimpleNamespace(value="fails.example.com"),
                challenges=[challb],
            )
        )
        order = types.SimpleNamespace(authorizations=[authzr], uri="https://acme.test/order/2")
        fake_acme_client.new_order.return_value = order
        fake_acme_client.poll_and_finalize.side_effect = Exception("authorization failed: timeout")

        monkeypatch.setattr(connector, "_build_client", lambda: (fake_account_key, fake_acme_client))
        monkeypatch.setattr(ACMEConnector, "_wait_for_dns_propagation", AsyncMock(return_value=True))

        with pytest.raises(ConnectorError):
            await connector.issue_certificate(IssueRequest(common_name="fails.example.com"))

        # Cleanup must still happen even though the order failed.
        assert dns_provider.deleted == [("fails.example.com", "record-1")]
