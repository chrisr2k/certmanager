"""TLS scanner regression tests.

Both bugs were found against a real device (an HP ENVY 5530 printer):
1. Embedded devices negotiate old ciphers that OpenSSL security levels
   refuse — the scanner context must allow legacy TLS.
2. Certificates with an ExtendedKeyUsage extension crashed the parser
   (iterating the Extension object instead of Extension.value).
"""

from __future__ import annotations

import ssl
from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from certmanager.agent.scanners.tls_scanner import (
    TLSScanner,
    _build_scan_ssl_context,
)


class TestScanSSLContext:
    def test_context_allows_legacy_tls_versions(self):
        ctx = _build_scan_ssl_context()
        assert ctx.verify_mode == ssl.CERT_NONE
        assert ctx.check_hostname is False
        # Legacy devices (printers/IoT) may only speak TLS 1.0/1.1
        assert ctx.minimum_version == ssl.TLSVersion.TLSv1

    def test_context_ciphers_permissive(self):
        ctx = _build_scan_ssl_context()
        # An embedded-device cipher: AES256-SHA. It must be offered —
        # default OpenSSL security levels silently drop it.
        ciphers = ctx.get_ciphers()
        names = {c["name"] for c in ciphers}
        assert any("SHA" in name for name in names), names


class TestParseCertificate:
    def _make_cert(self) -> bytes:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, "device.internal")]
        )
        now = datetime.now(UTC)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=365))
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName("device.internal")]),
                critical=False,
            )
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
                critical=False,
            )
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(key, hashes.SHA256())
        )
        return cert.public_bytes(serialization.Encoding.DER)

    def test_parse_cert_with_eku_extension(self):
        """Regression: certs WITH ExtendedKeyUsage crashed the parser
        ('Extension' object is not iterable)."""
        der = self._make_cert()
        scanner = TLSScanner()
        result = scanner._parse_certificate(der, host="192.168.0.11", port=443)

        assert result["common_name"] == "device.internal"
        assert result["cert_type"] == "server"
        assert result["sans"] == ["device.internal"]
        assert result["status"] == "active"
        assert result["thumbprint"]
