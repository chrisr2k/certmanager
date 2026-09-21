"""OpenSSL CA scanner tests — synthetic `openssl ca` directory in tmp_path."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from certmanager.agent.scanners.openssl_ca import OpenSSLCAscanner


def _make_cert(
    cn: str,
    issuer_name: x509.Name,
    issuer_key,
    ca: bool = False,
    not_after_delta: timedelta = timedelta(days=365),
    not_before_delta: timedelta = timedelta(days=1),
    eku=None,
) -> tuple[bytes, x509.Name]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.now(UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - not_before_delta)
        .not_valid_after(now + not_after_delta)
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=ca)
    )
    if eku:
        builder = builder.add_extension(x509.ExtendedKeyUsage(eku), critical=False)
    cert = builder.sign(issuer_key, hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.PEM), subject


def _index_date(dt: datetime) -> str:
    return dt.strftime("%y%m%d%H%M%S") + "Z"


def _build_ca_dir(tmp_path: Path) -> Path:
    """Create a synthetic openssl ca dir: root + 3 issued certs."""
    ca_dir = tmp_path / "demoCA"
    newcerts = ca_dir / "newcerts"
    newcerts.mkdir(parents=True)

    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Root CA")])
    root_pem, _ = _make_cert("Test Root CA", root_name, root_key, ca=True)
    (ca_dir / "cacert.pem").write_bytes(root_pem)

    now = datetime.now(UTC)
    entries = []

    # 01 — valid server cert
    pem, _ = _make_cert("web.internal", root_name, root_key, eku=[ExtendedKeyUsageOID.SERVER_AUTH])
    (newcerts / "01.pem").write_bytes(pem)
    entries.append(f"V\t{_index_date(now + timedelta(days=300))}\t\t01\tunknown\t/CN=web.internal")

    # 02 — revoked cert (PEM present, status R)
    pem, _ = _make_cert("old.internal", root_name, root_key)
    (newcerts / "02.pem").write_bytes(pem)
    entries.append(
        f"R\t{_index_date(now + timedelta(days=100))}\t{_index_date(now - timedelta(days=5))}\t02\tunknown\t/CN=old.internal"
    )

    # 03 — expired cert
    pem, _ = _make_cert(
        "gone.internal", root_name, root_key,
        not_after_delta=timedelta(days=-10),
        not_before_delta=timedelta(days=60),
    )
    (newcerts / "03.pem").write_bytes(pem)
    entries.append(
        f"V\t{_index_date(now - timedelta(days=10))}\t\t03\tunknown\t/CN=gone.internal"
    )

    # 04 — index entry whose PEM is missing
    entries.append(f"V\t{_index_date(now + timedelta(days=200))}\t\t04\tunknown\t/CN=missing.internal")

    (ca_dir / "index.txt").write_text("\n".join(entries) + "\n")
    (ca_dir / "serial").write_text("05\n")
    return ca_dir


def test_scan_discovers_all_certificates(tmp_path):
    ca_dir = _build_ca_dir(tmp_path)
    scanner = OpenSSLCAscanner(ca_dir=str(ca_dir), ca_name="test-ca")

    result = asyncio.run(scanner.scan())

    assert result.total_checked == 4
    assert result.total_new == 3
    assert result.total_errors == 1  # missing PEM for serial 04

    by_cn = {c["common_name"]: c for c in result.certificates}
    assert set(by_cn) == {"web.internal", "old.internal", "gone.internal"}

    # Status mapping: valid, revoked, expired (from expiry date, even though V)
    assert by_cn["web.internal"]["status"] == "active"
    assert by_cn["old.internal"]["status"] == "revoked"
    assert by_cn["gone.internal"]["status"] == "expired"

    # Normalized fields
    cert = by_cn["web.internal"]
    assert cert["issuer"] == "CN=Test Root CA"
    assert cert["cert_type"] == "server"
    assert cert["is_ca"] is False
    assert len(cert["thumbprint"]) == 64
    assert cert["source_detail"]["ca_name"] == "test-ca"
    assert cert["source_detail"]["index_serial"] == "01"

    assert result.metadata["ca_dir"] == str(ca_dir)


def test_scan_scope_overrides_configured_dir(tmp_path):
    ca_dir = _build_ca_dir(tmp_path)
    scanner = OpenSSLCAscanner(ca_dir="")  # not configured at agent level

    result = asyncio.run(scanner.scan({"ca_dir": str(ca_dir)}))
    assert result.total_new == 3


def test_scan_missing_ca_dir_returns_error():
    scanner = OpenSSLCAscanner(ca_dir="")
    result = asyncio.run(scanner.scan())
    assert result.total_errors == 1
    assert "not configured" in result.errors[0]


def test_scan_missing_index_returns_error(tmp_path):
    scanner = OpenSSLCAscanner(ca_dir=str(tmp_path))
    result = asyncio.run(scanner.scan())
    assert result.total_errors == 1
    assert "index not found" in result.errors[0]


def test_health_check(tmp_path):
    ca_dir = _build_ca_dir(tmp_path)
    ok = asyncio.run(OpenSSLCAscanner(ca_dir=str(ca_dir)).health_check())
    assert ok.status == "ok"

    missing = asyncio.run(OpenSSLCAscanner(ca_dir="").health_check())
    assert missing.status == "error"


def test_parse_index_date():
    dt = OpenSSLCAscanner._parse_index_date("260912123456Z")
    assert dt == datetime(2026, 9, 12, 12, 34, 56, tzinfo=UTC)
    # Two-digit years >= 50 map to the 1900s (ASN.1 UTCTime rule)
    dt2 = OpenSSLCAscanner._parse_index_date("990101000000Z")
    assert dt2 == datetime(1999, 1, 1, 0, 0, 0, tzinfo=UTC)
    assert OpenSSLCAscanner._parse_index_date("") is None
