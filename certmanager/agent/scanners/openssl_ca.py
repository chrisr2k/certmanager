"""OpenSSL CA scanner — reads a plain `openssl ca` PKI directory.

Discovers every certificate the CA has issued from its database files:
- index.txt        — one line per cert: status (V/R/E), expiry, serial, DN
- newcerts/<serial>.pem — the issued certificate PEMs
- serial           — next serial (informational)

The agent must run on the CA host (or somewhere with read access to the
CA directory). No CA-side software changes required — the database is
just files.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime
from pathlib import Path

import structlog
from cryptography import x509
from cryptography.hazmat.primitives import hashes

from certmanager.agent.scanners.base import HealthStatus, ScanResult, ScannerPlugin

logger = structlog.get_logger()

_STATUS_MAP = {"V": "active", "R": "revoked", "E": "expired"}


class OpenSSLCAscanner(ScannerPlugin):
    """Scanner plugin for a plain `openssl ca` certificate authority."""

    name = "openssl_ca"

    def __init__(self, ca_dir: str = "", ca_name: str = ""):
        self.ca_dir = ca_dir
        self.ca_name = ca_name

    # ------------------------------------------------------------------
    # ScannerPlugin interface
    # ------------------------------------------------------------------
    async def scan(self, scope: dict | None = None) -> ScanResult:
        """Parse the CA database and report every issued certificate."""
        start = time.monotonic()
        scope = scope or {}
        ca_dir = scope.get("ca_dir") or self.ca_dir

        if not ca_dir:
            return ScanResult(
                scanner_name=self.name,
                total_errors=1,
                errors=["openssl_ca_dir not configured — set it in agent_config.json or job scope"],
                duration_ms=0.0,
            )

        ca_path = Path(ca_dir)
        index_path = ca_path / "index.txt"
        newcerts = ca_path / "newcerts"

        if not index_path.is_file():
            return ScanResult(
                scanner_name=self.name,
                total_errors=1,
                errors=[f"CA index not found: {index_path}"],
                duration_ms=round((time.monotonic() - start) * 1000, 2),
                metadata={"ca_dir": ca_dir},
            )

        certificates: list[dict] = []
        errors: list[str] = []
        checked = 0

        for line_no, line in enumerate(index_path.read_text().splitlines(), start=1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            checked += 1
            fields = line.split("\t")
            if len(fields) < 6:
                errors.append(f"index.txt:{line_no}: malformed entry")
                continue

            status_char, expiry_raw, rev_raw, serial, _, subject_dn = fields[:6]
            if status_char not in _STATUS_MAP:
                errors.append(f"index.txt:{line_no}: unknown status {status_char!r}")
                continue

            pem = self._find_pem(newcerts, serial)
            if pem is None:
                errors.append(f"index.txt:{line_no}: certificate PEM not found for serial {serial}")
                continue

            record = self._parse_pem(
                pem_path=pem,
                serial=serial,
                status=_STATUS_MAP[status_char],
                subject_dn=subject_dn,
                expiry_raw=expiry_raw,
            )
            if record is None:
                errors.append(f"index.txt:{line_no}: failed to parse {pem.name}")
                continue

            certificates.append(record)

        duration_ms = round((time.monotonic() - start) * 1000, 2)
        logger.info(
            "openssl_ca_scan_complete",
            ca_dir=ca_dir,
            entries=checked,
            found=len(certificates),
            errors=len(errors),
            duration_ms=duration_ms,
        )

        return ScanResult(
            scanner_name=self.name,
            total_checked=checked,
            total_new=len(certificates),
            total_errors=len(errors),
            certificates=certificates,
            errors=errors,
            duration_ms=duration_ms,
            metadata={"ca_dir": ca_dir, "ca_name": self.ca_name or ca_path.name},
        )

    async def health_check(self) -> HealthStatus:
        """The scanner is healthy when the CA database is readable."""
        if not self.ca_dir:
            return HealthStatus("error", "openssl_ca_dir not configured")
        index = Path(self.ca_dir) / "index.txt"
        if index.is_file():
            return HealthStatus("ok", f"CA index readable: {index}")
        return HealthStatus("error", f"CA index not readable: {index}")

    # ------------------------------------------------------------------
    # Parsing helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _find_pem(newcerts: Path, serial: str) -> Path | None:
        """Locate the issued-certificate PEM for a serial (case-insensitive)."""
        for candidate in {f"{serial}.pem", f"{serial.upper()}.pem", f"{serial.lower()}.pem"}:
            path = newcerts / candidate
            if path.is_file():
                return path
        return None

    @staticmethod
    def _parse_index_date(raw: str) -> datetime | None:
        """Parse an index.txt YYMMDDHHMMSSZ expiry/revocation date."""
        if not raw or len(raw) < 13:
            return None
        try:
            yy = int(raw[0:2])
            year = 2000 + yy if yy < 50 else 1900 + yy
            return datetime.strptime(f"{year}{raw[2:12]}", "%Y%m%d%H%M%S").replace(tzinfo=UTC)
        except ValueError:
            return None

    def _parse_pem(
        self,
        pem_path: Path,
        serial: str,
        status: str,
        subject_dn: str,
        expiry_raw: str,
    ) -> dict | None:
        """Build a normalized certificate dict from an issued PEM."""
        try:
            cert = x509.load_pem_x509_certificate(pem_path.read_bytes())
        except Exception as e:
            logger.debug("openssl_ca_pem_parse_failed", pem=str(pem_path), error=str(e))
            return None

        thumbprint = cert.fingerprint(hashes.SHA256()).hex()
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc

        # Expiry from the PEM wins; if the index says expired and the PEM
        # doesn't, trust the index (status drives alerting).
        effective_status = status
        if effective_status == "active" and not_after < datetime.now(UTC):
            effective_status = "expired"

        common_name = ""
        for attr in cert.subject:
            if attr.oid._name == "commonName":
                common_name = attr.value
                break

        sans: list[str] = []
        try:
            san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            sans = san_ext.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            pass

        from cryptography.hazmat.primitives.asymmetric import ec, rsa

        pubkey = cert.public_key()
        if isinstance(pubkey, rsa.RSAPublicKey):
            key_algorithm = f"RSA-{pubkey.key_size}"
        elif isinstance(pubkey, ec.EllipticCurvePublicKey):
            key_algorithm = f"ECDSA-{pubkey.curve.name}"
        else:
            key_algorithm = type(pubkey).__name__

        is_ca = False
        try:
            bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
            is_ca = bc.value.ca
        except x509.ExtensionNotFound:
            pass

        cert_type = "ca" if is_ca else "server"
        try:
            eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
            purposes = {oid._name for oid in eku.value}
            if "clientAuth" in purposes and "serverAuth" not in purposes:
                cert_type = "client"
            elif "codeSigning" in purposes:
                cert_type = "code_signing"
        except x509.ExtensionNotFound:
            pass

        return {
            "common_name": common_name or subject_dn or serial,
            "subject": cert.subject.rfc4514_string(),
            "issuer": cert.issuer.rfc4514_string(),
            "serial_number": format(cert.serial_number, "X"),
            "thumbprint": thumbprint,
            "not_before": not_before.isoformat(),
            "not_after": not_after.isoformat(),
            "key_algorithm": key_algorithm,
            "signature_algorithm": cert.signature_algorithm_oid._name,
            "sans": sans,
            "cert_type": cert_type,
            "is_wildcard": common_name.startswith("*."),
            "is_ca": is_ca,
            "status": effective_status,
            "source_detail": {
                "ca_name": self.ca_name or "openssl_ca",
                "index_status": status,
                "index_serial": serial,
                "index_expiry": self._parse_index_date(expiry_raw).isoformat()
                if self._parse_index_date(expiry_raw)
                else expiry_raw,
                "pem_path": str(pem_path),
            },
        }
