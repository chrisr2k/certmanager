"""TLS network scanner — discovers certificates by performing TLS handshakes.

Scans configured CIDR ranges and ports to find TLS certificates on
endpoints not tracked by any CA. Each discovered certificate is
normalized and reported to the central API.

Uses asyncio for concurrent scanning of multiple hosts.
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import ssl
import time
from datetime import datetime, timezone
from typing import Optional

import structlog

from certmanager.agent.scanners.base import HealthStatus, ScannerPlugin, ScanResult

logger = structlog.get_logger()

# Disable certificate verification — we're just collecting metadata
_INSECURE_SSL_CONTEXT = ssl.create_default_context()
_INSECURE_SSL_CONTEXT.check_hostname = False
_INSECURE_SSL_CONTEXT.verify_mode = ssl.CERT_NONE


class TLSScanner(ScannerPlugin):
    """Discovers certificates by performing TLS handshakes against endpoints.

    Scans specified CIDR ranges and ports. For each endpoint that accepts
    a TLS connection, extracts the server certificate and records its metadata.
    """

    name = "tls_scanner"

    def __init__(
        self,
        cidr_ranges: list[str] | None = None,
        ports: list[int] | None = None,
        timeout: float = 5.0,
        max_concurrency: int = 50,
    ):
        """Initialize the TLS scanner.

        Args:
            cidr_ranges: CIDR ranges to scan (e.g., ["10.0.0.0/24"]).
            ports: TCP ports to check for TLS.
            timeout: Connection timeout in seconds.
            max_concurrency: Maximum concurrent TLS handshakes.
        """
        self.cidr_ranges = cidr_ranges or []
        self.ports = ports or [443, 8443, 636, 993, 995, 465, 3389]
        self.timeout = timeout
        self.max_concurrency = max_concurrency
        self._semaphore = asyncio.Semaphore(max_concurrency)

    async def health_check(self) -> HealthStatus:
        """Check if we can perform TLS handshakes."""
        try:
            # Test TLS against a known-good endpoint
            test_host = "1.1.1.1"  # Cloudflare DNS
            test_port = 443

            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(test_host, test_port, ssl=_INSECURE_SSL_CONTEXT),
                    timeout=self.timeout,
                )
                writer.close()
                await writer.wait_closed()

                return HealthStatus(
                    status="ok",
                    message=f"TLS scanning operational (tested against {test_host}:{test_port})",
                )
            except asyncio.TimeoutError:
                return HealthStatus(
                    status="degraded",
                    message="TLS test connection timed out — scanner may be firewalled",
                )
        except Exception as e:
            return HealthStatus(
                status="error",
                message=f"TLS health check failed: {e}",
            )

    async def scan(self, scope: dict | None = None) -> ScanResult:
        """Execute TLS discovery scan across configured CIDR ranges.

        Args:
            scope: Optional filter dict:
                {"cidr_ranges": ["10.0.0.0/24"], "ports": [443, 8443]}

        Returns:
            ScanResult with discovered certificates.
        """
        start = time.monotonic()
        scope = scope or {}
        errors: list[str] = []

        cidrs = scope.get("cidr_ranges", self.cidr_ranges)
        ports = scope.get("ports", self.ports)

        if not cidrs:
            return ScanResult(
                scanner_name=self.name,
                total_checked=0,
                errors=["No CIDR ranges configured for TLS scanning"],
            )

        # Expand CIDRs to IP addresses
        targets: list[str] = []
        for cidr in cidrs:
            try:
                network = ipaddress.ip_network(cidr, strict=False)
                # Limit to /24 or smaller to avoid scanning millions of IPs
                if network.num_addresses > 65536:
                    errors.append(f"CIDR {cidr} too large ({network.num_addresses} hosts). Skipping.")
                    continue
                # Only scan first 256 hosts per range for performance
                hosts = list(network.hosts())
                if len(hosts) > 256:
                    hosts = hosts[:256]
                    errors.append(f"CIDR {cidr} truncated to first 256 hosts.")

                for host in hosts:
                    for port in ports:
                        targets.append((str(host), port))
            except ValueError as e:
                errors.append(f"Invalid CIDR {cidr}: {e}")

        logger.info(
            "tls_scan_starting",
            cidrs=cidrs,
            target_count=len(targets),
            ports=ports,
        )

        # Concurrent scan
        tasks = [self._scan_host_port(host, port) for host, port in targets]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Collect results
        all_certs: list[dict] = []
        total_checked = 0
        total_errors = 0

        for result in results:
            if isinstance(result, Exception):
                total_errors += 1
                errors.append(str(result))
            elif result:
                total_checked += 1
                all_certs.append(result)

        duration_ms = (time.monotonic() - start) * 1000

        logger.info(
            "tls_scan_complete",
            targets=len(targets),
            found=len(all_certs),
            errors=total_errors,
            duration_ms=round(duration_ms, 2),
        )

        return ScanResult(
            scanner_name=self.name,
            total_checked=total_checked,
            total_new=len(all_certs),
            total_errors=total_errors,
            certificates=all_certs,
            errors=errors,
            duration_ms=round(duration_ms, 2),
            metadata={
                "cidrs": cidrs,
                "ports": ports,
                "target_count": len(targets),
            },
        )

    async def _scan_host_port(self, host: str, port: int) -> Optional[dict]:
        """Scan a single host:port for a TLS certificate.

        Returns:
            Certificate dict if TLS is present, None otherwise.
        """
        async with self._semaphore:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port, ssl=_INSECURE_SSL_CONTEXT),
                    timeout=self.timeout,
                )

                # Get the server certificate
                ssl_obj = writer.get_extra_info("ssl_object")
                if ssl_obj is None:
                    writer.close()
                    return None

                cert_bin = ssl_obj.getpeercert(binary_form=True)
                writer.close()
                await writer.wait_closed()

                if cert_bin is None:
                    return None

                return self._parse_certificate(cert_bin, host, port)

            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                return None
            except ssl.SSLError:
                # TLS present but negotiation failed — still record the endpoint
                return None
            except Exception as e:
                logger.debug("tls_scan_error", host=host, port=port, error=str(e))
                return None

    def _parse_certificate(self, cert_bin: bytes, host: str, port: int) -> dict:
        """Parse a DER-encoded X.509 certificate from a TLS handshake."""
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes

        cert = x509.load_der_x509_certificate(cert_bin)

        # SHA-256 thumbprint
        thumbprint = cert.fingerprint(hashes.SHA256()).hex()

        # Serial number
        serial = format(cert.serial_number, "X")

        # Subject and issuer
        subject = cert.subject.rfc4514_string()
        issuer = cert.issuer.rfc4514_string()

        # Common Name
        common_name = ""
        for attr in cert.subject:
            if attr.oid._name == "commonName":
                common_name = attr.value
                break

        # Validity
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc

        # SANs
        sans: list[str] = []
        try:
            san_ext = cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            )
            sans = san_ext.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            if common_name:
                sans = [common_name]

        # Key algorithm
        from cryptography.hazmat.primitives.asymmetric import ec, rsa

        pubkey = cert.public_key()
        if isinstance(pubkey, rsa.RSAPublicKey):
            key_algorithm = f"RSA-{pubkey.key_size}"
        elif isinstance(pubkey, ec.EllipticCurvePublicKey):
            key_algorithm = f"ECDSA-{pubkey.curve.name}"
        else:
            key_algorithm = type(pubkey).__name__

        # Signature algorithm
        sig_algorithm = cert.signature_algorithm_oid._name

        # Is it a CA?
        is_ca = False
        try:
            bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
            is_ca = bc.value.ca
        except x509.ExtensionNotFound:
            pass

        # Expiry status
        now = datetime.now(timezone.utc)
        if not_after < now:
            status = "expired"
        elif not_before > now:
            status = "not_yet_valid"
        else:
            status = "active"

        # Determine cert type from usage
        cert_type = "server"
        try:
            eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
            purposes = {oid._name for oid in eku}
            if "serverAuth" in purposes:
                cert_type = "server"
            elif "clientAuth" in purposes:
                cert_type = "client"
            elif "codeSigning" in purposes:
                cert_type = "code_signing"
        except x509.ExtensionNotFound:
            pass

        return {
            "common_name": common_name or host,
            "subject": subject,
            "issuer": issuer,
            "serial_number": serial,
            "thumbprint": thumbprint,
            "not_before": not_before.isoformat(),
            "not_after": not_after.isoformat(),
            "key_algorithm": key_algorithm,
            "signature_algorithm": sig_algorithm,
            "sans": sans,
            "cert_type": cert_type,
            "is_wildcard": (common_name or "").startswith("*."),
            "is_ca": is_ca,
            "status": status,
            "source": "tls_scan",
            "source_detail": {
                "discovered_host": host,
                "discovered_port": port,
                "discovery_method": "tls_handshake",
            },
        }
