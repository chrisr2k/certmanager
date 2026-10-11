"""ACME (Let's Encrypt and compatible) certificate authority connector.

Unlike AWS ACM / Azure Key Vault / AD CS, ACME is not a managed service —
there is no "list all my certs" API, and the private key is this
connector's problem to generate and hand back (never persisted here; see
`certmanager/services/acme_service.py` for where the caller stores it,
encrypted, for later download).

`acme`/`josepy` (the official EFF/Certbot libraries) are built on
`requests` and are fully synchronous. Every call into them is wrapped in
`asyncio.to_thread(...)` so a slow directory fetch or a 30-180s DNS-01
validation poll never blocks the API process's event loop — this matters
even for `health_check()`, which (unlike discovery) is invoked inline on
the request-serving loop by `POST /authorities/{id}/test`.

`source_id` convention for this connector only: both `renew_certificate`
and `revoke_certificate` take the certificate's own PEM body as
`source_id`, not a short identifier — there is no ACME-side object to
re-fetch by ID, and parsing the PEM directly (rather than requiring a DB
lookup) keeps this connector as DB-agnostic as every other one. The
caller (AcmeService) supplies `Certificate.source_detail["cert_pem"]`.
"""

from __future__ import annotations

import asyncio
import time
from datetime import UTC, datetime, timedelta

import httpx
import structlog
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from certmanager.connectors.base import (
    CAConnector,
    CAHealthResult,
    CAHealthStatus,
    CertificateRecord,
    ConnectorAuthError,
    ConnectorConfigError,
    ConnectorError,
    ConnectorRateLimitError,
    IssueRequest,
    IssueResult,
)
from certmanager.connectors.dns_providers import DNSChallengeProvider

logger = structlog.get_logger()

LETSENCRYPT_PRODUCTION_DIRECTORY = "https://acme-v02.api.letsencrypt.org/directory"
LETSENCRYPT_STAGING_DIRECTORY = "https://acme-staging-v02.api.letsencrypt.org/directory"

# Intermediate/root CNs Let's Encrypt issues from — used to filter crt.sh
# results in discover_certificates() to "certs issued by Let's Encrypt
# for domains we care about", not just "any cert for this domain".
_LETSENCRYPT_ISSUER_MARKERS = ("let's encrypt", "isrg", " r3", " r10", " r11", " r12", " r13", " e1", " e2")

# DNS-01 validation failures are hard-limited by Let's Encrypt to 5 per
# account/hostname/hour — validating before the TXT record has actually
# propagated is the single most common way to burn that budget for nothing.
_DNS_PROPAGATION_TIMEOUT_SECONDS = 90
_DNS_PROPAGATION_POLL_INTERVAL_SECONDS = 5
_AUTHORIZATION_TIMEOUT_SECONDS = 120


class ACMEConnector(CAConnector):
    """Connector for Let's Encrypt and other ACME-compatible CAs.

    Configuration (from CertificateAuthority.config JSONB):
        {
            "directory_url": "https://acme-v02.api.letsencrypt.org/directory",
            "contact_email": "admin@example.com",
            "domains": ["example.com", "*.example.com"],
            "dns_provider_api_token": "<cloudflare token>",
            "cloudflare_zone_id": "optional, resolved automatically if omitted",
            "account_key_pem": "generated and persisted back on first use",
            "account_url": "generated and persisted back on first use"
        }
    """

    connector_type = "acme"

    def __init__(
        self,
        directory_url: str,
        contact_email: str,
        domains: list[str],
        dns_provider: DNSChallengeProvider,
        account_key_pem: str | None = None,
        account_url: str | None = None,
    ):
        self.directory_url = directory_url or LETSENCRYPT_PRODUCTION_DIRECTORY
        self.contact_email = contact_email
        self.domains = domains
        self.dns_provider = dns_provider
        self.account_key_pem = account_key_pem
        self.account_url = account_url

        # Populated by ensure_account(); surfaced to the caller (service
        # layer) via new_account_key_pem/new_account_url so it can persist
        # them — this connector never touches the database itself.
        self.new_account_key_pem: str | None = None
        self.new_account_url: str | None = None

    # ------------------------------------------------------------------
    # Account bootstrap
    # ------------------------------------------------------------------
    def _build_client(self):
        """Blocking: build (account_key, net, acme_client) from the current
        account_key_pem/account_url, registering a new account if neither
        is set. Must only be called inside asyncio.to_thread."""
        import josepy as jose
        from acme import client as acme_client_mod
        from acme import messages

        if self.account_key_pem:
            private_key = serialization.load_pem_private_key(
                self.account_key_pem.encode(), password=None
            )
            account_key = jose.JWKRSA(key=jose.ComparableRSAKey(private_key))
        else:
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            account_key = jose.JWKRSA(key=jose.ComparableRSAKey(private_key))
            self.new_account_key_pem = private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ).decode()

        net = acme_client_mod.ClientNetwork(account_key, user_agent="certmanager/1.0")
        directory = acme_client_mod.ClientV2.get_directory(self.directory_url, net)
        acme_client = acme_client_mod.ClientV2(directory, net=net)

        if self.account_url:
            # Reuse the existing account — set kid directly, no extra
            # round trip needed, then confirm it's still valid.
            regr = messages.RegistrationResource(uri=self.account_url, body=messages.Registration())
            net.account = regr
            acme_client.query_registration(regr)
        else:
            new_reg = messages.NewRegistration.from_data(
                email=self.contact_email, terms_of_service_agreed=True
            )
            regr = acme_client.new_account(new_reg)  # sets net.account internally
            self.new_account_url = regr.uri

        return account_key, acme_client

    async def ensure_account(self) -> tuple[str | None, str | None]:
        """Ensure an ACME account exists, registering one if needed.

        Returns:
            (new_account_key_pem, new_account_url) — both None if the
            connector was already configured with an existing account;
            the caller (AcmeService) persists these into
            CertificateAuthority.config when non-None.
        """
        await asyncio.to_thread(self._build_client)
        return self.new_account_key_pem, self.new_account_url

    # ------------------------------------------------------------------
    # CAConnector interface
    # ------------------------------------------------------------------
    async def health_check(self) -> CAHealthResult:
        start = time.monotonic()
        try:
            await asyncio.to_thread(self._build_client)
            latency_ms = (time.monotonic() - start) * 1000
            return CAHealthResult(
                status=CAHealthStatus.HEALTHY,
                message=f"ACME directory reachable, account valid ({self.directory_url})",
                latency_ms=round(latency_ms, 2),
                detail={"directory_url": self.directory_url, "domains": self.domains},
            )
        except Exception as e:
            latency_ms = (time.monotonic() - start) * 1000
            error_str = str(e)
            if "401" in error_str or "403" in error_str or "unauthorized" in error_str.lower():
                status = CAHealthStatus.UNHEALTHY
                message = f"ACME account invalid or rejected: {error_str[:200]}"
            else:
                status = CAHealthStatus.UNHEALTHY
                message = f"ACME directory unreachable: {error_str[:200]}"
            return CAHealthResult(
                status=status, message=message, latency_ms=round(latency_ms, 2), detail={"error": error_str}
            )

    async def discover_certificates(self, scope: dict | None = None) -> list[CertificateRecord]:
        """Surface Let's Encrypt-issued certs for the configured domains via
        crt.sh — including ones issued outside this platform (e.g. an
        existing certbot setup). There is no ACME "list my certs" API."""
        domains = (scope or {}).get("domains", self.domains)
        records: list[CertificateRecord] = []

        async with httpx.AsyncClient(timeout=30.0) as http:
            for domain in domains:
                try:
                    entries = await self._query_crtsh(http, domain)
                except Exception as e:
                    logger.warning("acme_crtsh_query_failed", domain=domain, error=str(e))
                    continue

                for entry in entries:
                    issuer_name = (entry.get("issuer_name") or "").lower()
                    if not any(marker in issuer_name for marker in _LETSENCRYPT_ISSUER_MARKERS):
                        continue
                    record = self._parse_crtsh_entry(entry, domain)
                    if record:
                        records.append(record)

                await asyncio.sleep(1.5)  # crt.sh rate limiting, matches ct_log_worker.py

        return records

    @staticmethod
    async def _query_crtsh(http: httpx.AsyncClient, domain: str) -> list[dict]:
        resp = await http.get(
            "https://crt.sh/",
            params={"q": f"%.{domain}", "output": "json"},
            headers={"User-Agent": "CertManager-ACME-Discovery/1.0"},
        )
        if resp.status_code != 200:
            return []
        data = resp.json()
        return data if isinstance(data, list) else []

    @staticmethod
    def _parse_crtsh_entry(entry: dict, domain: str) -> CertificateRecord | None:
        try:
            not_before = datetime.fromisoformat(entry["not_before"]).replace(tzinfo=UTC)
            not_after = datetime.fromisoformat(entry["not_after"]).replace(tzinfo=UTC)
        except (KeyError, ValueError):
            return None

        name_value = entry.get("name_value", "")
        sans = sorted(set(name_value.split("\n"))) if name_value else [domain]
        common_name = sans[0] if sans else domain

        return CertificateRecord(
            common_name=common_name,
            subject=f"CN={common_name}",
            issuer=entry.get("issuer_name", ""),
            serial_number=str(entry.get("serial_number", "")),
            thumbprint_sha256="",  # crt.sh doesn't expose the leaf fingerprint directly
            not_before=not_before,
            not_after=not_after,
            sans=sans,
            cert_type="server",
            is_wildcard=common_name.startswith("*."),
            source_detail={"crtsh_id": entry.get("id"), "ct_log": entry.get("ct_log")},
            source_id="",
            status="active" if not_after > datetime.now(UTC) else "expired",
        )

    async def get_certificate(self, source_id: str) -> CertificateRecord | None:
        raise ConnectorError(
            "ACME does not support certificate lookup by ID — certificates issued through "
            "this connector are tracked in the platform inventory, not re-fetchable from "
            "the ACME server."
        )

    async def get_certificate_chain(self, source_id: str) -> list[CertificateRecord]:
        raise ConnectorError(
            "ACME does not support chain lookup by ID — the chain was returned at issuance "
            "time and is stored in the platform inventory (Certificate.source_detail)."
        )

    async def issue_certificate(self, request: IssueRequest) -> IssueResult:
        account_key, acme_client = await asyncio.to_thread(self._build_client)

        sans = list({request.common_name, *request.sans})  # CN duplicated into SANs
        private_key, csr_pem = self._build_csr(request.common_name, sans, request.key_algorithm)

        try:
            order = await asyncio.to_thread(acme_client.new_order, csr_pem)
        except Exception as e:
            raise self._map_acme_error(e) from e

        created_records: list[tuple[str, str]] = []  # (domain, record_id) for cleanup
        try:
            for authzr in order.authorizations:
                domain = authzr.body.identifier.value
                await self._answer_dns01(acme_client, account_key, authzr, domain, created_records)

            # acme's own poll_and_finalize default (datetime.now() + delta)
            # is a NAIVE datetime — its internal comparisons mix that with
            # whatever deadline we pass, so an aware one here raises
            # "can't compare offset-naive and offset-aware datetimes".
            deadline = datetime.now() + timedelta(seconds=_AUTHORIZATION_TIMEOUT_SECONDS)
            finalized = await asyncio.to_thread(
                acme_client.poll_and_finalize, order, deadline
            )
        except Exception as e:
            raise self._map_acme_error(e) from e
        finally:
            # Always clean up TXT records, even on failure. The ACME order
            # itself has no explicit "abort" — on a timeout it's simply
            # left to expire server-side (RFC8555 has no cancel operation).
            for domain, record_id in created_records:
                try:
                    await self.dns_provider.delete_txt_record(domain, record_id)
                except Exception as e:
                    logger.warning("acme_txt_cleanup_failed", domain=domain, error=str(e))

        fullchain_pem = finalized.fullchain_pem
        certs = x509.load_pem_x509_certificates(fullchain_pem.encode())
        leaf = certs[0]
        chain_pem = "\n".join(
            c.public_bytes(serialization.Encoding.PEM).decode() for c in certs[1:]
        )
        leaf_pem = leaf.public_bytes(serialization.Encoding.PEM).decode()
        key_pem = private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()

        record = self._parse_x509(leaf, request.cert_type, {
            "cert_pem": leaf_pem,
            "chain_pem": chain_pem,
            "fullchain_pem": fullchain_pem,
            "acme_order_url": order.uri,
        })
        return IssueResult(certificate=record, private_key_pem=key_pem)

    async def _answer_dns01(self, acme_client, account_key, authzr, domain: str, created_records: list):
        from acme import challenges

        challb = next(
            (c for c in authzr.body.challenges if isinstance(c.chall, challenges.DNS01)), None
        )
        if challb is None:
            raise ConnectorConfigError(f"No DNS-01 challenge offered for domain '{domain}'")

        response, validation = challb.chall.response_and_validation(account_key)
        record_id = await self.dns_provider.create_txt_record(domain, validation)
        created_records.append((domain, record_id))

        # Wait for propagation before telling the ACME server to validate —
        # premature validation attempts burn LE's 5-failures/hour budget
        # for this hostname, not just a free retry.
        propagated = await self._wait_for_dns_propagation(domain, validation)
        if not propagated:
            logger.warning(
                "acme_dns_propagation_timeout",
                domain=domain,
                message="Proceeding anyway — propagation check timed out but validation may still succeed",
            )

        await asyncio.to_thread(acme_client.answer_challenge, challb, response)

    @staticmethod
    async def _wait_for_dns_propagation(domain: str, expected_value: str) -> bool:
        """Poll Cloudflare's own DNS-over-HTTPS resolver (bypassing the
        local/OS caching resolver) for the TXT record to become visible."""
        record_name = f"_acme-challenge.{domain}"
        deadline = time.monotonic() + _DNS_PROPAGATION_TIMEOUT_SECONDS

        async with httpx.AsyncClient(timeout=10.0) as http:
            while time.monotonic() < deadline:
                try:
                    resp = await http.get(
                        "https://cloudflare-dns.com/dns-query",
                        params={"name": record_name, "type": "TXT"},
                        headers={"Accept": "application/dns-json"},
                    )
                    if resp.status_code == 200:
                        answers = resp.json().get("Answer", [])
                        for answer in answers:
                            if expected_value in answer.get("data", ""):
                                return True
                except Exception as e:
                    logger.debug("acme_dns_propagation_check_failed", domain=domain, error=str(e))
                await asyncio.sleep(_DNS_PROPAGATION_POLL_INTERVAL_SECONDS)

        return False

    async def renew_certificate(self, source_id: str) -> IssueResult:
        """Re-issues for the same name set as the certificate `source_id`
        (its PEM body) was issued for — not the authority's config.domains,
        which only scopes discovery and can drift from what was issued."""
        try:
            existing = x509.load_pem_x509_certificate(source_id.encode())
        except Exception as e:
            raise ConnectorConfigError(f"renew_certificate: source_id is not a valid PEM cert: {e}") from e

        common_name = ""
        for attr in existing.subject:
            if attr.oid == NameOID.COMMON_NAME:
                common_name = attr.value
                break
        try:
            sans = existing.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            ).value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            sans = [common_name] if common_name else []

        return await self.issue_certificate(
            IssueRequest(common_name=common_name or (sans[0] if sans else ""), sans=sans)
        )

    async def revoke_certificate(self, source_id: str, reason: str = "unspecified") -> bool:
        """Real ACME revocation, signed by the account key — unlike AWS
        ACM (no revoke API) this one genuinely works. `source_id` is the
        certificate's PEM body (see module docstring)."""
        reason_codes = {
            "unspecified": 0,
            "key_compromise": 1,
            "ca_compromise": 2,
            "superseded": 4,
            "cessation_of_operation": 5,
        }
        rsn = reason_codes.get(reason, 0)

        _account_key, acme_client = await asyncio.to_thread(self._build_client)
        try:
            cert = x509.load_pem_x509_certificate(source_id.encode())
        except Exception as e:
            raise ConnectorConfigError(f"revoke_certificate: source_id is not a valid PEM cert: {e}") from e

        try:
            await asyncio.to_thread(acme_client.revoke, cert, rsn)
        except Exception as e:
            raise self._map_acme_error(e) from e
        return True

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _build_csr(common_name: str, sans: list[str], key_algorithm: str):
        if key_algorithm.startswith("ECDSA"):
            private_key = ec.generate_private_key(ec.SECP256R1())
        else:
            key_size = 4096 if "4096" in key_algorithm else 2048
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)

        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), critical=False)
            .sign(private_key, hashes.SHA256())
        )
        csr_pem = csr.public_bytes(serialization.Encoding.PEM)
        return private_key, csr_pem

    @staticmethod
    def _parse_x509(cert: x509.Certificate, cert_type: str, source_detail: dict) -> CertificateRecord:
        common_name = ""
        for attr in cert.subject:
            if attr.oid == NameOID.COMMON_NAME:
                common_name = attr.value
                break

        sans: list[str] = []
        try:
            sans = cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            ).value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            pass

        pubkey = cert.public_key()
        if isinstance(pubkey, rsa.RSAPublicKey):
            key_algorithm = f"RSA-{pubkey.key_size}"
        elif isinstance(pubkey, ec.EllipticCurvePublicKey):
            key_algorithm = f"ECDSA-{pubkey.curve.name}"
        else:
            key_algorithm = type(pubkey).__name__

        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc

        return CertificateRecord(
            common_name=common_name,
            subject=cert.subject.rfc4514_string(),
            issuer=cert.issuer.rfc4514_string(),
            serial_number=format(cert.serial_number, "X"),
            thumbprint_sha256=cert.fingerprint(hashes.SHA256()).hex(),
            not_before=not_before,
            not_after=not_after,
            validity_days=int((not_after - not_before).total_seconds() / 86400),
            key_algorithm=key_algorithm,
            signature_algorithm=cert.signature_algorithm_oid._name,
            sans=sans,
            cert_type=cert_type,
            is_wildcard=common_name.startswith("*."),
            source_detail=source_detail,
            source_id="",
            status="active",
        )

    @staticmethod
    def _map_acme_error(e: Exception) -> ConnectorError:
        """Map ACME protocol errors to the connector's typed exceptions."""
        error_str = str(e)
        if "ratelimited" in error_str.lower() or "429" in error_str:
            return ConnectorRateLimitError(f"Let's Encrypt rate-limited the request: {error_str[:300]}")
        if "unauthorized" in error_str.lower() or "401" in error_str or "403" in error_str:
            return ConnectorAuthError(f"ACME account unauthorized: {error_str[:300]}")
        return ConnectorError(f"ACME request failed: {error_str[:300]}")
