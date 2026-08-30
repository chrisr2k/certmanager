"""Azure Key Vault connector.

Discovers certificates across Azure Key Vaults using the Azure SDK.
Supports DefaultAzureCredential chain (Managed Identity, Azure CLI,
environment variables, etc.).

Configuration (from CertificateAuthority.config JSONB):
    {
        "vault_url": "https://myvault.vault.azure.net/",
        "tenant_id": "00000000-0000-0000-0000-000000000000",
        "subscription_id": "00000000-0000-0000-0000-000000000000"
    }

Credentials are loaded via DefaultAzureCredential chain.
"""

from __future__ import annotations

import hashlib
import time
from datetime import datetime, timedelta, timezone
from typing import List, Optional

import structlog

from certmanager.connectors.base import (
    CAConnector,
    CAHealthResult,
    CAHealthStatus,
    CertificateRecord,
    ConnectorAuthError,
    ConnectorError,
    IssueRequest,
    IssueResult,
)

logger = structlog.get_logger()


class AzureKeyVaultConnector(CAConnector):
    """Connector for Azure Key Vault certificates.

    Uses DefaultAzureCredential for authentication, which tries:
    1. Environment variables (AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID)
    2. Managed Identity (when running in Azure)
    3. Azure CLI credentials
    4. More credential sources
    """

    connector_type = "azure_keyvault"

    def __init__(
        self,
        vault_url: str,
        tenant_id: Optional[str] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
    ):
        """Initialize the Azure Key Vault connector.

        Args:
            vault_url: Full Azure Key Vault URL (https://<vault-name>.vault.azure.net/).
            tenant_id: Azure AD tenant ID (optional, for service principal auth).
            client_id: Service principal client ID (optional).
            client_secret: Service principal client secret (optional).
        """
        self.vault_url = vault_url.rstrip("/")
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self._vault_name = self.vault_url.split("//")[1].split(".")[0] if "//" in vault_url else vault_url

    def _get_credential(self):
        """Get Azure credential using DefaultAzureCredential chain."""
        from azure.identity import DefaultAzureCredential

        if self.client_id and self.client_secret and self.tenant_id:
            from azure.identity import ClientSecretCredential
            return ClientSecretCredential(
                tenant_id=self.tenant_id,
                client_id=self.client_id,
                client_secret=self.client_secret,
            )
        return DefaultAzureCredential()

    def _get_cert_client(self):
        """Get the Key Vault certificate client."""
        from azure.keyvault.certificates import CertificateClient

        return CertificateClient(
            vault_url=self.vault_url,
            credential=self._get_credential(),
        )

    async def health_check(self) -> CAHealthResult:
        """Test Key Vault connectivity by listing certificates (max 1 page)."""
        start = time.monotonic()

        try:
            client = self._get_cert_client()
            # Use list_properties_of_certificates for a lightweight check
            count = 0
            for _ in client.list_properties_of_certificates():
                count += 1
                if count >= 1:
                    break

            latency_ms = (time.monotonic() - start) * 1000
            return CAHealthResult(
                status=CAHealthStatus.HEALTHY,
                message=f"Key Vault accessible: {self._vault_name}",
                latency_ms=round(latency_ms, 2),
                detail={"vault_url": self.vault_url, "cert_count_sampled": count},
            )
        except Exception as e:
            latency_ms = (time.monotonic() - start) * 1000
            error_str = str(e)

            if "AuthenticationError" in str(type(e).__name__) or "unauthorized" in error_str.lower():
                status = CAHealthStatus.UNHEALTHY
                message = f"Key Vault authentication failed for {self._vault_name}"
            else:
                status = CAHealthStatus.UNHEALTHY
                message = f"Key Vault unreachable: {self._vault_name}: {error_str[:200]}"

            return CAHealthResult(
                status=status,
                message=message,
                latency_ms=round(latency_ms, 2),
                detail={"error": error_str},
            )

    async def discover_certificates(
        self, scope: Optional[dict] = None
    ) -> List[CertificateRecord]:
        """Discover all certificates in the configured Key Vault.

        Iterates through all certificate versions and collects metadata.
        Never retrieves private keys.

        Args:
            scope: Optional filter dict (unused for now — future: version filter).

        Returns:
            List of normalized CertificateRecord objects.
        """
        client = self._get_cert_client()
        records: List[CertificateRecord] = []

        try:
            # List all certificates
            for cert_props in client.list_properties_of_certificates():
                try:
                    # Get the full certificate with policy (not the private key)
                    certificate = client.get_certificate(cert_props.name)
                    record = self._parse_certificate(certificate)
                    records.append(record)
                except Exception as e:
                    logger.warning(
                        "azure_cert_parse_failed",
                        vault=self._vault_name,
                        cert_name=cert_props.name,
                        error=str(e),
                    )
                    continue

        except Exception as e:
            raise ConnectorError(f"Key Vault discovery failed: {e}")

        logger.info(
            "azure_discovery_complete",
            vault=self._vault_name,
            cert_count=len(records),
        )
        return records

    def _parse_certificate(self, certificate) -> CertificateRecord:
        """Parse an Azure Key Vault certificate into a CertificateRecord.

        The KeyVaultCertificate object contains:
        - properties: version, enabled, created, updated, tags
        - policy: key size, key type, subject, validity, SANs, issuers
        - cer: X.509 certificate bytes (public key only)
        """
        from azure.keyvault.certificates import CertificateContentType

        props = certificate.properties
        policy = certificate.policy
        x509_bytes = certificate.cer  # DER-encoded public certificate

        # Parse X.509 for detailed metadata
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes

        cert_id = certificate.id or f"{self.vault_url}/certificates/{certificate.name}/{props.version}"
        subject_str = policy.subject if policy else "Unknown"
        issuer_str = policy.issuer_name if policy and policy.issuer_name else "Unknown"
        serial_number = ""
        thumbprint = props.x509_thumbprint.hex() if props.x509_thumbprint else ""
        not_before = datetime.min.replace(tzinfo=timezone.utc)
        not_after = datetime.max.replace(tzinfo=timezone.utc)
        key_algorithm = "unknown"
        signature_algorithm = "unknown"
        sans: List[str] = []
        is_ca = False

        if x509_bytes:
            try:
                cert = x509.load_der_x509_certificate(x509_bytes)
                subject_str = cert.subject.rfc4514_string()
                issuer_str = cert.issuer.rfc4514_string()
                serial_number = format(cert.serial_number, "X")
                not_before = cert.not_valid_before_utc
                not_after = cert.not_valid_after_utc
                thumbprint = cert.fingerprint(hashes.SHA256()).hex()

                from certmanager.connectors.aws_acm import _describe_public_key

                key_algorithm = _describe_public_key(cert)
                signature_algorithm = cert.signature_algorithm_oid._name

                # SANs
                try:
                    san_ext = cert.extensions.get_extension_for_class(
                        x509.SubjectAlternativeName
                    )
                    sans = san_ext.value.get_values_for_type(x509.DNSName)
                except x509.ExtensionNotFound:
                    pass

                # CA check
                try:
                    bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
                    is_ca = bc.value.ca
                except x509.ExtensionNotFound:
                    pass

            except Exception as e:
                logger.warning(
                    "azure_x509_parse_warning",
                    cert_id=cert_id,
                    error=str(e),
                )

        # Status
        if props.enabled:
            status = "active"
        else:
            status = "revoked"

        # Check expiry
        if not_after < datetime.now(timezone.utc):
            status = "expired"

        # Determine cert type
        cert_type = "server"
        if is_ca:
            cert_type = "ca"

        validity_days = int((not_after - not_before).total_seconds() / 86400) if not_before and not_after else 0

        return CertificateRecord(
            common_name=certificate.name,
            subject=subject_str,
            issuer=issuer_str,
            serial_number=serial_number,
            thumbprint_sha256=thumbprint or hashlib.sha256(cert_id.encode()).hexdigest(),
            not_before=not_before,
            not_after=not_after,
            validity_days=validity_days or None,
            key_algorithm=key_algorithm,
            signature_algorithm=signature_algorithm,
            sans=sans,
            cert_type=cert_type,
            is_wildcard=certificate.name.startswith("*") if certificate.name else False,
            is_ca=is_ca,
            source_detail={
                "azure_cert_id": cert_id,
                "vault_url": self.vault_url,
                "vault_name": self._vault_name,
                "version": props.version,
                "content_type": str(props.content_type) if props.content_type else None,
                "key_type": policy.key_type if policy else None,
            },
            source_id=cert_id,
            status=status,
        )

    async def get_certificate(self, source_id: str) -> Optional[CertificateRecord]:
        """Get a single certificate by its Azure Key Vault certificate ID."""
        client = self._get_cert_client()

        try:
            # Parse cert name from the URL/ID
            # Format: https://vault.vault.azure.net/certificates/my-cert/version
            cert_name = source_id.split("/certificates/")[1].split("/")[0]
            certificate = client.get_certificate(cert_name)
            return self._parse_certificate(certificate)
        except Exception as e:
            if "not found" in str(e).lower() or "404" in str(e):
                return None
            raise ConnectorError(f"Failed to get certificate: {e}")

    async def issue_certificate(self, request: IssueRequest) -> IssueResult:
        """Issue a new certificate via Azure Key Vault.

        Azure Key Vault can generate keys internally or accept CSR.
        This implementation uses Key Vault's internal key generation.

        Note: Azure manages the private key internally. Export depends on
        the certificate policy's exportable setting.
        """
        from azure.keyvault.certificates import (
            CertificatePolicy,
            CertificateContentType,
            WellKnownIssuerNames,
        )

        client = self._get_cert_client()

        # Build certificate policy
        policy = CertificatePolicy(
            issuer_name=WellKnownIssuerNames.self,
            subject=f"CN={request.common_name}",
            san_dns_names=request.sans if request.sans else None,
            exportable=True,  # Allow private key export
            key_type="RSA" if "RSA" in request.key_algorithm else "EC",
            key_size=_rsa_key_size(request.key_algorithm),
            reuse_key=False,
            content_type=CertificateContentType.pkcs12,
            validity_lifetime=int(request.validity_days),
        )

        # Begin certificate creation
        create_op = client.begin_create_certificate(
            certificate_name=request.common_name.replace("*", "wildcard"),
            policy=policy,
        )

        # Wait for completion (synchronous for now — can be made async)
        certificate = create_op.result()

        cert_id = certificate.id or f"{self.vault_url}/certificates/{request.common_name}"
        record = self._parse_certificate(certificate)

        return IssueResult(
            certificate=record,
            private_key_pem=None,  # Retrieved separately via get_certificate + secret
            password=None,
        )

    async def renew_certificate(self, source_id: str) -> IssueResult:
        """Renew an existing Key Vault certificate.

        Key Vault supports auto-renewal via certificate policies.
        This triggers a manual renewal if auto-renew is not configured.
        """
        client = self._get_cert_client()
        cert_name = source_id.split("/certificates/")[1].split("/")[0]

        try:
            create_op = client.begin_create_certificate(
                certificate_name=cert_name,
                policy=client.get_certificate_policy(cert_name),
            )
            certificate = create_op.result()
            record = self._parse_certificate(certificate)
            return IssueResult(certificate=record, private_key_pem=None)
        except Exception as e:
            raise ConnectorError(f"Certificate renewal failed: {e}")

    async def revoke_certificate(
        self, source_id: str, reason: str = "unspecified"
    ) -> bool:
        """Disable a certificate in Key Vault (Azure doesn't have CRL-based revocation).

        Sets the certificate to disabled state.
        """
        client = self._get_cert_client()
        cert_name = source_id.split("/certificates/")[1].split("/")[0]

        try:
            # Disable the certificate
            from azure.keyvault.certificates import CertificateProperties

            client.update_certificate_properties(
                certificate_name=cert_name,
                enabled=False,
            )
            return True
        except Exception as e:
            raise ConnectorError(f"Certificate disable failed: {e}")

    async def get_certificate_chain(self, source_id: str) -> List[CertificateRecord]:
        """Get the certificate chain. Key Vault returns only the leaf certificate."""
        # Key Vault doesn't expose chains directly — the chain is assembled
        # by the client during TLS. Return an empty list for now.
        return []


def _rsa_key_size(key_algorithm: str) -> int:
    """Extract RSA key size from algorithm string (e.g., 'RSA-2048' -> 2048)."""
    if "RSA" in key_algorithm:
        try:
            return int(key_algorithm.split("-")[1])
        except (IndexError, ValueError):
            return 2048
    return 2048  # default
