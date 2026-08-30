"""Abstract Base Class for Certificate Authority connectors.

Following the provider ABC pattern from entra-pentest's LLMProvider,
each CA connector implements a common interface for:
- Discovery: List all certificates managed by a CA
- Health check: Verify CA reachability
- Issue/Renew/Revoke: Lifecycle operations
- Chain retrieval: Get the full certificate chain

Private keys are NEVER persisted by the platform. The issue/renew methods
return the private key to the caller, but no connector stores it.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Optional


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------
class CAHealthStatus(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------
@dataclass
class CertificateRecord:
    """Normalized certificate record returned by all connectors.

    Contains only observable metadata — NEVER includes the private key.
    """

    common_name: str
    subject: str
    issuer: str
    serial_number: str
    thumbprint_sha256: str
    not_before: datetime
    not_after: datetime
    key_algorithm: str = "unknown"
    signature_algorithm: str = "unknown"
    sans: List[str] = field(default_factory=list)
    cert_type: str = "unknown"  # server | client | ca | code_signing
    is_wildcard: bool = False
    is_ca: bool = False
    source_detail: dict = field(default_factory=dict)
    source_id: str = ""  # AWS ARN, Azure cert ID, AD CS request ID
    chain_certs: List["CertificateRecord"] = field(default_factory=list)
    status: str = "active"


@dataclass
class CAHealthResult:
    """Result of a CA health check."""

    status: CAHealthStatus
    message: str
    latency_ms: float
    detail: dict = field(default_factory=dict)


@dataclass
class IssueRequest:
    """Request to issue a new certificate."""

    common_name: str
    sans: List[str] = field(default_factory=list)
    key_algorithm: str = "RSA-2048"
    validity_days: int = 365
    cert_type: str = "server"


@dataclass
class IssueResult:
    """Result of a certificate issuance request.

    The private_key_pem is returned to the caller but NEVER stored
    by the platform. The certificate metadata IS stored in the inventory.
    """

    certificate: CertificateRecord
    private_key_pem: Optional[str] = None
    password: Optional[str] = None


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------
class ConnectorError(Exception):
    """Base exception for connector errors."""


class ConnectorAuthError(ConnectorError):
    """Authentication/authorization failure with the CA."""


class ConnectorTimeoutError(ConnectorError):
    """CA did not respond within the timeout window."""


class ConnectorRateLimitError(ConnectorError):
    """CA rate-limited the request."""


class ConnectorConfigError(ConnectorError):
    """Connector configuration is invalid."""


# ---------------------------------------------------------------------------
# Abstract Base Class
# ---------------------------------------------------------------------------
class CAConnector(ABC):
    """Abstract Base Class for all Certificate Authority connectors.

    Each connector abstracts a specific CA backend:
    - AWS Certificate Manager (ACM)
    - Azure Key Vault
    - Active Directory Certificate Services (via datacenter agent)
    - (Future: Google Certificate Manager, HashiCorp Vault PKI, etc.)

    The pattern mirrors the LLMProvider ABC in entra-pentest:
    each implementation handles provider-specific SDK calls
    while presenting a uniform interface to the service layer.
    """

    @property
    @abstractmethod
    def connector_type(self) -> str:
        """Unique string identifying this connector type: aws_acm, azure_keyvault, adcs."""

    @abstractmethod
    async def health_check(self) -> CAHealthResult:
        """Verify the CA is reachable and operational.

        Returns:
            CAHealthResult with status and diagnostic information.
        """

    @abstractmethod
    async def discover_certificates(
        self, scope: Optional[dict] = None
    ) -> List[CertificateRecord]:
        """Discover all certificates managed by this CA.

        Args:
            scope: CA-type-specific filter.
                For AWS: {"regions": ["us-east-1"], "account_id": "..."}
                For Azure: {"vault_url": "..."}
                For ADCS: {"templates": ["WebServer"]}

        Returns:
            List of normalized certificate records. Never includes private keys.
        """

    @abstractmethod
    async def get_certificate(self, source_id: str) -> Optional[CertificateRecord]:
        """Retrieve a single certificate by its source-native identifier."""

    @abstractmethod
    async def issue_certificate(self, request: IssueRequest) -> IssueResult:
        """Request issuance of a new certificate.

        The private key is returned to the caller but is NEVER persisted
        by the connector or stored in the database.

        Args:
            request: Certificate issuance parameters.

        Returns:
            IssueResult with the new certificate record and private key.
        """

    @abstractmethod
    async def renew_certificate(self, source_id: str) -> IssueResult:
        """Renew an existing certificate if the CA supports in-place renewal.

        Args:
            source_id: CA-native identifier for the certificate.

        Returns:
            IssueResult with the new certificate record and private key.
        """

    @abstractmethod
    async def revoke_certificate(
        self, source_id: str, reason: str = "unspecified"
    ) -> bool:
        """Revoke a certificate.

        Args:
            source_id: CA-native identifier for the certificate.
            reason: CRL reason code.
                (key_compromise, ca_compromise, superseded,
                 cessation_of_operation, unspecified)

        Returns:
            True if revocation was successful.
        """

    @abstractmethod
    async def get_certificate_chain(
        self, source_id: str
    ) -> List[CertificateRecord]:
        """Retrieve the full certificate chain (leaf + intermediates).

        Args:
            source_id: CA-native identifier for the leaf certificate.

        Returns:
            Ordered list of CertificateRecord (index 0 = leaf).
        """

    async def validate_config(self) -> None:
        """Optional: validate the connector configuration before first use.

        Raises:
            ConnectorConfigError if configuration is invalid.
        """
        pass  # Override in subclasses if needed
