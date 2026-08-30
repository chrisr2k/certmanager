"""Domain-specific exceptions for CertManager."""

from __future__ import annotations


class CertManagerError(Exception):
    """Base exception for all CertManager errors."""


# --- Auth ---
class AuthenticationError(CertManagerError):
    """Invalid credentials, expired token, or missing auth."""


class AuthorizationError(CertManagerError):
    """Insufficient permissions for the requested action."""


class TokenReuseError(AuthenticationError):
    """Refresh token reuse detected — family revoked."""


class MFARequiredError(AuthenticationError):
    """MFA challenge required before completing login."""


# --- Resources ---
class NotFoundError(CertManagerError):
    """Requested resource does not exist."""


class ConflictError(CertManagerError):
    """Resource already exists (e.g., duplicate CA name)."""


class ValidationError(CertManagerError):
    """Request data failed validation."""


# --- CA / Connector ---
class ConnectorError(CertManagerError):
    """Base for connector-related errors."""


class ConnectorAuthError(ConnectorError):
    """Authentication/authorization failure with a CA."""


class ConnectorTimeoutError(ConnectorError):
    """CA did not respond within the timeout window."""


class ConnectorRateLimitError(ConnectorError):
    """CA rate-limited the request."""


class CAHealthError(ConnectorError):
    """CA is unhealthy or unreachable."""


# --- Agent ---
class AgentError(CertManagerError):
    """Base for agent-related errors."""


class AgentOfflineError(AgentError):
    """Agent has not sent a heartbeat recently."""


class AgentRegistrationError(AgentError):
    """Agent registration failed (invalid PSK, already registered, etc.)."""


# --- Certificate ---
class CertificateError(CertManagerError):
    """Base for certificate operations."""


class CertificateRevocationError(CertificateError):
    """Failed to revoke certificate at the source CA."""


class CertificateIssuanceError(CertificateError):
    """Failed to issue a new certificate."""
