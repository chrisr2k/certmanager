"""CA Connector factory — creates the appropriate connector from DB config.

Follows the exact pattern from entra-pentest's get_llm() factory:
given a CA configuration record, returns a configured CAConnector instance.
"""

from __future__ import annotations

from typing import Optional

from certmanager.connectors.base import CAConnector, ConnectorConfigError
from certmanager.core.models import CertificateAuthority


def get_connector(
    authority: CertificateAuthority,
    credential_store: Optional["CredentialStore"] = None,
) -> CAConnector:
    """Create a configured CA connector from a CertificateAuthority record.

    Args:
        authority: CertificateAuthority ORM record with config JSONB.
        credential_store: Optional service for decrypting stored credentials.

    Returns:
        A fully configured CAConnector instance ready for discovery/issuance.

    Raises:
        ConnectorConfigError: If the CA type is unknown or config is invalid.
    """
    ca_type = authority.ca_type
    config = authority.config or {}

    if ca_type == "aws_acm":
        return _create_aws_connector(config, authority.name, credential_store)

    elif ca_type == "azure_keyvault":
        return _create_azure_connector(config, authority.name, credential_store)

    elif ca_type == "adcs":
        return _create_adcs_connector(config, authority.name, credential_store)

    else:
        raise ConnectorConfigError(
            f"Unknown CA type: '{ca_type}'. "
            f"Supported types: aws_acm, azure_keyvault, adcs"
        )


def _create_aws_connector(
    config: dict, name: str, credential_store: Optional["CredentialStore"] = None
) -> CAConnector:
    """Create an AWS ACM connector from config."""
    from certmanager.connectors.aws_acm import AWSACMConnector

    account_id = config.get("account_id")
    regions = config.get("regions", ["us-east-1"])
    role_arn = config.get("role_arn")
    external_id = config.get("external_id")
    profile_name = config.get("profile_name")

    if not account_id:
        raise ConnectorConfigError(
            f"AWS ACM CA '{name}' is missing required 'account_id' in config"
        )

    if not regions:
        raise ConnectorConfigError(
            f"AWS ACM CA '{name}' must specify at least one region in config.regions"
        )

    # Resolve credentials from credential store if a ref is present
    if credential_store and config.get("credential_ref"):
        creds = credential_store.get(config["credential_ref"])
        if creds:
            external_id = creds.get("external_id") or external_id

    return AWSACMConnector(
        account_id=account_id,
        regions=regions,
        role_arn=role_arn,
        external_id=external_id,
        profile_name=profile_name,
    )


def _create_azure_connector(
    config: dict, name: str, credential_store: Optional["CredentialStore"] = None
) -> CAConnector:
    """Create an Azure Key Vault connector from config."""
    from certmanager.connectors.azure_keyvault import AzureKeyVaultConnector

    vault_url = config.get("vault_url")
    tenant_id = config.get("tenant_id")
    client_id = config.get("client_id")
    client_secret = config.get("client_secret")

    if not vault_url:
        raise ConnectorConfigError(
            f"Azure Key Vault CA '{name}' is missing required 'vault_url' in config"
        )

    # Resolve credentials
    if credential_store and config.get("credential_ref"):
        creds = credential_store.get(config["credential_ref"])
        if creds:
            client_id = creds.get("client_id") or client_id
            client_secret = creds.get("client_secret") or client_secret
            tenant_id = creds.get("tenant_id") or tenant_id

    return AzureKeyVaultConnector(
        vault_url=vault_url,
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret=client_secret,
    )


def _create_adcs_connector(
    config: dict, name: str, credential_store: Optional["CredentialStore"] = None
) -> CAConnector:
    """Create an AD CS connector from config.

    The AD CS connector delegates to a datacenter agent's REST API.
    The agent runs PowerShell commands against the local AD CS server.
    """
    from certmanager.connectors.adcs import ADCSConnector

    agent_id = config.get("agent_id")
    ca_server = config.get("ca_server")
    ca_name = config.get("ca_name")
    agent_base_url = config.get("agent_base_url")

    if not agent_id:
        raise ConnectorConfigError(
            f"AD CS CA '{name}' is missing required 'agent_id' in config"
        )

    # Agent API token resolved from credential store
    api_token = None
    if credential_store and config.get("credential_ref"):
        creds = credential_store.get(config["credential_ref"])
        if creds:
            api_token = creds.get("agent_token")

    return ADCSConnector(
        agent_id=agent_id,
        ca_server=ca_server or "",
        ca_name=ca_name or "",
        base_url=agent_base_url or "",
        api_token=api_token or "",
    )


class CredentialStore:
    """Service for resolving encrypted CA credentials.

    In production, this queries the ca_credentials table and decrypts values.
    For now, returns a simple dict-based lookup.
    """

    def __init__(self):
        self._cache: dict[str, dict] = {}

    def get(self, lookup_key: str) -> Optional[dict]:
        """Retrieve decrypted credentials for a lookup key."""
        if lookup_key in self._cache:
            return self._cache[lookup_key]

        # In production: query ca_credentials table, decrypt encrypted_value
        # For now, credentials are embedded in config JSONB directly
        return None

    def set(self, lookup_key: str, credentials: dict) -> None:
        """Cache credentials (in production: encrypt and persist)."""
        self._cache[lookup_key] = credentials
