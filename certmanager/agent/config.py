"""Agent configuration via pydantic-settings and agent_config.json.

Environment variables override the JSON config file.
Prefix: CERTMGMT_AGENT__
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class AgentSettings(BaseSettings):
    """Agent configuration loaded from env vars and config file."""

    model_config = SettingsConfigDict(
        env_prefix="CERTMGMT_AGENT__",
        case_sensitive=False,
        extra="ignore",
    )

    # Central API connection
    api_url: str = Field(default="https://localhost:8000", description="Central CertManager API URL")
    psk: str = Field(default="", description="Pre-shared key for agent registration")

    # Agent identity
    agent_name: str = Field(default="", description="Unique agent name (auto-detected if empty)")
    agent_type: str = Field(default="adcs", description="adcs | tls_scanner | generic")
    datacenter_code: str = Field(default="", description="Datacenter code this agent belongs to")

    # Registration
    agent_id: Optional[str] = Field(default=None, description="Agent UUID (set after registration, informational)")

    # Polling
    poll_interval: int = Field(default=30, description="Seconds between job poll cycles")

    # Local storage
    local_db_path: str = Field(default="agent_data/agent.db", description="SQLite database path")
    data_dir: str = Field(default="agent_data", description="Agent data directory")

    # TLS scanner settings (if agent_type=tls_scanner)
    tls_cidr_ranges: list[str] = Field(default_factory=list, description="CIDR ranges for TLS scanning")
    tls_ports: list[int] = Field(default_factory=lambda: [443, 8443, 636, 993, 995], description="Ports to scan for TLS")
    tls_timeout: float = Field(default=5.0, description="TLS handshake timeout in seconds")
    tls_max_hosts_per_cidr: int = Field(default=256, description="Max hosts scanned per CIDR (safety cap)")

    # Connector listener (the central AD CS connector calls the agent here)
    listener_enabled: bool = Field(default=True, description="Serve the connector HTTP listener")
    listener_host: str = Field(default="0.0.0.0", description="Listener bind address")
    listener_port: int = Field(default=8443, description="Listener port")
    listener_ssl_cert: Optional[str] = Field(default=None, description="Path to listener TLS cert PEM")
    listener_ssl_key: Optional[str] = Field(default=None, description="Path to listener TLS key PEM")
    listener_ssl_ca: Optional[str] = Field(default=None, description="Path to client CA PEM (requires client certs when set)")

    # AD CS scanner settings (if agent_type=adcs)
    adcs_ca_server: str = Field(default="", description="AD CS server hostname")
    adcs_ca_name: str = Field(default="", description="Certificate Authority name")
    adcs_use_winrm: bool = Field(default=False, description="Use WinRM instead of local subprocess")

    # Logging
    log_level: str = Field(default="INFO")
    log_format: str = Field(default="json")  # json | console


def load_agent_config(config_path: Optional[str] = None) -> AgentSettings:
    """Load agent configuration from file and environment.

    Args:
        config_path: Path to agent_config.json. Defaults to ./agent_config.json.

    Returns:
        AgentSettings with merged config (env vars override file values).
    """
    import json
    import os

    settings = AgentSettings()

    # Try to load from config file
    path = Path(config_path or "agent_config.json")
    if path.exists():
        with open(path) as f:
            file_config = json.load(f)

        # Map file keys to settings fields
        field_mapping = {
            "api_url": "api_url",
            "psk": "psk",
            "agent_name": "agent_name",
            "agent_type": "agent_type",
            "datacenter_code": "datacenter_code",
            "agent_id": "agent_id",
            "poll_interval": "poll_interval",
            "local_db_path": "local_db_path",
            "tls_cidr_ranges": "tls_cidr_ranges",
            "tls_ports": "tls_ports",
            "tls_timeout": "tls_timeout",
            "tls_max_hosts_per_cidr": "tls_max_hosts_per_cidr",
            "adcs_ca_server": "adcs_ca_server",
            "adcs_ca_name": "adcs_ca_name",
            "listener_enabled": "listener_enabled",
            "listener_host": "listener_host",
            "listener_port": "listener_port",
            "listener_ssl_cert": "listener_ssl_cert",
            "listener_ssl_key": "listener_ssl_key",
            "listener_ssl_ca": "listener_ssl_ca",
            "log_level": "log_level",
        }

        for file_key, setting_key in field_mapping.items():
            if file_key in file_config:
                setattr(settings, setting_key, file_config[file_key])

    # Auto-detect agent name from hostname
    if not settings.agent_name:
        import socket
        settings.agent_name = socket.gethostname()

    # Ensure data directory exists
    Path(settings.data_dir).mkdir(parents=True, exist_ok=True)

    return settings


def save_agent_config(settings: AgentSettings, config_path: Optional[str] = None) -> None:
    """Persist agent settings to the JSON config file.

    Only saves persistent fields — NEVER runtime tokens (JWT/agent tokens
    stay in memory only; the agent re-registers with its PSK on restart).
    The PSK itself is the bootstrap secret and must be protected with file
    permissions (the install scripts set restrictive ACLs).
    """
    import json

    path = Path(config_path or "agent_config.json")

    data = {
        "api_url": settings.api_url,
        "psk": settings.psk,
        "agent_name": settings.agent_name,
        "agent_type": settings.agent_type,
        "datacenter_code": settings.datacenter_code,
        "agent_id": settings.agent_id,
        "poll_interval": settings.poll_interval,
        "local_db_path": settings.local_db_path,
        "tls_cidr_ranges": settings.tls_cidr_ranges,
        "tls_ports": settings.tls_ports,
        "tls_timeout": settings.tls_timeout,
        "tls_max_hosts_per_cidr": settings.tls_max_hosts_per_cidr,
        "adcs_ca_server": settings.adcs_ca_server,
        "adcs_ca_name": settings.adcs_ca_name,
        "listener_enabled": settings.listener_enabled,
        "listener_host": settings.listener_host,
        "listener_port": settings.listener_port,
        "listener_ssl_cert": settings.listener_ssl_cert,
        "listener_ssl_key": settings.listener_ssl_key,
        "listener_ssl_ca": settings.listener_ssl_ca,
        "log_level": settings.log_level,
    }

    with open(path, "w") as f:
        json.dump(data, f, indent=2)
