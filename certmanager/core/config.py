"""Central configuration via pydantic-settings.

All settings are loaded from environment variables with the CERTMGMT_ prefix,
following the same pattern as entra-pentest's config module.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class CORSSettings(BaseModel):
    origins: list[str] = Field(
        default_factory=lambda: ["http://localhost:5173", "http://localhost:3000"],
        description="Allowed CORS origins",
    )


class SecuritySettings(BaseModel):
    secret_key: str = Field(default="change-me-in-production", description="JWT signing secret")
    access_token_expire_minutes: int = Field(default=15, description="JWT access token TTL")
    refresh_token_expire_hours: int = Field(default=24, description="JWT refresh token TTL")
    encryption_key: str = Field(
        default="",
        description="Base64-encoded 32-byte AES-256 key for credential encryption",
    )
    bcrypt_rounds: int = Field(default=12, description="bcrypt hashing rounds")


class DatabaseSettings(BaseModel):
    url: str = Field(
        default="postgresql+asyncpg://certmanager:changeme@localhost:5432/certmanager",
        description="Async database URL (asyncpg driver)",
    )
    url_sync: str = Field(
        default="postgresql+psycopg2://certmanager:changeme@localhost:5432/certmanager",
        description="Sync database URL (for Alembic migrations)",
    )
    pool_size: int = Field(default=20, description="Connection pool size")
    pool_overflow: int = Field(default=10, description="Max overflow connections")
    pool_timeout: int = Field(default=30, description="Pool timeout in seconds")


class RedisSettings(BaseModel):
    url: str = Field(default="redis://localhost:6379/0", description="Redis connection URL")


class AgentSettings(BaseModel):
    psk: str = Field(default="", description="Pre-shared key for agent registration")
    api_url: str = Field(default="", description="Central API URL for agents")


class SMTPConfig(BaseModel):
    host: str = Field(default="localhost")
    port: int = Field(default=587)
    user: str = Field(default="")
    password: str = Field(default="")
    from_address: str = Field(default="CertManager <noreply@example.com>")
    use_tls: bool = Field(default=True)


class Settings(BaseSettings):
    """Root settings loaded from environment with CERTMGMT_ prefix."""

    model_config = SettingsConfigDict(
        env_prefix="CERTMGMT_",
        env_nested_delimiter="__",
        env_file=".env",
        case_sensitive=False,
        extra="ignore",
    )

    # Environment
    environment: str = Field(default="development", description="development | staging | production")

    # Sub-settings
    api_host: str = Field(default="0.0.0.0")
    api_port: int = Field(default=8000)
    cors: CORSSettings = Field(default_factory=CORSSettings)
    security: SecuritySettings = Field(default_factory=SecuritySettings)
    database: DatabaseSettings = Field(default_factory=DatabaseSettings)
    redis: RedisSettings = Field(default_factory=RedisSettings)
    agent: AgentSettings = Field(default_factory=AgentSettings)
    smtp: SMTPConfig = Field(default_factory=SMTPConfig)
    log_level: str = Field(default="INFO")
    log_format: str = Field(default="json")  # json | console

    @field_validator("environment")
    @classmethod
    def validate_environment(cls, v: str) -> str:
        allowed = {"development", "staging", "production"}
        if v not in allowed:
            raise ValueError(f"environment must be one of {allowed}, got {v}")
        return v

    @model_validator(mode="after")
    def reject_insecure_production_defaults(self) -> "Settings":
        """Refuse to boot production/staging with default secrets or dev DB credentials."""
        if self.environment == "development":
            return self
        problems: list[str] = []
        if self.security.secret_key == "change-me-in-production":
            problems.append("CERTMGMT_SECURITY__SECRET_KEY is the default value")
        if not self.security.encryption_key:
            problems.append("CERTMGMT_SECURITY__ENCRYPTION_KEY is not set")
        if "changeme" in self.database.url:
            problems.append("CERTMGMT_DATABASE__URL uses default credentials")
        if not self.agent.psk:
            problems.append("CERTMGMT_AGENT__PSK is not set")
        if problems:
            raise ValueError(
                f"Refusing to start in {self.environment!r} environment: " + "; ".join(problems)
            )
        return self


# Singleton instance
_settings: Settings | None = None


def get_settings() -> Settings:
    """Return the cached Settings singleton, creating it if needed."""
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings


def reload_settings() -> Settings:
    """Force reload settings from environment (useful in tests)."""
    global _settings
    _settings = Settings()
    return _settings
