"""Unit tests for security primitives, crypto, config, and credential encryption."""

from __future__ import annotations

import pytest

from certmanager.core import security
from certmanager.core.config import reload_settings
from certmanager.connectors.secrets import (
    decrypt_sensitive_values,
    encrypt_sensitive_values,
    redact_for_display,
)


class TestPasswordHashing:
    def test_hash_and_verify(self):
        hashed = security.hash_password("s3cret-password")
        assert hashed != "s3cret-password"
        assert security.verify_password("s3cret-password", hashed) is True
        assert security.verify_password("wrong", hashed) is False

    def test_verify_malformed_hash_returns_false(self):
        assert security.verify_password("x", "not-a-bcrypt-hash") is False


class TestRefreshFamilyStore:
    async def test_rotate_and_reuse_detection(self):
        family = "fam-1"
        await security.rotate_refresh_family(family, "jti-1", 3600)

        # Current token still valid
        assert await security.verify_refresh_family(family, "jti-1") is True

        # Rotate to jti-2
        await security.rotate_refresh_family(family, "jti-2", 3600)

        # Old jti now signals reuse → family revoked
        assert await security.verify_refresh_family(family, "jti-1") is False
        # And the new one is dead too (whole family revoked)
        assert await security.verify_refresh_family(family, "jti-2") is False

    async def test_revoke_family(self):
        family = "fam-2"
        await security.rotate_refresh_family(family, "jti-1", 3600)
        await security.revoke_refresh_family(family)
        assert await security.verify_refresh_family(family, "jti-1") is False


class TestCredentialEncryption:
    def test_roundtrip(self):
        config = {
            "vault_url": "https://vault.vault.azure.net/",
            "tenant_id": "tenant-123",
            "client_id": "client-123",
            "client_secret": "super-secret-value",
            "regions": ["us-east-1"],
        }
        encrypted = encrypt_sensitive_values(config)
        assert encrypted["client_secret"] != "super-secret-value"
        assert isinstance(encrypted["client_secret"], dict)
        assert "__enc" in encrypted["client_secret"]
        # Non-sensitive values untouched
        assert encrypted["vault_url"] == config["vault_url"]
        assert encrypted["regions"] == config["regions"]

        decrypted = decrypt_sensitive_values(encrypted)
        assert decrypted == config

    def test_encryption_is_idempotent(self):
        config = {"client_secret": "s3cret"}
        once = encrypt_sensitive_values(config)
        twice = encrypt_sensitive_values(once)
        assert twice == once

    def test_redact_for_display(self):
        config = {"vault_url": "https://v", "client_secret": "s3cret", "api_token": "tok"}
        redacted = redact_for_display(config)
        assert redacted["client_secret"] == "[REDACTED]"
        assert redacted["api_token"] == "[REDACTED]"
        assert redacted["vault_url"] == "https://v"

    def test_decrypt_bad_token_returns_empty(self):
        config = {"client_secret": {"__enc": "not-valid-base64-token"}}
        decrypted = decrypt_sensitive_values(config)
        assert decrypted["client_secret"] == ""


class TestConfigContract:
    def test_nested_env_vars_are_parsed(self, monkeypatch):
        monkeypatch.setenv("CERTMGMT_SECURITY__SECRET_KEY", "env-secret")
        monkeypatch.setenv("CERTMGMT_DATABASE__URL", "postgresql+asyncpg://x")
        monkeypatch.setenv("CERTMGMT_AGENT__PSK", "env-psk")
        settings = reload_settings()
        assert settings.security.secret_key == "env-secret"
        assert settings.database.url == "postgresql+asyncpg://x"
        assert settings.agent.psk == "env-psk"

    def test_production_guard_rejects_defaults(self, monkeypatch):
        monkeypatch.setenv("CERTMGMT_ENVIRONMENT", "production")
        with pytest.raises(ValueError):
            reload_settings()

    def test_production_guard_passes_with_secrets(self, monkeypatch):
        import base64
        import os

        monkeypatch.setenv("CERTMGMT_ENVIRONMENT", "production")
        monkeypatch.setenv("CERTMGMT_SECURITY__SECRET_KEY", "a" * 64)
        monkeypatch.setenv(
            "CERTMGMT_SECURITY__ENCRYPTION_KEY",
            base64.b64encode(os.urandom(32)).decode(),
        )
        monkeypatch.setenv("CERTMGMT_DATABASE__URL", "postgresql+asyncpg://user:real@db:5432/app")
        monkeypatch.setenv("CERTMGMT_AGENT__PSK", "real-psk")
        settings = reload_settings()
        assert settings.environment == "production"
