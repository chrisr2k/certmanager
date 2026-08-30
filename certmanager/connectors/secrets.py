"""Encryption-at-rest for sensitive CA config values.

CA connector configs live in CertificateAuthority.config (JSONB). Keys that
hold credentials (client_secret, external_id, agent tokens, ...) are
encrypted with the platform encryption key (Fernet) before the config row
is written, and decrypted when the connector factory reads it.

Encrypted values are stored as {"__enc": "<base64 fernet token>"} so the
storage format is self-describing and idempotent.
"""

from __future__ import annotations

import base64

import structlog

from certmanager.core.crypto import decrypt_value, encrypt_value

logger = structlog.get_logger()

# Config keys that must never be stored in plaintext
SENSITIVE_KEYS = {
    "client_secret",
    "external_id",
    "api_token",
    "agent_token",
    "psk",
    "password",
    "access_key",
    "secret_access_key",
}

_ENCRYPTED_MARKER = "__enc"


def encrypt_sensitive_values(config: dict) -> dict:
    """Return a copy of config with sensitive values encrypted.

    Idempotent: values already in {"__enc": ...} form are left untouched.
    """
    if not config:
        return config

    encrypted = {}
    for key, value in config.items():
        if key.lower() in SENSITIVE_KEYS and isinstance(value, str) and value:
            if not (isinstance(value, dict) and _ENCRYPTED_MARKER in value):
                token = encrypt_value(value)
                encrypted[key] = {_ENCRYPTED_MARKER: base64.b64encode(token).decode()}
                continue
        encrypted[key] = value
    return encrypted


def decrypt_sensitive_values(config: dict) -> dict:
    """Return a copy of config with encrypted sensitive values decrypted.

    Decryption failures are logged and the value is replaced with an empty
    string so the connector can surface a clear auth error instead of
    crashing on ciphertext.
    """
    if not config:
        return config

    decrypted = {}
    for key, value in config.items():
        if (
            isinstance(value, dict)
            and _ENCRYPTED_MARKER in value
            and isinstance(value[_ENCRYPTED_MARKER], str)
        ):
            try:
                token = base64.b64decode(value[_ENCRYPTED_MARKER])
                decrypted[key] = decrypt_value(token)
                continue
            except Exception:
                logger.warning(
                    "credential_decrypt_failed",
                    key=key,
                    message="Returning empty value — the stored credential cannot be decrypted "
                    "with the configured encryption key",
                )
                decrypted[key] = ""
                continue
        decrypted[key] = value
    return decrypted


def redact_for_display(config: dict) -> dict:
    """Return a copy of config safe for API responses and logs."""
    if not config:
        return config
    return {
        key: ("[REDACTED]" if key.lower() in SENSITIVE_KEYS else value)
        for key, value in config.items()
    }
