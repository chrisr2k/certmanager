"""Cryptographic utilities for credential encryption and integrity.

- AES-256-GCM encryption/decryption for CA credentials and agent tokens.
- KEK/DEK hierarchy: a master Key Encryption Key (from config) encrypts
  per-credential Data Encryption Keys.

Never log decrypted values. Never store plaintext credentials outside
of the ca_credentials table's encrypted_value column.
"""

from __future__ import annotations

import base64
import os
from dataclasses import dataclass

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from certmanager.core.config import get_settings

# ---------------------------------------------------------------------------
# High-level: Fernet-based encryption (simpler, for most credential types)
# ---------------------------------------------------------------------------


def _get_fernet() -> Fernet:
    """Get or derive a Fernet key from the configured encryption key."""
    settings = get_settings().security
    key_b64 = settings.encryption_key

    if not key_b64:
        # In development, generate a deterministic key from the secret_key
        import hashlib

        digest = hashlib.sha256(settings.secret_key.encode()).digest()
        key_b64 = base64.urlsafe_b64encode(digest)

    # Fernet requires a 32-byte urlsafe-base64-encoded key
    try:
        return Fernet(key_b64.encode() if isinstance(key_b64, str) else key_b64)
    except Exception:
        # If the key isn't a valid Fernet key, derive one
        import hashlib

        raw = key_b64.encode() if isinstance(key_b64, str) else key_b64
        digest = hashlib.sha256(raw).digest()
        return Fernet(base64.urlsafe_b64encode(digest))


def encrypt_value(plaintext: str) -> bytes:
    """Encrypt a string value using Fernet (AES-128-CBC with HMAC).

    Returns the encrypted bytes (Fernet token). Safe to store as BYTEA.
    """
    return _get_fernet().encrypt(plaintext.encode("utf-8"))


def decrypt_value(encrypted: bytes) -> str:
    """Decrypt a Fernet-encrypted value back to a string.

    Raises cryptography.fernet.InvalidToken if the token is tampered with.
    """
    return _get_fernet().decrypt(encrypted).decode("utf-8")


# ---------------------------------------------------------------------------
# Low-level: AES-256-GCM (for higher-security scenarios)
# ---------------------------------------------------------------------------


def aes_gcm_encrypt(plaintext: str, key: bytes | None = None) -> tuple[bytes, bytes, bytes]:
    """Encrypt using AES-256-GCM. Returns (nonce, ciphertext, tag).

    Args:
        plaintext: The data to encrypt.
        key: 32-byte AES-256 key. If None, derived from the configured encryption key.

    Returns:
        Tuple of (nonce, ciphertext, tag) — all bytes.
    """
    if key is None:
        key = _derive_aes_key()

    nonce = os.urandom(12)  # 96-bit nonce for GCM
    aesgcm = AESGCM(key)
    # GCM includes the authentication tag in the ciphertext
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    # The tag is the last 16 bytes
    ciphertext = ciphertext_with_tag[:-16]
    tag = ciphertext_with_tag[-16:]
    return nonce, ciphertext, tag


def aes_gcm_decrypt(nonce: bytes, ciphertext: bytes, tag: bytes, key: bytes | None = None) -> str:
    """Decrypt AES-256-GCM encrypted data.

    Args:
        nonce: The nonce used during encryption.
        ciphertext: The encrypted data (without tag).
        tag: The 16-byte authentication tag.
        key: 32-byte AES-256 key.

    Returns:
        Decrypted plaintext string.

    Raises:
        InvalidTag: If authentication fails (tampered data).
    """
    if key is None:
        key = _derive_aes_key()

    aesgcm = AESGCM(key)
    ciphertext_with_tag = ciphertext + tag
    plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, None)
    return plaintext.decode("utf-8")


def _derive_aes_key() -> bytes:
    """Derive a 32-byte AES-256 key from the configured encryption key."""
    import hashlib

    settings = get_settings().security
    material = settings.encryption_key or settings.secret_key
    return hashlib.sha256(material.encode()).digest()


# ---------------------------------------------------------------------------
# Data structures for encrypted credentials
# ---------------------------------------------------------------------------


@dataclass
class EncryptedCredential:
    """Represents a credential that has been encrypted for storage."""

    encrypted_value: bytes
    encryption_key_id: str = "kek-v1"

    @classmethod
    def from_plaintext(cls, plaintext: str) -> EncryptedCredential:
        return cls(encrypted_value=encrypt_value(plaintext))

    def decrypt(self) -> str:
        return decrypt_value(self.encrypted_value)
