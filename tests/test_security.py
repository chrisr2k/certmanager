"""Tests for core security and crypto modules."""

import pytest
from jose import JWTError

from certmanager.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    verify_password,
)
from certmanager.core.crypto import encrypt_value, decrypt_value


class TestPasswordHashing:
    def test_hash_and_verify(self):
        password = "secure-password-123"
        hashed = hash_password(password)
        assert hashed != password
        assert verify_password(password, hashed)
        assert not verify_password("wrong-password", hashed)

    def test_hash_is_unique(self):
        password = "same-password"
        h1 = hash_password(password)
        h2 = hash_password(password)
        assert h1 != h2  # bcrypt generates unique salts
        assert verify_password(password, h1)
        assert verify_password(password, h2)


class TestJWT:
    def test_create_and_decode_access_token(self):
        token = create_access_token(subject="user-123")
        claims = decode_token(token)

        assert claims["sub"] == "user-123"
        assert claims["type"] == "access"
        assert "exp" in claims
        assert "jti" in claims

    def test_create_and_decode_refresh_token(self):
        token, family = create_refresh_token(subject="user-456")
        claims = decode_token(token)

        assert claims["sub"] == "user-456"
        assert claims["type"] == "refresh"
        assert claims["family"] == family

    def test_token_family_rotation(self):
        token1, family1 = create_refresh_token(subject="user-789")
        token2, family2 = create_refresh_token(
            subject="user-789", token_family=family1
        )

        assert family1 == family2
        assert token1 != token2  # Tokens are different even in same family

    def test_expired_token_rejected(self, monkeypatch):
        from datetime import datetime, timedelta, timezone

        token = create_access_token(
            subject="test", expires_delta=timedelta(seconds=-1)
        )
        with pytest.raises(JWTError):
            decode_token(token)

    def test_extra_claims_in_token(self):
        extra = {"email": "test@example.com", "roles": ["admin"], "permissions": ["certificates:read"]}
        token = create_access_token(subject="user-1", extra_claims=extra)
        claims = decode_token(token)

        assert claims["email"] == "test@example.com"
        assert claims["roles"] == ["admin"]
        assert claims["permissions"] == ["certificates:read"]


class TestCrypto:
    def test_encrypt_decrypt_roundtrip(self):
        plaintext = "my-secret-api-key-12345"
        encrypted = encrypt_value(plaintext)
        assert encrypted != plaintext.encode()
        decrypted = decrypt_value(encrypted)
        assert decrypted == plaintext

    def test_encrypt_produces_different_output(self):
        plaintext = "same-secret"
        e1 = encrypt_value(plaintext)
        e2 = encrypt_value(plaintext)
        assert e1 != e2  # Fernet uses random IV
        assert decrypt_value(e1) == plaintext
        assert decrypt_value(e2) == plaintext

    def test_decrypt_invalid_data_raises(self):
        import cryptography.fernet

        with pytest.raises(cryptography.fernet.InvalidToken):
            decrypt_value(b"not-valid-encrypted-data")
