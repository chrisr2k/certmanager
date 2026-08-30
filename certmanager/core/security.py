"""Authentication and authorization security primitives.

- JWT creation and validation (access + refresh tokens)
- Password hashing (bcrypt via passlib)
- Refresh token family management (for rotation + reuse detection)
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from jose import JWTError, jwt
from passlib.context import CryptContext

from certmanager.core.config import get_settings

# --- Password hashing ---
_pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    """Hash a plain-text password with bcrypt."""
    return _pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plain-text password against a bcrypt hash."""
    return _pwd_context.verify(plain_password, hashed_password)


# --- JWT ---
ALGORITHM = "HS256"


def _get_secret_key() -> str:
    return get_settings().security.secret_key


def create_access_token(
    subject: str,
    extra_claims: dict[str, Any] | None = None,
    expires_delta: timedelta | None = None,
) -> str:
    """Create a JWT access token.

    Args:
        subject: Usually the user's UUID string.
        extra_claims: Additional claims to include (e.g., roles, permissions).
        expires_delta: Override the default expiration time.

    Returns:
        Encoded JWT string.
    """
    settings = get_settings().security
    if expires_delta is None:
        expires_delta = timedelta(minutes=settings.access_token_expire_minutes)

    now = datetime.now(UTC)
    claims: dict[str, Any] = {
        "sub": subject,
        "iat": now,
        "exp": now + expires_delta,
        "jti": uuid.uuid4().hex,
        "type": "access",
    }
    if extra_claims:
        claims.update(extra_claims)

    return jwt.encode(claims, _get_secret_key(), algorithm=ALGORITHM)


def create_refresh_token(
    subject: str,
    token_family: str | None = None,
    expires_delta: timedelta | None = None,
) -> tuple[str, str]:
    """Create a JWT refresh token with token family for rotation.

    Token families enable refresh token reuse detection:
    if a token from the same family is used twice, the entire family
    is revoked (indicating a stolen refresh token).

    Args:
        subject: Usually the user's UUID string.
        token_family: Existing family ID to rotate within. If None, a new family is created.
        expires_delta: Override the default expiration time.

    Returns:
        Tuple of (encoded_jwt, token_family_id).
    """
    settings = get_settings().security
    if expires_delta is None:
        expires_delta = timedelta(hours=settings.refresh_token_expire_hours)

    if token_family is None:
        token_family = uuid.uuid4().hex

    now = datetime.now(UTC)
    claims: dict[str, Any] = {
        "sub": subject,
        "iat": now,
        "exp": now + expires_delta,
        "jti": uuid.uuid4().hex,
        "type": "refresh",
        "family": token_family,
    }

    return jwt.encode(claims, _get_secret_key(), algorithm=ALGORITHM), token_family


def decode_token(token: str) -> dict[str, Any]:
    """Decode and validate a JWT token. Raises JWTError on failure."""
    return jwt.decode(token, _get_secret_key(), algorithms=[ALGORITHM])


def get_token_type(token: str) -> str:
    """Extract the token type (access/refresh) without full validation."""
    try:
        # Decode without verification just to read type claim
        claims = jwt.decode(
            token, _get_secret_key(), algorithms=[ALGORITHM], options={"verify_exp": True}
        )
        return claims.get("type", "unknown")
    except JWTError:
        return "invalid"
