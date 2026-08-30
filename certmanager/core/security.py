"""Authentication and authorization security primitives.

- JWT creation and validation (access + refresh tokens)
- Password hashing (bcrypt directly — passlib 1.7.4 is unmaintained)
- Refresh token family management (for rotation + reuse detection),
  backed by Redis when available with an in-memory fallback
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import bcrypt
from jose import JWTError, jwt

from certmanager.core.config import get_settings

# --- Password hashing ---


def hash_password(password: str) -> str:
    """Hash a plain-text password with bcrypt."""
    rounds = get_settings().security.bcrypt_rounds
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=rounds)).decode()


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plain-text password against a bcrypt hash."""
    try:
        return bcrypt.checkpw(plain_password.encode(), hashed_password.encode())
    except ValueError:
        # Malformed hash in DB — treat as mismatch, never raise
        return False


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


# --- Refresh token family store (rotation + reuse detection) ---

_IN_MEMORY_FAMILIES: dict[str, str] = {}  # family -> current valid jti


def _redis() -> Any | None:
    """Return a Redis client if Redis is reachable, else None."""
    try:
        import redis.asyncio as aioredis

        return aioredis.from_url(
            get_settings().redis.url, decode_responses=True, socket_connect_timeout=2
        )
    except Exception:
        return None


def _family_key(family: str) -> str:
    return f"certmgmt:refresh:{family}"


async def rotate_refresh_family(family: str, new_jti: str, ttl_seconds: int) -> str:
    """Rotate a refresh family: old jti becomes invalid, new jti is current.

    Raises:
        TokenReuseError: if the family is already revoked (reuse detected).
    """
    from certmanager.core.exceptions import TokenReuseError

    client = _redis()
    if client is not None:
        try:
            # GET (existence check) and SET are not atomic here, so use a
            # small Lua-free approach: watch for a "revoked" marker.
            current = await client.get(_family_key(family))
            if current == "REVOKED":
                raise TokenReuseError("Refresh token family has been revoked")
            await client.set(_family_key(family), new_jti, ex=ttl_seconds)
            await client.aclose()
            return new_jti
        except TokenReuseError:
            if client is not None:
                await client.aclose()
            raise
        except Exception:
            # Fall through to in-memory store
            pass

    if _IN_MEMORY_FAMILIES.get(family) == "REVOKED":
        raise TokenReuseError("Refresh token family has been revoked")
    _IN_MEMORY_FAMILIES[family] = new_jti
    return new_jti


async def verify_refresh_family(family: str, presented_jti: str) -> bool:
    """Check that the presented jti is the CURRENT token of its family.

    If a previously-rotated (stolen) token is presented, the whole family
    is revoked and False is returned.
    """
    from certmanager.core.exceptions import TokenReuseError

    client = _redis()
    if client is not None:
        try:
            current = await client.get(_family_key(family))
            await client.aclose()
            if current == "REVOKED":
                return False
            if current is not None and current != presented_jti:
                # Reuse of an old token — revoke the family
                await revoke_refresh_family(family)
                return False
            return True
        except Exception:
            pass

    current = _IN_MEMORY_FAMILIES.get(family)
    if current == "REVOKED":
        return False
    if current is not None and current != presented_jti:
        await revoke_refresh_family(family)
        return False
    return True


async def revoke_refresh_family(family: str) -> None:
    """Revoke an entire refresh token family (logout / reuse detection)."""
    client = _redis()
    if client is not None:
        try:
            # Keep the REVOKED marker for the remainder of the token TTL
            ttl = int(get_settings().security.refresh_token_expire_hours * 3600)
            await client.set(_family_key(family), "REVOKED", ex=ttl)
            await client.aclose()
            return
        except Exception:
            pass

    _IN_MEMORY_FAMILIES[family] = "REVOKED"
