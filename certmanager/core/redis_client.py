"""Shared Redis client with unavailability backoff.

Redis is optional at runtime (dev machines often have none running), but a
naive per-call connection attempt costs the full connect timeout. This
helper caches one client and, after a failed connection, marks Redis
unavailable for BACKOFF_SECONDS so hot paths (rate limiting, refresh
families) degrade to their in-memory fallbacks instantly instead of
stalling every request.
"""

from __future__ import annotations

import time

_client: object | None = None
_creation_failed = False
_available = True
_last_failure: float = 0.0

BACKOFF_SECONDS = 60.0
PING_TIMEOUT = 1.5


def _get_client() -> object | None:
    """Get (or lazily create) the shared Redis client.

    Returns None if Redis was marked unavailable within the backoff window.
    """
    global _client, _creation_failed, _available, _last_failure

    if not _available and time.time() - _last_failure < BACKOFF_SECONDS:
        return None

    if _client is None and not _creation_failed:
        try:
            import redis.asyncio as aioredis

            from certmanager.core.config import get_settings

            _client = aioredis.from_url(
                get_settings().redis.url,
                decode_responses=True,
                socket_connect_timeout=PING_TIMEOUT,
                socket_timeout=PING_TIMEOUT,
            )
        except Exception:
            _creation_failed = True
            _available = False
            _last_failure = time.time()
            return None
    return _client


async def get_redis() -> object | None:
    """Return a verified-reachable Redis client, or None on unavailability."""
    global _available, _last_failure

    client = _get_client()
    if client is None:
        return None

    try:
        await client.ping()
        _available = True
        return client
    except Exception:
        # Connection failed — mark unavailable and back off
        _available = False
        _last_failure = time.time()
        return None


def reset_for_tests() -> None:
    """Reset cached state (used by the test suite)."""
    global _client, _creation_failed, _available, _last_failure
    _client = None
    _creation_failed = False
    _available = True
    _last_failure = 0.0
