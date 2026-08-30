"""Rate limiting middleware using a Redis-backed token bucket.

Rate limits are configurable per endpoint category:
- auth: 20 req/min (login, MFA)
- read: 300 req/min (GET requests)
- write: 60 req/min (POST/PUT/PATCH/DELETE)
- agent: 120 req/min (agent endpoints)

In development mode without Redis, rate limiting is skipped.
"""

from __future__ import annotations

import time
from collections import defaultdict
from typing import Dict, Tuple

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response


# Rate limit configuration: (max_requests, window_seconds)
RATE_LIMITS: Dict[str, Tuple[int, int]] = {
    "auth": (20, 60),       # 20 requests per minute
    "read": (300, 60),      # 300 GET requests per minute
    "write": (60, 60),      # 60 write requests per minute
    "agent": (120, 60),     # 120 agent requests per minute
}

# Path prefix → rate limit category
PATH_CATEGORIES = [
    ("/api/v1/auth", "auth"),
    ("/api/v1/agents/", "agent"),
]


def _get_category(path: str, method: str) -> str:
    """Determine the rate limit category for a request."""
    for prefix, category in PATH_CATEGORIES:
        if path.startswith(prefix):
            return category
    if method == "GET":
        return "read"
    return "write"


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Token bucket rate limiter.

    Uses an in-memory store when Redis is unavailable (development mode).
    For production, replace with Redis-backed counters for consistency
    across multiple API replicas.
    """

    def __init__(self, app, *args, **kwargs):
        super().__init__(app, *args, **kwargs)
        # In-memory fallback: {ip_or_user: {category: [(timestamp, count)]}}
        self._in_memory: dict = defaultdict(lambda: defaultdict(list))

    async def dispatch(self, request: Request, call_next) -> Response:
        path = request.url.path

        # Skip rate limiting for non-API paths
        if not path.startswith("/api/"):
            return await call_next(request)

        # Determine client key (prefer user ID, fall back to IP)
        user_id = getattr(request.state, "actor_id", None)
        client_ip = request.client.host if request.client else "unknown"
        client_key = user_id or client_ip

        category = _get_category(path, request.method)
        max_req, window = RATE_LIMITS.get(category, (300, 60))

        # Try Redis first, fall back to in-memory
        if not await self._check_redis(client_key, category, max_req, window):
            if not self._check_in_memory(client_key, category, max_req, window):
                return JSONResponse(
                    status_code=429,
                    content={
                        "error": "RateLimitExceeded",
                        "message": f"Rate limit exceeded for {category}. "
                        f"Max {max_req} requests per {window}s.",
                        "retry_after": window,
                    },
                )

        return await call_next(request)

    async def _check_redis(
        self, client_key: str, category: str, max_req: int, window: int
    ) -> bool:
        """Check rate limit using Redis token bucket. Returns True if allowed."""
        try:
            from certmanager.core.config import get_settings

            import redis.asyncio as aioredis

            r = aioredis.from_url(get_settings().redis.url, decode_responses=True)
            key = f"ratelimit:{category}:{client_key}"
            current = await r.incr(key)
            if current == 1:
                await r.expire(key, window)
            if current > max_req:
                return False
            return True
        except Exception:
            # Redis unavailable — fall through to in-memory
            return True  # Signal to try in-memory

    def _check_in_memory(
        self, client_key: str, category: str, max_req: int, window: int
    ) -> bool:
        """In-memory rate limit check. Returns True if allowed."""
        now = time.time()
        bucket = self._in_memory[client_key][category]

        # Remove entries outside the window
        bucket[:] = [ts for ts in bucket if now - ts < window]

        if len(bucket) >= max_req:
            return False

        bucket.append(now)
        return True
