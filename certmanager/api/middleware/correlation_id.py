"""Correlation ID middleware.

Injects a unique X-Correlation-ID header into every request/response cycle.
If the client provides one, it is preserved. Otherwise, a new UUID is generated.
The correlation ID is added to the structlog context for all log entries during
the request lifecycle.
"""

from __future__ import annotations

import uuid

import structlog
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

CORRELATION_ID_HEADER = "X-Correlation-ID"


class CorrelationIDMiddleware(BaseHTTPMiddleware):
    """Inject and propagate correlation IDs for request tracing."""

    async def dispatch(self, request: Request, call_next) -> Response:
        # Use existing or generate new correlation ID
        correlation_id = request.headers.get(CORRELATION_ID_HEADER) or uuid.uuid4().hex

        # Bind to structlog context so all log calls in this request include it
        structlog.contextvars.bind_contextvars(correlation_id=correlation_id)

        # Attach to request state for downstream access
        request.state.correlation_id = correlation_id

        # Process request
        response: Response = await call_next(request)

        # Echo back in response header
        response.headers[CORRELATION_ID_HEADER] = correlation_id

        # Clean up structlog context
        structlog.contextvars.unbind_contextvars("correlation_id")

        return response
