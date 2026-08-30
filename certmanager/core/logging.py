"""Structured logging configuration using structlog.

Following the entra-pentest logging pattern: JSON in production,
colored console output in development.
"""

from __future__ import annotations

import logging
import re
import sys

import structlog

from certmanager.core.config import get_settings

# Field names that may carry secrets — their values are scrubbed entirely
_SENSITIVE_FIELD_NAMES = {
    "password",
    "psk",
    "secret",
    "token",
    "api_key",
    "client_secret",
    "access_key",
    "secret_access_key",
    "authorization",
    "mfa_code",
    "recovery_code",
}

# Key=value-ish secret patterns that could appear inside message strings
_SECRET_VALUE_PATTERNS = [
    re.compile(r"(password|passwd|psk|secret|token|api_key|authorization)(=|:)\s*\S+", re.IGNORECASE),
    re.compile(r"Bearer\s+\S+", re.IGNORECASE),
]


def _redact(text: str) -> str:
    """Scrub secret-looking patterns from a rendered string."""
    for pattern in _SECRET_VALUE_PATTERNS:
        text = pattern.sub(lambda m: f"{m.group(1)}=[REDACTED]" if m.lastindex else "[REDACTED]", text)
    return text


def _redact_processor(logger, method_name, event_dict):
    """Structlog processor: strip sensitive fields from every log entry."""
    for key, value in list(event_dict.items()):
        if key.lower() in _SENSITIVE_FIELD_NAMES:
            event_dict[key] = "[REDACTED]"
        elif isinstance(value, str):
            event_dict[key] = _redact(value)
    return event_dict


def configure_logging() -> None:
    """Configure structlog and stdlib logging for the application.

    Called once at application startup (FastAPI lifespan or CLI entry point).
    """
    settings = get_settings()

    # Determine if we're rendering as JSON or console
    is_json = settings.log_format == "json"
    is_production = settings.environment == "production"

    # Shared processors
    shared_processors: list[structlog.typing.Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        _redact_processor,
        structlog.dev.ConsoleRenderer()
        if not is_json
        else structlog.processors.JSONRenderer(),
    ]

    # Configure structlog
    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            *shared_processors,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    # Configure stdlib logging to route through structlog
    level = getattr(logging, settings.log_level.upper(), logging.INFO)

    formatter = structlog.stdlib.ProcessorFormatter(
        foreign_pre_chain=[
            structlog.stdlib.add_log_level,
            structlog.stdlib.add_logger_name,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
        ],
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            _redact_processor,
            structlog.dev.ConsoleRenderer() if not is_json else structlog.processors.JSONRenderer(),
        ],
    )

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    root_logger.addHandler(handler)
    root_logger.setLevel(level)

    # Quiet noisy libraries
    for noisy in ("uvicorn.access", "botocore", "azure.core", "urllib3", "aiosqlite"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    if not is_production:
        logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)
