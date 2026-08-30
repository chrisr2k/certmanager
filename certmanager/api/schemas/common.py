"""Common Pydantic schemas: pagination, error envelope, shared fields."""

from __future__ import annotations

from datetime import datetime
from typing import TypeVar

from pydantic import BaseModel, Field

T = TypeVar("T")


class PaginationParams(BaseModel):
    """Query parameters for paginated list endpoints."""

    page: int = Field(default=1, ge=1, description="Page number (1-indexed)")
    page_size: int = Field(default=50, ge=1, le=250, description="Items per page")


class PaginationMeta(BaseModel):
    """Metadata returned with paginated responses."""

    page: int
    page_size: int
    total: int
    total_pages: int


class ErrorDetail(BaseModel):
    """A single error in a validation or error response."""

    field: str | None = None
    message: str
    code: str | None = None


class APIResponse[T](BaseModel):
    """Standard API response envelope."""

    data: T | None = None
    meta: PaginationMeta | None = None
    errors: list[ErrorDetail] | None = None
    correlation_id: str | None = None


class TimestampedSchema(BaseModel):
    """Mixin for schemas with timestamps."""

    created_at: datetime
    updated_at: datetime
