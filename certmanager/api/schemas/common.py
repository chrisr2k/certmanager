"""Common Pydantic schemas: pagination, error envelope, shared fields."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Generic, Optional, TypeVar

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

    field: Optional[str] = None
    message: str
    code: Optional[str] = None


class APIResponse(BaseModel, Generic[T]):
    """Standard API response envelope."""

    data: Optional[T] = None
    meta: Optional[PaginationMeta] = None
    errors: Optional[list[ErrorDetail]] = None
    correlation_id: Optional[str] = None


class TimestampedSchema(BaseModel):
    """Mixin for schemas with timestamps."""

    created_at: datetime
    updated_at: datetime
