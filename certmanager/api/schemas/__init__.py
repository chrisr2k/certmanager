"""Pydantic v2 request/response schemas for the CertManager API.

All list responses follow a standard envelope:
    {
        "data": [...],
        "meta": {"page": 1, "page_size": 50, "total": 423},
        "errors": null,
        "correlation_id": "abc123"
    }
"""
