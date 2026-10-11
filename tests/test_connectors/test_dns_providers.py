"""CloudflareDNSProvider tests — zone resolution and TXT create/delete,
with httpx mocked via MockTransport (no real network calls)."""

from __future__ import annotations

import httpx
import pytest

from certmanager.connectors.base import ConnectorAuthError, ConnectorConfigError
from certmanager.connectors.dns_providers import CloudflareDNSProvider

_RealAsyncClient = httpx.AsyncClient


def _mock_client_factory(handler):
    """Patch httpx.AsyncClient so every `async with httpx.AsyncClient(...)`
    inside the provider routes through a MockTransport handler."""

    def _factory(*args, **kwargs):
        kwargs.pop("timeout", None)
        return _RealAsyncClient(transport=httpx.MockTransport(handler))

    return _factory


async def test_resolve_zone_id_from_domain(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.params["name"] == "example.com"
        return httpx.Response(200, json={"success": True, "result": [{"id": "zone-123"}]})

    monkeypatch.setattr(httpx, "AsyncClient", _mock_client_factory(handler))

    provider = CloudflareDNSProvider(api_token="tok")
    zone_id = await provider._resolve_zone_id("www.example.com")
    assert zone_id == "zone-123"
    # Cached on the registrable domain for subsequent calls
    assert provider._zone_cache["example.com"] == "zone-123"


async def test_resolve_zone_id_uses_override(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("should not call the API when zone_id is overridden")

    monkeypatch.setattr(httpx, "AsyncClient", _mock_client_factory(handler))

    provider = CloudflareDNSProvider(api_token="tok", zone_id="explicit-zone")
    zone_id = await provider._resolve_zone_id("example.com")
    assert zone_id == "explicit-zone"


async def test_resolve_zone_id_no_zone_found_raises_config_error(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"success": True, "result": []})

    monkeypatch.setattr(httpx, "AsyncClient", _mock_client_factory(handler))

    provider = CloudflareDNSProvider(api_token="tok")
    with pytest.raises(ConnectorConfigError, match="No Cloudflare zone found"):
        await provider._resolve_zone_id("unmanaged.example")


async def test_resolve_zone_id_auth_error(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, json={"success": False})

    monkeypatch.setattr(httpx, "AsyncClient", _mock_client_factory(handler))

    provider = CloudflareDNSProvider(api_token="bad-token")
    with pytest.raises(ConnectorAuthError):
        await provider._resolve_zone_id("example.com")


async def test_create_txt_record(monkeypatch):
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append((request.method, str(request.url)))
        if request.method == "GET":
            return httpx.Response(200, json={"success": True, "result": [{"id": "zone-1"}]})
        assert "/zones/zone-1/dns_records" in str(request.url)
        return httpx.Response(200, json={"success": True, "result": {"id": "record-1"}})

    monkeypatch.setattr(httpx, "AsyncClient", _mock_client_factory(handler))

    provider = CloudflareDNSProvider(api_token="tok")
    record_id = await provider.create_txt_record("example.com", "validation-value")
    assert record_id == "record-1"
    assert any(m == "POST" for m, _ in calls)


async def test_create_txt_record_failure_raises(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, json={"success": True, "result": [{"id": "zone-1"}]})
        return httpx.Response(200, json={"success": False, "errors": ["bad request"]})

    monkeypatch.setattr(httpx, "AsyncClient", _mock_client_factory(handler))

    provider = CloudflareDNSProvider(api_token="tok", zone_id="zone-1")
    with pytest.raises(ConnectorConfigError, match="rejected TXT record"):
        await provider.create_txt_record("example.com", "value")


async def test_delete_txt_record_tolerates_404(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404)

    monkeypatch.setattr(httpx, "AsyncClient", _mock_client_factory(handler))

    provider = CloudflareDNSProvider(api_token="tok", zone_id="zone-1")
    # Must not raise — a missing record on cleanup is not an error.
    await provider.delete_txt_record("example.com", "already-gone")


async def test_delete_txt_record_success(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "DELETE"
        return httpx.Response(200, json={"success": True})

    monkeypatch.setattr(httpx, "AsyncClient", _mock_client_factory(handler))

    provider = CloudflareDNSProvider(api_token="tok", zone_id="zone-1")
    await provider.delete_txt_record("example.com", "record-1")
