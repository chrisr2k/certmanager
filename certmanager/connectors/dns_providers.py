"""DNS-01 challenge providers for ACME domain validation.

A DNS-01 challenge is answered by publishing a short-lived TXT record at
`_acme-challenge.<domain>` and asking the ACME server to check it. This
module abstracts "create/delete that TXT record" behind a small provider
interface so a second provider (Route53, etc.) is a clean addition later —
v1 ships Cloudflare only, per the platform's existing Cloudflare-based
DNS/tunnel setup.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

import httpx
import structlog

from certmanager.connectors.base import ConnectorAuthError, ConnectorConfigError

logger = structlog.get_logger()

CLOUDFLARE_API_BASE = "https://api.cloudflare.com/client/v4"


class DNSChallengeProvider(ABC):
    """Abstract interface for publishing/removing ACME DNS-01 TXT records."""

    @abstractmethod
    async def create_txt_record(self, domain: str, value: str) -> str:
        """Create a `_acme-challenge.<domain>` TXT record with the given value.

        Returns:
            A provider-native record ID, passed back to delete_txt_record.
        """

    @abstractmethod
    async def delete_txt_record(self, domain: str, record_id: str) -> None:
        """Delete a previously created TXT record. Must not raise on
        "already gone" — callers invoke this from cleanup paths, including
        after failures, and a missing record is not itself an error."""


class CloudflareDNSProvider(DNSChallengeProvider):
    """Publishes ACME DNS-01 TXT records via the Cloudflare API.

    Requires an API token with Zone:DNS:Edit permission on the zone(s)
    covering the domains being validated. If `zone_id` isn't configured,
    the zone is resolved per-domain from its registrable domain (the last
    two labels, e.g. `example.com` for `www.example.com`) via Cloudflare's
    `GET /zones?name=` lookup.
    """

    def __init__(self, api_token: str, zone_id: str | None = None):
        self.api_token = api_token
        self._zone_id_override = zone_id
        self._zone_cache: dict[str, str] = {}

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.api_token}", "Content-Type": "application/json"}

    async def _resolve_zone_id(self, domain: str) -> str:
        """Resolve the Cloudflare zone ID covering `domain`."""
        if self._zone_id_override:
            return self._zone_id_override

        registrable = ".".join(domain.rstrip(".").split(".")[-2:])
        if registrable in self._zone_cache:
            return self._zone_cache[registrable]

        async with httpx.AsyncClient(timeout=15.0) as http:
            resp = await http.get(
                f"{CLOUDFLARE_API_BASE}/zones",
                params={"name": registrable},
                headers=self._headers(),
            )
        if resp.status_code in (401, 403):
            raise ConnectorAuthError(
                f"Cloudflare API token rejected while resolving zone for '{registrable}' "
                f"(HTTP {resp.status_code}) — check the token's Zone:DNS:Edit permission"
            )
        resp.raise_for_status()
        results = resp.json().get("result", [])
        if not results:
            raise ConnectorConfigError(
                f"No Cloudflare zone found for '{registrable}' — is this domain managed "
                "in the Cloudflare account the API token belongs to?"
            )
        zone_id = results[0]["id"]
        self._zone_cache[registrable] = zone_id
        return zone_id

    async def create_txt_record(self, domain: str, value: str) -> str:
        zone_id = await self._resolve_zone_id(domain)
        record_name = f"_acme-challenge.{domain}"

        async with httpx.AsyncClient(timeout=15.0) as http:
            resp = await http.post(
                f"{CLOUDFLARE_API_BASE}/zones/{zone_id}/dns_records",
                headers=self._headers(),
                json={"type": "TXT", "name": record_name, "content": value, "ttl": 60},
            )
        if resp.status_code in (401, 403):
            raise ConnectorAuthError(
                f"Cloudflare API token rejected creating TXT record for '{record_name}' "
                f"(HTTP {resp.status_code})"
            )
        resp.raise_for_status()
        body = resp.json()
        if not body.get("success"):
            raise ConnectorConfigError(f"Cloudflare rejected TXT record creation: {body.get('errors')}")

        record_id = body["result"]["id"]
        logger.info("cloudflare_txt_record_created", domain=domain, record_id=record_id)
        return record_id

    async def delete_txt_record(self, domain: str, record_id: str) -> None:
        try:
            zone_id = await self._resolve_zone_id(domain)
        except Exception as e:
            logger.warning("cloudflare_txt_cleanup_zone_lookup_failed", domain=domain, error=str(e))
            return

        async with httpx.AsyncClient(timeout=15.0) as http:
            resp = await http.delete(
                f"{CLOUDFLARE_API_BASE}/zones/{zone_id}/dns_records/{record_id}",
                headers=self._headers(),
            )
        # 404 means it's already gone — not an error for a cleanup path.
        if resp.status_code not in (200, 404):
            logger.warning(
                "cloudflare_txt_cleanup_failed",
                domain=domain,
                record_id=record_id,
                status=resp.status_code,
            )
        else:
            logger.info("cloudflare_txt_record_deleted", domain=domain, record_id=record_id)
