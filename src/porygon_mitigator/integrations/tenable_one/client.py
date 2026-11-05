"""Tenable VM / Tenable One API client. `asset_with_findings` is checked against the partner lab tenant (2026-11-03);
the inventory search is still unverified.

Uses the bulk export endpoints the standard Tenable integrations use:
    POST /assets/v2/export -> GET /assets/export/{uuid}/status -> GET /assets/export/{uuid}/chunks/{n}
    POST /vulns/export     -> GET /vulns/export/{uuid}/status  -> GET /vulns/export/{uuid}/chunks/{n}
and GET /assets/{uuid} for one asset. Everything here only reads. The one write path is `flow/tenable.py`, behind a
person's explicit flag.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from typing import Any

from porygon_mitigator.integrations.tenable_one.config import TenableConfig
from porygon_mitigator.sources.net import FetchError, Http

POLL_SECONDS = 5.0
MAX_POLLS = 360  # 30 minutes
FINISHED = "FINISHED"
FAILED = {"ERROR", "CANCELLED"}
# Export chunks are far bigger than advisory pages: about 0.6 MB per asset on a scanned server.
EXPORT_MAX_BYTES = 128 * 1024 * 1024
EXPORT_TIMEOUT = 120.0
ASSETS_PER_CHUNK = 50


def tenable_http() -> Http:
    """An HTTP client sized for Tenable export chunks."""
    return Http(max_bytes=EXPORT_MAX_BYTES, timeout=EXPORT_TIMEOUT)

# Plugins whose output describes the machine rather than a vulnerability (see plugin_outputs.py).
ENRICHMENT_PLUGIN_IDS = (22869, 20811, 83991, 25221, 34252, 10456, 44401, 110483, 70329)


class TenableError(RuntimeError):
    pass


class TenableOneClient:
    def __init__(self, http: Http, config: TenableConfig | None = None) -> None:
        self.http = http
        self.config = config or TenableConfig()
        if not self.config.configured:
            raise TenableError("set TENABLE_ACCESS_KEY and TENABLE_SECRET_KEY to use the Tenable integration")

    def _url(self, path: str) -> str:
        return self.config.base_url.rstrip("/") + path

    async def _export(self, kind: str, body: dict[str, Any], create_path: str) -> AsyncIterator[dict[str, Any]]:
        created = await self.http.post_json(self._url(create_path), body, headers=self.config.headers())
        export_uuid = str(created.get("export_uuid") or "") if isinstance(created, dict) else ""
        if not export_uuid:
            raise TenableError(f"{kind} export did not return an export_uuid")
        served: set[int] = set()
        for _ in range(MAX_POLLS):
            status = await self.http.get_json(self._url(f"/{kind}/export/{export_uuid}/status"),
                                              headers=self.config.headers())
            if not isinstance(status, dict):
                raise TenableError(f"{kind} export {export_uuid} returned an unreadable status")
            state = str(status.get("status") or "")
            if state in FAILED:
                raise TenableError(f"{kind} export {export_uuid} ended with {state}")
            lost = (status.get("chunks_failed") or []) + (status.get("chunks_cancelled") or [])
            if lost:
                raise TenableError(f"{kind} export {export_uuid} lost chunks {lost}; the data would be incomplete")
            for chunk_id in sorted(set(status.get("chunks_available") or []) - served):
                served.add(chunk_id)
                rows = await self.http.get_json(self._url(f"/{kind}/export/{export_uuid}/chunks/{chunk_id}"),
                                                headers=self.config.headers())
                if not isinstance(rows, list):
                    raise TenableError(f"{kind} export {export_uuid} chunk {chunk_id} is not a list of rows")
                for row in rows:
                    if isinstance(row, dict):
                        yield row
            if state == FINISHED:
                return
            await asyncio.sleep(POLL_SECONDS)
        raise TenableError(f"{kind} export {export_uuid} did not finish in time")

    async def export_assets(self, filters: dict[str, Any] | None = None,
                            chunk_size: int = 1000) -> AsyncIterator[dict[str, Any]]:
        body: dict[str, Any] = {"chunk_size": chunk_size}
        if filters:
            body["filters"] = filters
        async for row in self._export("assets", body, "/assets/v2/export"):
            yield row

    async def export_vulns(self, filters: dict[str, Any] | None = None,
                           num_assets: int = 500) -> AsyncIterator[dict[str, Any]]:
        body: dict[str, Any] = {"num_assets": num_assets,
                                "filters": {"state": ["OPEN", "REOPENED", "FIXED"], **(filters or {})}}
        async for row in self._export("vulns", body, "/vulns/export"):
            yield row

    async def open_findings(self, cidr: str | None = None) -> list[dict[str, Any]]:
        """Every open or reopened finding in the tenant, or only on assets inside `cidr` (e.g. 10.0.48.0/22)."""
        filters: dict[str, Any] = {"state": ["OPEN", "REOPENED"]}
        if cidr:
            filters["cidr_range"] = cidr
        return [row async for row in self.export_vulns(filters=filters, num_assets=ASSETS_PER_CHUNK)]

    async def asset_with_findings(self, asset_id: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        """One asset and its findings (vulnerabilities plus the enrichment plugins). Neither export accepts an asset
        UUID filter, so the asset comes from GET /assets/{uuid} and its findings from a vuln export scoped to its
        IPv4 address, keeping only rows whose asset UUID matches."""
        try:
            data = await self.http.get_json(self._url(f"/assets/{asset_id}"), headers=self.config.headers())
        except FetchError as error:
            raise TenableError(f"asset {asset_id}: {error}") from error
        asset = (data.get("info") or data) if isinstance(data, dict) else None
        if not isinstance(asset, dict) or str(asset.get("id")) != asset_id:
            raise TenableError(f"asset {asset_id} not found")
        addresses = [str(item) for item in asset.get("ipv4") or asset.get("ipv4s") or [] if item]
        if not addresses:
            raise TenableError(f"asset {asset_id} has no IPv4 address to scope its findings export")
        findings = [row async for row in self.export_vulns(filters={"cidr_range": f"{addresses[0]}/32"})
                    if str((row.get("asset") or {}).get("uuid") or "") == asset_id]
        return asset, findings

    async def scan_inventory(self) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """Every asset and every open finding, including the informational rows the coverage report reads. Give this
        client `tenable_http()`: the default cap is sized for web pages."""
        assets = [row async for row in self.export_assets()]
        findings = [row async for row in self.export_vulns(filters={"state": ["OPEN", "REOPENED"]},
                                                           num_assets=ASSETS_PER_CHUNK)]
        return assets, findings

    async def search_assets(self, text: str, limit: int = 20) -> list[dict[str, Any]]:
        """Tenable One inventory search. Experimental: the request body for
        /api/v1/t1/inventory/assets/search is unconfirmed, and an unexpected shape returns an empty list."""
        body = {"query": {"text": text}, "limit": limit}
        try:
            data = await self.http.post_json(self._url("/api/v1/t1/inventory/assets/search"), body,
                                             headers=self.config.headers())
        except FetchError as error:
            raise TenableError(f"inventory search failed: {error.reason}") from error
        items = (data or {}).get("data") or (data or {}).get("assets") or []
        return [item for item in items if isinstance(item, dict)]
