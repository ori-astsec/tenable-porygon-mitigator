"""`porygon catalogs sync`: download the public rule catalogues and write compact CVE -> rule ID indexes.

Indexes for public catalogues are written next to the package (committed when running from a checkout), so lookups
work offline. Threat Vault data needs your own key and is only ever written to the local work directory.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from porygon_mitigator.catalogs import parsers
from porygon_mitigator.catalogs.templates import SOURCE_INFO
from porygon_mitigator.config import Settings, package_data_dir, running_from_checkout
from porygon_mitigator.sources.net import FetchError, Http

SNORT3_URL = "https://www.snort.org/downloads/community/snort3-community-rules.tar.gz"
ET_OPEN_URL = "https://rules.emergingthreats.net/open/snort-2.9.0/emerging.rules.tar.gz"
F5_URL = "https://docs.cloud.f5.com/docs-v2/platform/reference/attack-signatures"
AZURE_APPGW_URL = "https://learn.microsoft.com/azure/web-application-firewall/ag/application-gateway-crs-rulegroups-rules"
AZURE_FD_URL = "https://learn.microsoft.com/azure/web-application-firewall/afds/waf-front-door-drs"
CLOUDFLARE_RSS = "https://developers.cloudflare.com/changelog/rss/waf.xml"
CLOUDFLARE_HISTORY = "https://developers.cloudflare.com/waf/change-log/historical-{year}/"
NETSCALER_SITEMAP = "https://docs.netscaler.com/us/en/citrix-adc.sitemap.xml"
THREAT_VAULT_API = "https://api.threatvault.paloaltonetworks.com/service/v1/threats"
CATALOGUE_MAX_BYTES = 64 * 1024 * 1024
MIN_SHRINK_RATIO = 0.5  # a new snapshot this much smaller than the stored one is treated as a broken parse


@dataclass
class SyncResult:
    source: str
    cves: int
    path: Path | None
    note: str = ""


async def _snort3(http: Http) -> tuple[parsers.CatalogueMap, dict[str, str], list[str]]:
    body = (await http.get(SNORT3_URL)).body
    return parsers.rules_archive(body), {}, [SNORT3_URL]


async def _et_open(http: Http) -> tuple[parsers.CatalogueMap, dict[str, str], list[str]]:
    body = (await http.get(ET_OPEN_URL)).body
    return parsers.rules_archive(body, sid_range=parsers.ET_BSD_SIDS), {}, [ET_OPEN_URL]


async def _f5(http: Http) -> tuple[parsers.CatalogueMap, dict[str, str], list[str]]:
    return parsers.f5_signatures((await http.get(F5_URL)).text), {}, [F5_URL]


async def _azure_appgw(http: Http) -> tuple[parsers.CatalogueMap, dict[str, str], list[str]]:
    return parsers.azure_waf((await http.get(AZURE_APPGW_URL)).text), {}, [AZURE_APPGW_URL]


async def _azure_fd(http: Http) -> tuple[parsers.CatalogueMap, dict[str, str], list[str]]:
    return parsers.azure_waf((await http.get(AZURE_FD_URL)).text), {}, [AZURE_FD_URL]


async def _cloudflare(http: Http) -> tuple[parsers.CatalogueMap, dict[str, str], list[str]]:
    feed = (await http.get(CLOUDFLARE_RSS)).text
    pages: list[str] = []
    urls = [CLOUDFLARE_RSS]
    for year in range(2022, datetime.now(UTC).year):
        url = CLOUDFLARE_HISTORY.format(year=year)
        try:
            pages.append((await http.get(url)).text)
            urls.append(url)
        except FetchError:
            continue
    mapping, links = parsers.cloudflare_changelog(feed, pages)
    return mapping, links, urls


async def _netscaler(http: Http) -> tuple[parsers.CatalogueMap, dict[str, str], list[str]]:
    sitemap = (await http.get(NETSCALER_SITEMAP)).text
    urls = sorted(set(re.findall(r"<loc>(https://docs\.netscaler\.com/[^<]*signature-update-version-\d+\.html)</loc>",
                                 sitemap)))
    semaphore = asyncio.Semaphore(4)

    async def one(url: str) -> str:
        async with semaphore:
            try:
                return (await http.get(url)).text
            except FetchError:
                return ""

    pages = await asyncio.gather(*(one(url) for url in urls))
    return parsers.netscaler_signatures([page for page in pages if page]), {}, [NETSCALER_SITEMAP]


async def _threat_vault(http: Http) -> tuple[parsers.CatalogueMap, dict[str, str], list[str]]:
    key = os.environ.get("PALO_ALTO_THREAT_VAULT_API_KEY")
    if not key:
        raise FetchError("PALO_ALTO_THREAT_VAULT_API_KEY is not set")
    rows: list[dict[str, Any]] = []
    offset, total = 0, None
    while total is None or offset < total:
        data = await http.get_json(THREAT_VAULT_API, params={"type": "vulnerability", "offset": str(offset),
                                                              "limit": "1000"}, headers={"X-API-KEY": key})
        batch = ((data or {}).get("data") or {}).get("vulnerability") or []
        total = int((data or {}).get("count") or 0)
        rows.extend(batch)
        if not batch:
            break
        offset += len(batch)
    return parsers.threat_vault(rows), {}, [THREAT_VAULT_API]


Loader = Callable[[Http], Awaitable[tuple[parsers.CatalogueMap, dict[str, str], list[str]]]]
LOADERS: dict[str, Loader] = {
    "snort3": _snort3,
    "et_open": _et_open,
    "f5": _f5,
    "azure_appgw": _azure_appgw,
    "azure_frontdoor": _azure_fd,
    "cloudflare": _cloudflare,
    "netscaler": _netscaler,
    "threat_vault": _threat_vault,
}
DEFAULT_SOURCES = ("snort3", "et_open", "f5", "azure_appgw", "azure_frontdoor", "cloudflare")
PRIVATE_SOURCES = ("threat_vault",)  # licensed data: local only, never committed


def index_dir(source: str, settings: Settings) -> Path:
    if source in PRIVATE_SOURCES or not running_from_checkout():
        return settings.work_dir() / "catalogs"
    return package_data_dir() / "catalogs"


def write_index(path: Path, source: str, mapping: parsers.CatalogueMap, links: dict[str, str],
                urls: list[str]) -> None:
    """One CVE per line, sorted, so a sync shows up as a readable diff."""
    path.parent.mkdir(parents=True, exist_ok=True)
    header = {"source": source, "name": SOURCE_INFO[source][1], "generated_at": datetime.now(UTC).isoformat(
        timespec="seconds"), "source_urls": urls, "note": "Rule IDs and links only; no rule content."}
    lines = [json.dumps(header)[:-1] + ', "cves": {']
    entries = []
    for cve in sorted(mapping):
        entry: dict[str, Any] = {"rules": mapping[cve]}
        if cve in links:
            entry["link"] = links[cve]
        entries.append(f"  {json.dumps(cve)}: {json.dumps(entry)}")
    lines.append(",\n".join(entries))
    lines.append("}}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _stored_size(path: Path) -> int:
    try:
        return len(json.loads(path.read_text(encoding="utf-8")).get("cves", {}))
    except (OSError, ValueError):
        return 0


async def sync(sources: list[str], settings: Settings, progress: Callable[[str], None] | None = None) -> list[
        SyncResult]:
    say = progress or (lambda _message: None)
    results: list[SyncResult] = []
    async with Http(max_bytes=CATALOGUE_MAX_BYTES, timeout=120.0) as http:
        for source in sources:
            path = index_dir(source, settings) / f"{source}.json"
            try:
                mapping, links, urls = await LOADERS[source](http)
            except (FetchError, ValueError, OSError) as error:
                results.append(SyncResult(source, 0, None, f"failed: {error}"))
                say(f"{source}: failed ({error})")
                continue
            stored = _stored_size(path)
            if stored and len(mapping) < stored * MIN_SHRINK_RATIO:
                note = f"kept the stored index: new snapshot has {len(mapping)} CVEs vs {stored} (broken parse?)"
                results.append(SyncResult(source, stored, path, note))
                say(f"{source}: {note}")
                continue
            write_index(path, source, mapping, links, urls)
            results.append(SyncResult(source, len(mapping), path))
            say(f"{source}: {len(mapping)} CVEs -> {path}")
    return results
