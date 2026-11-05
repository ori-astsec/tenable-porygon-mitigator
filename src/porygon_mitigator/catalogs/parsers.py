"""Parse public IPS/WAF rule catalogues into {CVE: [rule ids]} maps. Pure functions over downloaded bytes."""

from __future__ import annotations

import html as html_lib
import io
import json
import re
import tarfile
from collections import defaultdict
from typing import Any

from bs4 import BeautifulSoup, Tag

_CVE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
_RULE_CVE = re.compile(r"reference\s*:\s*cve\s*,\s*(?:cve-)?(\d{4})-(\d{4,})", re.IGNORECASE)
_RULE_SID = re.compile(r"(?:^|[;(])\s*sid\s*:\s*(\d+)")
ET_BSD_SIDS = (2_000_000, 2_799_999)
MAX_RULES = 40

CatalogueMap = dict[str, list[str]]


def _cves(text: str) -> list[str]:
    return list(dict.fromkeys(match.upper() for match in _CVE.findall(text)))


def _sorted_ids(ids: set[str]) -> list[str]:
    return sorted(ids, key=lambda item: (len(item), item))[:MAX_RULES]


def rules_archive(tarball: bytes, *, sid_range: tuple[int, int] | None = None,
                  include_commented: bool = False) -> CatalogueMap:
    """Snort/Suricata rule archives: every rule's `reference:cve,` links to its SID."""
    found: dict[str, set[str]] = defaultdict(set)
    with tarfile.open(fileobj=io.BytesIO(tarball), mode="r:gz") as archive:
        for member in archive.getmembers():
            if not member.name.endswith(".rules"):
                continue
            handle = archive.extractfile(member)
            if handle is None:
                continue
            for line in handle.read().decode("utf-8", errors="replace").splitlines():
                stripped = line.strip()
                if not stripped or (stripped.startswith("#") and not include_commented):
                    continue
                sid = _RULE_SID.search(stripped)
                if sid is None:
                    continue
                number = int(sid.group(1))
                if sid_range and not sid_range[0] <= number <= sid_range[1]:
                    continue
                for year, sequence in _RULE_CVE.findall(stripped):
                    found[f"CVE-{year}-{sequence}"].add(str(number))
    return {cve: _sorted_ids(ids) for cve, ids in sorted(found.items())}


def f5_signatures(page: str) -> CatalogueMap:
    """F5's attack-signature reference embeds every signature as JSON in __NEXT_DATA__."""
    match = re.search(r'<script id="__NEXT_DATA__" type="application/json">(.*?)</script>', page, re.S)
    if match is None:
        raise ValueError("F5 page has no __NEXT_DATA__ payload; its layout changed")
    data: Any = json.loads(match.group(1))
    for key in ("props", "pageProps", "docData", "scope", "JsonData"):
        data = data.get(key) if isinstance(data, dict) else None
    if not isinstance(data, list):
        raise ValueError("F5 signature list not found at props.pageProps.docData.scope.JsonData")
    found: dict[str, set[str]] = defaultdict(set)
    for signature in data:
        if not isinstance(signature, dict) or not str(signature.get("id", "")).isdigit():
            continue
        for cve in _cves(json.dumps(signature.get("references") or "")):
            found[cve].add(str(signature["id"]))
    return {cve: _sorted_ids(ids) for cve, ids in sorted(found.items())}


def azure_waf(page: str) -> CatalogueMap:
    """Microsoft's Azure WAF rule-group pages: rule tables whose descriptions name CVEs."""
    soup = BeautifulSoup(page, "html.parser")
    found: dict[str, set[str]] = defaultdict(set)
    for row in soup.find_all("tr"):
        cells = row.find_all("td") if isinstance(row, Tag) else []
        if not cells:
            continue
        rule_id = cells[0].get_text(strip=True).rstrip("*")
        if not rule_id.isdigit():
            continue
        for cve in _cves(row.get_text(" ")):
            found[cve].add(rule_id)
    return {cve: _sorted_ids(ids) for cve, ids in sorted(found.items())}


def cloudflare_changelog(feed: str, history_pages: list[str]) -> tuple[CatalogueMap, dict[str, str]]:
    """Cloudflare WAF release notes (RSS + yearly history pages): tables of rule IDs whose descriptions name CVEs.
    Returns the CVE map and, per CVE, the post that announced the rule."""
    found: dict[str, set[str]] = defaultdict(set)
    links: dict[str, str] = {}
    blocks: list[tuple[str, str]] = []
    for item in re.findall(r"<item>(.*?)</item>", feed, re.S):
        link_match = re.search(r"<link>(.*?)</link>", item, re.S)
        description = re.search(r"<description>(.*?)</description>", item, re.S)
        if link_match and description:
            body = html_lib.unescape(description.group(1).replace("<![CDATA[", "").replace("]]>", ""))
            blocks.append((link_match.group(1).strip(), body))
    for page in history_pages:
        blocks.append(("", page))
    for link, body in blocks:
        soup = BeautifulSoup(body, "html.parser")
        for row in soup.find_all("tr"):
            cells = [cell.get_text(" ", strip=True) for cell in row.find_all("td")] if isinstance(row, Tag) else []
            if len(cells) < 3:
                continue
            ruleset, rule_id, legacy = cells[0], cells[1], cells[2]
            if "managed" not in ruleset.lower() and "specials" not in ruleset.lower():
                continue
            ids = [value for value in (legacy, rule_id) if value and value.upper() not in ("N/A", "NA", "-")]
            if not ids:
                continue
            for cve in _cves(" ".join(cells)):
                found[cve].update(part for part in re.split(r"[,;\s]+", ids[0]) if part)  # "100604, 100605"
                if link and cve not in links:
                    links[cve] = link
    return {cve: _sorted_ids(ids) for cve, ids in sorted(found.items())}, links


def netscaler_signatures(pages: list[str]) -> CatalogueMap:
    """NetScaler Web App Firewall signature-update pages: rule tables with CVE references."""
    found: dict[str, set[str]] = defaultdict(set)
    for page in pages:
        soup = BeautifulSoup(page, "html.parser")
        for row in soup.find_all("tr"):
            cells = [cell.get_text(" ", strip=True) for cell in row.find_all("td")] if isinstance(row, Tag) else []
            if not cells:
                continue
            rule_id = next((cell for cell in cells if cell.isdigit() and len(cell) >= 4), None)
            if rule_id is None:
                continue
            for cve in _cves(" ".join(cells)):
                found[cve].add(rule_id)
    return {cve: _sorted_ids(ids) for cve, ids in sorted(found.items())}


def threat_vault(signatures: list[dict[str, Any]]) -> CatalogueMap:
    """Palo Alto Threat Vault API rows (type=vulnerability): threat IDs per CVE."""
    found: dict[str, set[str]] = defaultdict(set)
    for signature in signatures:
        threat_id = str(signature.get("id") or "")
        if not threat_id.isdigit():
            continue
        for cve in _cves(json.dumps(signature.get("cve") or [])):
            found[cve].add(threat_id)
    return {cve: _sorted_ids(ids) for cve, ids in sorted(found.items())}
