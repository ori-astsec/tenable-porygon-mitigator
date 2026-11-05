"""NVD CVE API 2.0: CPE configurations (vulnerable version ranges) and tagged references.

This product uses the NVD API but is not endorsed or certified by the NVD. Without an API key NVD allows 5 requests
per 30 seconds, so requests are spaced; set NVD_API_KEY to go faster.
"""

from __future__ import annotations

import asyncio
import time
from datetime import date
from typing import Any

from porygon_mitigator.match.cpe import parse_cpe
from porygon_mitigator.models.cve import AffectedRange, Cvss, KevInfo, Reference
from porygon_mitigator.sources.net import Http

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_lock = asyncio.Lock()
_last_request = 0.0


async def _throttle(has_key: bool) -> None:
    global _last_request
    interval = 0.7 if has_key else 6.5
    async with _lock:
        wait = _last_request + interval - time.monotonic()
        if wait > 0:
            await asyncio.sleep(wait)
        _last_request = time.monotonic()


def _date(value: Any) -> date | None:
    try:
        return date.fromisoformat(str(value)[:10]) if value else None
    except ValueError:
        return None


def parse_nvd(cve: dict[str, Any]) -> dict[str, Any]:
    ranges: list[AffectedRange] = []
    for configuration in cve.get("configurations") or []:
        for node in configuration.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                if not match.get("vulnerable"):
                    continue
                criteria = str(match.get("criteria") or "")
                cpe = parse_cpe(criteria)
                if cpe is None:
                    continue
                bounds = {
                    "version_start_including": match.get("versionStartIncluding"),
                    "version_start_excluding": match.get("versionStartExcluding"),
                    "version_end_including": match.get("versionEndIncluding"),
                    "version_end_excluding": match.get("versionEndExcluding"),
                }
                exact = [cpe.full_version] if cpe.full_version and not any(bounds.values()) else []
                ranges.append(AffectedRange(vendor=cpe.vendor, product=cpe.product, cpe=criteria,
                                            exact_versions=[v for v in exact if v], **bounds))
    cvss: Cvss | None = None
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30", "cvssMetricV2"):
        for metric in metrics.get(key) or []:
            data = metric.get("cvssData") or {}
            if data.get("baseScore") is not None:
                cvss = Cvss(version=str(data.get("version", "")), base_score=float(data["baseScore"]),
                            severity=data.get("baseSeverity") or metric.get("baseSeverity"),
                            vector=data.get("vectorString"))
                break
        if cvss:
            break
    cwes = []
    for weakness in cve.get("weaknesses") or []:
        for description in weakness.get("description") or []:
            value = str(description.get("value") or "")
            if value.startswith("CWE-") and value not in cwes:
                cwes.append(value)
    references = [
        Reference(url=str(ref["url"]), tags=[str(tag) for tag in ref.get("tags") or []])
        for ref in cve.get("references") or []
        if ref.get("url")
    ]
    kev = None
    if cve.get("cisaExploitAdd"):
        kev = KevInfo(
            date_added=_date(cve.get("cisaExploitAdd")),
            due_date=_date(cve.get("cisaActionDue")),
            required_action=cve.get("cisaRequiredAction"),
        )
    descriptions = [d.get("value", "") for d in cve.get("descriptions") or [] if d.get("lang") == "en"]
    return {
        "description": descriptions[0] if descriptions else "",
        "published": _date(cve.get("published")),
        "last_modified": _date(cve.get("lastModified")),
        "cvss": cvss,
        "cwes": cwes,
        "affected": ranges,
        "references": references,
        "kev": kev,
    }


async def fetch_nvd(cve_id: str, http: Http, api_key: str | None) -> dict[str, Any] | None:
    await _throttle(bool(api_key))
    headers = {"apiKey": api_key} if api_key else None
    data = await http.get_json(NVD_API, params={"cveId": cve_id}, headers=headers)
    vulnerabilities = data.get("vulnerabilities") if isinstance(data, dict) else None
    if not vulnerabilities:
        return None
    cve = vulnerabilities[0].get("cve") or {}
    return parse_nvd(cve)
