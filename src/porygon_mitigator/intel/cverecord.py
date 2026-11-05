"""CVE.org (CVE JSON 5) records: the CNA's own description, affected versions, workarounds and solutions."""

from __future__ import annotations

from datetime import date
from typing import Any

from porygon_mitigator.models.cve import AffectedRange, Cvss, KevInfo, Reference
from porygon_mitigator.sources.net import Http

CVE_API = "https://cveawg.mitre.org/api/cve/{cve}"
_UNBOUNDED = {"", "0", "*", "n/a", "unspecified", "unknown", "-", "all", "0.0", "0.0.0"}


def _english(items: list[dict[str, Any]] | None) -> list[str]:
    out = []
    for item in items or []:
        if str(item.get("lang", "en")).lower().startswith("en") and item.get("value"):
            out.append(str(item["value"]).strip())
    return out


def _date(value: Any) -> date | None:
    if not value:
        return None
    try:
        return date.fromisoformat(str(value)[:10])
    except ValueError:
        return None


def parse_cvss(metrics: list[dict[str, Any]] | None) -> Cvss | None:
    best: Cvss | None = None
    for preference in ("cvssV3_1", "cvssV4_0", "cvssV3_0", "cvssV2_0"):
        for metric in metrics or []:
            data = metric.get(preference)
            if isinstance(data, dict) and data.get("baseScore") is not None:
                return Cvss(
                    version=str(data.get("version") or preference.removeprefix("cvssV").replace("_", ".")),
                    base_score=float(data["baseScore"]),
                    severity=data.get("baseSeverity"),
                    vector=data.get("vectorString"),
                )
    return best


def parse_affected(entries: list[dict[str, Any]] | None) -> list[AffectedRange]:
    ranges: list[AffectedRange] = []
    for entry in entries or []:
        vendor = str(entry.get("vendor") or "").strip()
        product = str(entry.get("product") or entry.get("packageName") or "").strip()
        if not vendor or not product or vendor.lower() in ("n/a", "unknown"):
            continue
        exact: list[str] = []
        for version in entry.get("versions") or []:
            if version.get("status") != "affected":
                continue
            start = str(version.get("version") or "").strip()
            start_bound = None if start.lower() in _UNBOUNDED else start
            if version.get("lessThan") and str(version["lessThan"]).strip() not in ("*", ""):
                ranges.append(AffectedRange(vendor=vendor, product=product, version_start_including=start_bound,
                                            version_end_excluding=str(version["lessThan"]).strip()))
            elif version.get("lessThanOrEqual") and str(version["lessThanOrEqual"]).strip() not in ("*", ""):
                ranges.append(AffectedRange(vendor=vendor, product=product, version_start_including=start_bound,
                                            version_end_including=str(version["lessThanOrEqual"]).strip()))
            elif start_bound:
                exact.append(start_bound)
        already = any(r.vendor == vendor and r.product == product for r in ranges)
        if exact:
            ranges.append(AffectedRange(vendor=vendor, product=product, exact_versions=exact[:50]))
        elif not already and (entry.get("defaultStatus") == "affected" or entry.get("versions")):
            # Affected with no usable versions (or defaultStatus affected): keep the product, unbounded.
            ranges.append(AffectedRange(vendor=vendor, product=product))
    return ranges


def parse_cve_record(data: dict[str, Any]) -> dict[str, Any]:
    """The parts of a CVE JSON 5 record porygon uses, as plain fields for `CveFacts`."""
    meta = data.get("cveMetadata") or {}
    containers = data.get("containers") or {}
    cna = containers.get("cna") or {}
    cvss = parse_cvss(cna.get("metrics"))
    kev: KevInfo | None = None
    for adp in containers.get("adp") or []:
        if cvss is None:
            cvss = parse_cvss(adp.get("metrics"))
        for metric in adp.get("metrics") or []:
            other = metric.get("other") or {}
            if other.get("type") == "kev":
                content = other.get("content") or {}
                kev = KevInfo(date_added=_date(content.get("dateAdded")))
    cwes: list[str] = []
    for problem in cna.get("problemTypes") or []:
        for description in problem.get("descriptions") or []:
            cwe = description.get("cweId")
            if cwe and cwe not in cwes:
                cwes.append(str(cwe))
    references = [
        Reference(url=str(ref["url"]), tags=[str(tag) for tag in ref.get("tags") or []])
        for ref in cna.get("references") or []
        if ref.get("url")
    ]
    descriptions = _english(cna.get("descriptions"))
    return {
        "title": cna.get("title"),
        "description": descriptions[0] if descriptions else "",
        "published": _date(meta.get("datePublished")),
        "last_modified": _date(meta.get("dateUpdated")),
        "cvss": cvss,
        "cwes": cwes,
        "affected": parse_affected(cna.get("affected")),
        "references": references,
        "kev": kev,
        "cna_workarounds": _english(cna.get("workarounds")),
        "cna_solutions": _english(cna.get("solutions")),
        "state": meta.get("state"),
    }


async def fetch_cve_record(cve_id: str, http: Http) -> dict[str, Any]:
    data = await http.get_json(CVE_API.format(cve=cve_id))
    if not isinstance(data, dict):
        raise ValueError("unexpected CVE record shape")
    return data
