"""Gather a CVE's facts from CVE.org (primary), NVD (CPE ranges, reference tags) and CISA KEV."""

from __future__ import annotations

from typing import Any

from porygon_mitigator.config import Settings
from porygon_mitigator.intel.cverecord import fetch_cve_record, parse_cve_record
from porygon_mitigator.intel.kev import kev_info, load_kev
from porygon_mitigator.intel.nvd import fetch_nvd
from porygon_mitigator.match.cpe import product_slug
from porygon_mitigator.models.actions import vendor_key
from porygon_mitigator.models.cve import AffectedRange, CveFacts, Reference
from porygon_mitigator.sources.net import FetchError, Http


class CveNotFoundError(LookupError):
    pass


def _merge_references(*groups: list[Reference]) -> list[Reference]:
    merged: dict[str, Reference] = {}
    for group in groups:
        for ref in group:
            key = ref.url.rstrip("/")
            if key in merged:
                tags = list(dict.fromkeys([*merged[key].tags, *ref.tags]))
                merged[key] = Reference(url=merged[key].url, tags=tags)
            else:
                merged[key] = ref
    return list(merged.values())


def _range_key(item: AffectedRange) -> tuple[Any, ...]:
    return (
        vendor_key(item.vendor), product_slug(item.product), item.version_start_including,
        item.version_start_excluding, item.version_end_including, item.version_end_excluding,
        tuple(item.exact_versions),
    )


def merge_facts(cve_id: str, cna: dict[str, Any] | None, nvd: dict[str, Any] | None,
                kev_entry: dict[str, Any] | None) -> CveFacts:
    cna = cna or {}
    nvd = nvd or {}
    affected: list[AffectedRange] = []
    seen: set[tuple[Any, ...]] = set()
    for item in [*(nvd.get("affected") or []), *(cna.get("affected") or [])]:
        key = _range_key(item)
        if key not in seen:
            seen.add(key)
            affected.append(item)
    kev = kev_info(kev_entry) or nvd.get("kev") or cna.get("kev")
    sources = [name for name, part in (("cve.org", cna), ("nvd", nvd)) if part]
    if kev_entry:
        sources.append("cisa-kev")
    return CveFacts(
        cve_id=cve_id,
        title=cna.get("title"),
        description=cna.get("description") or nvd.get("description") or "",
        published=cna.get("published") or nvd.get("published"),
        last_modified=nvd.get("last_modified") or cna.get("last_modified"),
        cvss=nvd.get("cvss") or cna.get("cvss"),
        cwes=list(dict.fromkeys([*(cna.get("cwes") or []), *(nvd.get("cwes") or [])])),
        affected=affected,
        references=_merge_references(cna.get("references") or [], nvd.get("references") or []),
        kev=kev,
        cna_workarounds=cna.get("cna_workarounds") or [],
        cna_solutions=cna.get("cna_solutions") or [],
        fact_sources=sources,
    )


async def gather_facts(cve_id: str, http: Http, settings: Settings) -> CveFacts:
    cna: dict[str, Any] | None = None
    try:
        cna = parse_cve_record(await fetch_cve_record(cve_id, http))
    except FetchError as error:
        if error.status == 404:
            raise CveNotFoundError(f"{cve_id} is not a published CVE (CVE.org has no record)") from error
    if cna and cna.get("state") == "REJECTED":
        raise CveNotFoundError(f"{cve_id} was rejected by its CNA")
    nvd: dict[str, Any] | None = None
    try:
        nvd = await fetch_nvd(cve_id, http, settings.nvd_api_key)
    except (FetchError, ValueError):
        nvd = None
    kev_entry = None
    try:
        kev_entry = (await load_kev(http, settings.work_dir())).get(cve_id.upper())
    except (FetchError, ValueError, OSError):
        kev_entry = None
    if cna is None and nvd is None:
        raise CveNotFoundError(f"no CVE data found for {cve_id}")
    return merge_facts(cve_id, cna, nvd, kev_entry)
