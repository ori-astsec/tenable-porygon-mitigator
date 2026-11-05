"""Machine-specific follow-up search when nothing in the CVE record applies to the machine.

The first research pass is machine-agnostic. When the machine is affected and none of the record's mitigations fits
it, one more search is aimed at what the machine actually has: its distribution, the security devices in front of
it, and its endpoint tool. When host controls apply but no signature fits the devices in its traffic path, the
search looks only for those devices' IPS/WAF signatures. New, verified mitigations are merged into the record
(which stays machine-free: only the search was steered by the machine, nothing about it is stored).
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Literal

from porygon_mitigator.config import Settings
from porygon_mitigator.extract.dedupe import dedupe
from porygon_mitigator.extract.llm import Llm
from porygon_mitigator.extract.prompts import DISCOVERY_SYSTEM
from porygon_mitigator.models.actions import vendor_key
from porygon_mitigator.models.cve import CveFacts, CveRecord, GenerationCost
from porygon_mitigator.models.machine import MachineProfile
from porygon_mitigator.sources.discover import (
    Candidate,
    canonical_url,
    fetch_page,
    ips_search_candidates,
    worth_reading,
)
from porygon_mitigator.sources.net import Http
from porygon_mitigator.sources.registry import VENDOR_DOMAINS, is_allowed, search_domains_for
from porygon_mitigator.sources.text import about_other_cve

Progress = Callable[[str], None]
Focus = Literal["any", "ips"]
MAX_GAP_PAGES = 4


def machine_context(machine: MachineProfile) -> tuple[list[str], list[str]]:
    """(search phrases, vendor keys) describing what this machine has that could carry a mitigation."""
    phrases: list[str] = []
    vendors: list[str] = []
    if machine.os.distribution and machine.os.platform == "linux":
        phrases.append(f"{machine.os.distribution} {machine.os.version or ''}".strip())
        vendors.append("linux")
    for device in machine.network_path:
        phrases.append(f"{device.vendor} {device.product or device.role} {device.role}".strip())
        vendors.append(vendor_key(device.vendor))
    for tool in machine.security_tools:
        phrases.append(f"{tool.vendor} {tool.product or ''}".strip())
        vendors.append(vendor_key(tool.vendor))
    if machine.vendor:
        vendors.append(vendor_key(machine.vendor))
    return list(dict.fromkeys(phrases))[:5], [v for v in dict.fromkeys(vendors) if v in VENDOR_DOMAINS or v]


async def _search_urls(facts: CveFacts, machine: MachineProfile, llm: Llm, focus: Focus,
                       say: Progress) -> list[str]:
    if focus == "ips":
        device_vendors = list(dict.fromkeys(vendor_key(device.vendor) for device in machine.network_path))
        if not device_vendors:
            return []
        found, note = await ips_search_candidates(facts, llm, device_vendors, max_uses=3)
        say(f"IPS gap-fill search for {', '.join(device_vendors)}: {len(found)} results ({note})")
        return [candidate.url for candidate in found]
    phrases, vendors = machine_context(machine)
    if not phrases:
        return []
    domains = search_domains_for(vendors, web_app=False, linux="linux" in vendors)
    prompt = (
        f"Find vendor or CERT guidance that protects against {facts.cve_id} ({facts.title or ''}) on systems with: "
        f"{'; '.join(phrases)}. Look for signatures, rules, configuration changes or workarounds specific to these "
        "products. Run up to 3 searches, then list the most relevant page URLs, one per line."
    )
    hits, note = await llm.search(system=DISCOVERY_SYSTEM, prompt=prompt, domains=domains, max_uses=3)
    say(f"gap-fill search for {', '.join(phrases)}: {len(hits)} results ({note})")
    return [hit.url for hit in hits
            if is_allowed(hit.url) and worth_reading(hit.url) and not about_other_cve(hit.url, facts.cve_id)]


async def gap_fill_record(
    record: CveRecord,
    machine: MachineProfile,
    *,
    settings: Settings,
    focus: Focus = "any",
    progress: Progress | None = None,
) -> tuple[CveRecord, GenerationCost] | None:
    """`focus="ips"` searches only for signatures the devices in the machine's traffic path can enforce."""
    if not settings.has_anthropic_credentials:
        return None
    from porygon_mitigator.research import extract_all  # local import: research imports this module's siblings

    say = progress or (lambda _message: None)
    facts = record.facts
    llm = Llm(settings)
    urls = await _search_urls(facts, machine, llm, focus, say)
    known = {canonical_url(source.url) for source in record.sources}
    candidates = [Candidate(40 + rank, url, "gap_fill") for rank, url in enumerate(urls)
                  if canonical_url(url) not in known][:MAX_GAP_PAGES]
    if not candidates:
        return None
    async with Http() as http:
        fetched = await asyncio.gather(*(fetch_page(candidate, facts.cve_id, http) for candidate in candidates))
    docs = [doc for doc, _attempt in fetched if doc is not None]
    attempts = [attempt for _doc, attempt in fetched]
    today = datetime.now(UTC).date()
    results = await extract_all(llm, facts, docs, attempts, today, progress=say)
    new = [item for _doc, result in results for item in result.mitigations]
    if not new:
        updated = record.model_copy(deep=True)
        updated.sources.extend(attempt.record() for attempt in attempts)
        return updated, llm.cost
    merged, _ambiguous = dedupe([*record.mitigations, *new])
    updated = record.model_copy(deep=True)
    updated.mitigations = merged
    updated.sources.extend(attempt.record() for attempt in attempts)
    total = updated.generation_cost
    for field in ("input_tokens", "output_tokens", "cache_read_input_tokens", "cache_creation_input_tokens",
                  "web_searches"):
        setattr(total, field, getattr(total, field) + getattr(llm.cost, field))
    total.cost_usd = round(total.cost_usd + llm.cost.cost_usd, 6)
    say(f"gap-fill added {len(merged) - len(record.mitigations)} mitigation(s)")
    return updated, llm.cost
