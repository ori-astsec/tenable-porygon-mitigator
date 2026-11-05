"""The entry point every surface (CLI, MCP server, eval runner) goes through.

`assess()` answers "which mitigations apply to this machine?" from a CVE record. `mitigate()` gets the record (cache
first, live research on a miss or when stale) and then assesses.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Literal

from porygon_mitigator.cache.store import CacheStore, freshness, normalize_cve_id, record_age_days
from porygon_mitigator.catalogs.lookup import catalogue_mitigations
from porygon_mitigator.config import Settings
from porygon_mitigator.match.affected import assess_affected
from porygon_mitigator.match.applicability import assess_mitigation
from porygon_mitigator.match.rank import decide_verdict, rank
from porygon_mitigator.models.actions import rule_key
from porygon_mitigator.models.assessment import CacheInfo, MachineAssessment
from porygon_mitigator.models.cve import CveRecord, GenerationCost
from porygon_mitigator.models.machine import MachineProfile
from porygon_mitigator.models.mitigation import Mitigation

Mode = Literal["auto", "offline", "refresh"]
Progress = Callable[[str], None]


class NotCachedError(LookupError):
    """Offline mode and the CVE has no cached record."""


def _duplicates_extracted(item: Mitigation, extracted: list[Mitigation]) -> bool:
    """A catalogue record adds nothing when an advisory already gave the same rule for the same product."""
    vendor = item.action.target.partition(":")[0]
    rules = {rule_key(rule) for rule in item.rule_ids}
    for other in extracted:
        if other.id == item.id or other.action == item.action:
            return True
        if (other.action.kind == item.action.kind and other.action.target.partition(":")[0] == vendor
                and rules & {rule_key(rule) for rule in other.rule_ids}):
            return True
    return False


def assess(
    record: CveRecord,
    machine: MachineProfile,
    *,
    layer: Literal["seed", "local", "live"] = "seed",
    run_cost: GenerationCost | None = None,
    now: datetime | None = None,
) -> MachineAssessment:
    now = now or datetime.now(UTC)
    affected = assess_affected(record.facts, machine)
    # Catalogue coverage is looked up fresh, so a `porygon catalogs sync` improves every cached CVE at once.
    extra = [item for item in catalogue_mitigations(record.facts, now.date())
             if not _duplicates_extracted(item, record.mitigations)]
    items = rank([assess_mitigation(item, machine, affected) for item in [*record.mitigations, *extra]])
    verdict, reason = decide_verdict(affected, items, record.negative_evidence)
    fresh, _ = freshness(record, now)
    return MachineAssessment(
        cve_id=record.cve_id,
        machine=machine.name,
        verdict=verdict,
        verdict_reason=reason,
        affected=affected,
        facts=record.facts,
        mitigations=items,
        remediation=record.remediation,
        negative_evidence=record.negative_evidence,
        sources=record.sources,
        cache=CacheInfo(
            computed_at=record.computed_at,
            age_days=record_age_days(record, now.date()),
            fresh=fresh,
            layer=layer,
        ),
        run_cost=run_cost,
        generated_at=now,
    )


async def get_record(
    cve_id: str,
    *,
    settings: Settings,
    mode: Mode = "auto",
    save: bool = True,
    max_sources: int | None = None,
    consensus: bool = False,
    progress: Progress | None = None,
) -> tuple[CveRecord, Literal["seed", "local", "live"], GenerationCost | None]:
    cve_id = normalize_cve_id(cve_id)
    store = CacheStore.from_settings(settings)
    cached = store.get(cve_id)
    if mode == "offline":
        if cached is None:
            raise NotCachedError(f"{cve_id} is not in the cache; run without --offline to research it live")
        return cached.record, cached.layer, None
    if mode == "auto" and cached is not None:
        fresh, why = freshness(cached.record)
        if fresh:
            return cached.record, cached.layer, None
        if progress:
            progress(f"cached record is stale ({why}); researching again")
    from porygon_mitigator.research import research_cve  # imported lazily: needs network + API key

    record = await research_cve(
        cve_id,
        settings=settings,
        previous=cached.record if cached else None,
        max_sources=max_sources,
        consensus=consensus,
        progress=progress,
    )
    if save:
        path = store.put(record)
        if progress:
            progress(f"saved {path}")
    return record, "live", record.generation_cost


def gap_fill_focus(result: MachineAssessment, machine: MachineProfile) -> Literal["any", "ips"] | None:
    """What a follow-up search should look for: anything when nothing applies; only signatures when host controls
    apply but none of the devices in the traffic path has a rule to enforce."""
    if result.affected.status not in ("affected", "likely"):
        return None
    if result.verdict in ("no_documented_mitigation", "unknown", "needs_additional_controls"):
        return "any"
    has_signature = any(item.status == "applicable" and item.mitigation.layer in ("ips", "waf")
                        for item in result.mitigations)
    if machine.network_path and result.facts.network_reachable() and not has_signature:
        return "ips"
    return None


async def mitigate(
    cve_id: str,
    machine: MachineProfile,
    *,
    settings: Settings,
    mode: Mode = "auto",
    save: bool = True,
    max_sources: int | None = None,
    consensus: bool = False,
    gap_fill: bool = True,
    progress: Progress | None = None,
) -> MachineAssessment:
    record, layer, cost = await get_record(
        cve_id, settings=settings, mode=mode, save=save, max_sources=max_sources, consensus=consensus,
        progress=progress,
    )
    result = assess(record, machine, layer=layer, run_cost=cost)
    focus = gap_fill_focus(result, machine)
    if gap_fill and mode != "offline" and focus is not None:
        from porygon_mitigator.gapfill import gap_fill_record

        filled = await gap_fill_record(record, machine, settings=settings, focus=focus, progress=progress)
        if filled is not None:
            record, extra_cost = filled
            if save:
                CacheStore.from_settings(settings).put(record)
            total = (cost or GenerationCost()).model_copy()
            for field in ("input_tokens", "output_tokens", "cache_read_input_tokens",
                          "cache_creation_input_tokens", "web_searches"):
                setattr(total, field, getattr(total, field) + getattr(extra_cost, field))
            total.cost_usd = round(total.cost_usd + extra_cost.cost_usd, 4)
            result = assess(record, machine, layer="live", run_cost=total)
    return result
