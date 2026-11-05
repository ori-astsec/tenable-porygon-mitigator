"""Live research for one CVE: facts -> sources -> extraction -> verification -> merge -> a cache record."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import UTC, date, datetime

from porygon_mitigator import __version__
from porygon_mitigator.catalogs.lookup import catalogue_mitigations
from porygon_mitigator.config import Settings
from porygon_mitigator.extract.arbiter import arbitrate
from porygon_mitigator.extract.dedupe import dedupe, group_key
from porygon_mitigator.extract.llm import Llm
from porygon_mitigator.extract.prompts import EXTRACTION_SYSTEM, EXTRACTION_USER, PROMPT_VERSION
from porygon_mitigator.extract.schema import LlmExtraction
from porygon_mitigator.extract.verify import DocResult, build_records
from porygon_mitigator.intel.facts import gather_facts
from porygon_mitigator.models.cve import CveFacts, CveRecord, PipelineInfo
from porygon_mitigator.models.mitigation import Evidence, Mitigation, Remediation
from porygon_mitigator.sources.discover import Candidate, Collected, collect_sources
from porygon_mitigator.sources.documents import SourceAttempt, SourceDoc
from porygon_mitigator.sources.net import Http

Progress = Callable[[str], None]
EXTRACTION_CONCURRENCY = 4


def _envelope(text: str) -> str:
    # The advisory can't close our envelope early.
    return text.replace("</untrusted-advisory", "</untrusted_advisory")


def extraction_prompt(facts: CveFacts, doc: SourceDoc) -> str:
    products = ", ".join(dict.fromkeys(f"{item.vendor} {item.product}" for item in facts.affected[:8])) or "unknown"
    return EXTRACTION_USER.format(
        cve_id=facts.cve_id,
        title=facts.title or "",
        description=facts.description[:1200],
        products=products,
        url=doc.url,
        text=_envelope(doc.text),
    )


async def extract_document(llm: Llm, facts: CveFacts, doc: SourceDoc, today: date,
                           effort: str | None = None) -> tuple[DocResult | None, str, str]:
    """Extract one document. Returns (result or None, outcome, note)."""
    result = await llm.parse(system=EXTRACTION_SYSTEM, user=extraction_prompt(facts, doc),
                             output_format=LlmExtraction, effort=effort)
    if result.parsed is None:
        return None, result.outcome, result.note
    return build_records(result.parsed, doc, facts, today), "ok", ""


async def extract_all(llm: Llm, facts: CveFacts, docs: list[SourceDoc], attempts: list[SourceAttempt],
                      today: date, effort: str | None = None,
                      progress: Progress | None = None) -> list[tuple[SourceDoc, DocResult]]:
    """Extract every document. The first runs alone so the prompt cache is written once; the rest run in parallel."""
    by_url = {attempt.url: attempt for attempt in attempts}
    results: list[tuple[SourceDoc, DocResult]] = []
    semaphore = asyncio.Semaphore(EXTRACTION_CONCURRENCY)

    async def one(doc: SourceDoc) -> None:
        async with semaphore:
            outcome, outcome_kind, note = await extract_document(llm, facts, doc, today, effort)
        attempt = by_url.get(doc.url)
        if outcome is None:
            if attempt:
                attempt.status = "skipped"
                attempt.note = note or outcome_kind
            return
        results.append((doc, outcome))
        if attempt:
            attempt.mitigations = outcome.stats.kept
            if not outcome.mitigations and attempt.status == "ok":
                attempt.status = "no_mitigation"
            dropped = outcome.stats.dropped_unverified
            if dropped:
                attempt.note = f"{dropped} unverified mitigation(s) dropped"
        if progress:
            progress(f"  {doc.publisher}: {outcome.stats.kept} kept, {outcome.stats.dropped_unverified} dropped")

    if docs:
        await one(docs[0])
        await asyncio.gather(*(one(doc) for doc in docs[1:]))
    return results


def _merge_previous(new: list[Mitigation], previous: CveRecord | None) -> list[Mitigation]:
    """Keep first_seen from earlier runs; keep earlier records the new run didn't re-find (sources change)."""
    if previous is None:
        return new
    old_by_key = {group_key(item): item for item in previous.mitigations}
    out: list[Mitigation] = []
    found_keys = set()
    for item in new:
        key = group_key(item)
        found_keys.add(key)
        if key in old_by_key:
            item.first_seen = min(item.first_seen, old_by_key[key].first_seen)
        out.append(item)
    out.extend(item for key, item in old_by_key.items() if key not in found_keys and item.origin != "extraction")
    out.extend(item for key, item in old_by_key.items() if key not in found_keys and item.origin == "extraction")
    return out


def _consensus(first: list[Mitigation], second: list[Mitigation]) -> list[Mitigation]:
    keys = {group_key(item) for item in second}
    return [item for item in first if group_key(item) in keys or item.origin != "extraction"]


async def research_cve(
    cve_id: str,
    *,
    settings: Settings,
    previous: CveRecord | None = None,
    max_sources: int | None = None,
    consensus: bool = False,
    progress: Progress | None = None,
    extra_candidates: list[Candidate] | None = None,
    search: bool = True,
) -> CveRecord:
    say = progress or (lambda _message: None)
    today = datetime.now(UTC).date()
    llm = Llm(settings)
    async with Http() as http:
        say(f"{cve_id}: gathering CVE facts")
        facts = await gather_facts(cve_id, http, settings)
        collected: Collected = await collect_sources(
            facts, http, llm, settings, max_sources=max_sources or settings.max_sources, search=search,
            extra=extra_candidates, progress=say,
        )
    facts.distro_fixes = collected.distro_fixes
    say(f"extracting from {len(collected.docs)} sources with {settings.model}")
    results = await extract_all(llm, facts, collected.docs, collected.attempts, today, progress=say)
    mitigations = [item for _doc, result in results for item in result.mitigations]
    if consensus and mitigations:
        say("consensus pass")
        second = await extract_all(llm, facts, [doc for doc, r in results if r.mitigations], [], today,
                                   effort="high")
        mitigations = _consensus(mitigations, [item for _d, r in second for item in r.mitigations])
    mitigations += catalogue_mitigations(facts, today)
    merged, ambiguous = dedupe(mitigations)
    merged = await arbitrate(llm, cve_id, merged, ambiguous)
    merged = _merge_previous(merged, previous)

    remediation: list[Remediation] = []
    for _doc, result in results:
        if result.remediation and all(result.remediation.summary != item.summary for item in remediation):
            remediation.append(result.remediation)
    negatives: list[Evidence] = [result.negative for _doc, result in results if result.negative is not None]
    active = len([m for m in merged if m.status == "active"])
    say(f"{cve_id}: {active} active mitigations, cost ${llm.cost.cost_usd:.3f}")
    return CveRecord(
        cve_id=cve_id,
        computed_at=datetime.now(UTC),
        pipeline=PipelineInfo(tool_version=__version__, model=settings.model, prompt_version=PROMPT_VERSION,
                              effort=settings.effort),
        facts=facts,
        sources=[attempt.record() for attempt in collected.attempts],
        mitigations=merged,
        remediation=remediation[:4],
        negative_evidence=negatives[:4],
        generation_cost=llm.cost,
    )
