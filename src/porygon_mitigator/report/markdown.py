"""Markdown report for one (CVE, machine) assessment. ASCII-only so it renders in any terminal."""

from __future__ import annotations

from porygon_mitigator.models.assessment import MachineAssessment, MitigationAssessment
from porygon_mitigator.models.mitigation import Mitigation, Note
from porygon_mitigator.text import to_ascii

_VERDICT_TITLE = {
    "not_affected": "NOT AFFECTED",
    "mitigations_available": "MITIGATIONS AVAILABLE",
    "already_mitigated": "ALREADY MITIGATED",
    "needs_additional_controls": "NEEDS ADDITIONAL CONTROLS",
    "no_documented_mitigation": "NO DOCUMENTED MITIGATION",
    "unknown": "UNKNOWN",
}
_RISK = {0: "no change", 1: "read-only", 2: "changes the system", 3: "disruptive"}
_CONFIDENCE = {"vendor_documented": "vendor documented", "third_party": "third-party source", "derived": "derived"}


def _note(label: str, note: Note | None) -> list[str]:
    if note is None:
        return []
    origin = "from the source" if note.origin == "source" else "our inference, not from the source"
    return [f"- **{label}** ({origin}): {to_ascii(note.text)}"]


def _mitigation_block(item: MitigationAssessment, heading: str) -> list[str]:
    mitigation: Mitigation = item.mitigation
    lines = [
        f"### {heading}{to_ascii(mitigation.title)}",
        "",
        f"`{mitigation.type}` | layer: {mitigation.layer} | max step risk: {mitigation.max_risk} "
        f"({_RISK.get(mitigation.max_risk, '?')}) | {_CONFIDENCE.get(mitigation.confidence, mitigation.confidence)}",
        "",
        to_ascii(mitigation.summary),
        "",
    ]
    if item.reasons:
        lines.append("Why: " + "; ".join(to_ascii(reason) for reason in item.reasons))
        lines.append("")
    if mitigation.rule_ids:
        lines.append("Rule / signature IDs: " + ", ".join(mitigation.rule_ids))
        lines.append("")
    if mitigation.steps:
        lines.append("Steps:")
        for number, step in enumerate(mitigation.steps, start=1):
            risk = f" [risk {step.risk}: {_RISK.get(step.risk, '?')}]" if step.command or step.risk else ""
            lines.append(f"{number}. {to_ascii(step.text)}{risk}")
            if step.command:
                lines.append(f"   `{to_ascii(step.command)}`")
            if step.warning:
                lines.append(f"   WARNING: {to_ascii(step.warning)}")
        lines.append("")
    extra = (
        _note("Side effects", mitigation.side_effects)
        + _note("Rollback", mitigation.rollback)
        + _note("How to verify", mitigation.how_to_verify)
    )
    if extra:
        lines.extend([*extra, ""])
    for evidence in mitigation.evidence:
        mark = "verified" if evidence.verified else "NOT verified"
        lines.append(f'> "{to_ascii(evidence.quote)}"  ')
        lines.append(f"> -- {evidence.url} ({mark}, retrieved {evidence.retrieved_at.isoformat()})")
        lines.append("")
    return lines


def render_markdown(assessment: MachineAssessment) -> str:
    facts = assessment.facts
    lines = [f"# {assessment.cve_id} on {to_ascii(assessment.machine)}", ""]
    lines.append(f"**Verdict: {_VERDICT_TITLE[assessment.verdict]}** -- {to_ascii(assessment.verdict_reason)}")
    lines.append("")
    affected = assessment.affected
    lines.append(f"**Affected: {affected.status.upper()}** -- " + "; ".join(to_ascii(r) for r in affected.reasons))
    lines.append("")
    meta = []
    if facts.title:
        meta.append(to_ascii(facts.title))
    if facts.cvss:
        meta.append(f"CVSS {facts.cvss.base_score} {facts.cvss.severity or ''}".strip())
    if facts.kev:
        added = facts.kev.date_added.isoformat() if facts.kev.date_added else "?"
        meta.append(f"CISA KEV (added {added})")
    if meta:
        lines.append(" | ".join(meta))
        lines.append("")
    cache = assessment.cache
    freshness = "fresh" if cache.fresh else "stale"
    lines.append(
        f"Data: computed {cache.computed_at.date().isoformat()} ({cache.age_days} days ago, {freshness}, "
        f"{cache.layer} cache)"
    )
    if assessment.run_cost:
        cost = assessment.run_cost
        lines.append(
            f"Live research this run: {cost.web_searches} web searches, {cost.input_tokens} input / "
            f"{cost.output_tokens} output tokens, about ${cost.cost_usd:.2f}"
        )
    lines.append("")

    sections = [
        ("applicable", "Apply now (ranked)"),
        ("already_applied", "Already in place"),
        ("needs_device", "Needs a device or tool this machine doesn't have"),
        ("unknown", "Can't tell from the profile"),
    ]
    for status, title in sections:
        items = assessment.by_status(status)  # type: ignore[arg-type]
        if not items:
            continue
        lines.extend([f"## {title}", ""])
        for item in items:
            heading = f"{item.rank}. " if item.rank else ""
            lines.extend(_mitigation_block(item, heading))

    withdrawn = [i for i in assessment.mitigations if i.mitigation.status == "withdrawn"]
    not_applicable = [
        i for i in assessment.mitigations if i.status == "not_applicable" and i.mitigation.status == "active"
    ]
    if not_applicable:
        lines.extend(["## Not applicable to this machine", ""])
        for item in not_applicable:
            lines.append(f"- {to_ascii(item.mitigation.title)}: " + "; ".join(to_ascii(r) for r in item.reasons))
        lines.append("")
    if withdrawn:
        lines.extend(["## Withdrawn workarounds: do not rely on these", ""])
        for item in withdrawn:
            why = item.mitigation.withdrawn_reason or "withdrawn by the source"
            lines.append(f"- {to_ascii(item.mitigation.title)}: {to_ascii(why)}")
        lines.append("")
    if assessment.negative_evidence:
        lines.extend(["## What the sources say about workarounds", ""])
        for evidence in assessment.negative_evidence:
            lines.append(f'> "{to_ascii(evidence.quote)}" -- {evidence.url}')
        lines.append("")
    if assessment.remediation:
        lines.extend(["## If you can patch", ""])
        for remediation in assessment.remediation:
            fixed = f" (fixed in: {', '.join(remediation.fixed_versions)})" if remediation.fixed_versions else ""
            lines.append(f"- {to_ascii(remediation.summary)}{fixed}")
        lines.append("")
    if assessment.sources:
        lines.extend(["## Sources checked", ""])
        for source in assessment.sources:
            found = f", {source.mitigations} mitigation(s)" if source.mitigations else ""
            lines.append(f"- [{source.status}] {source.publisher}: {source.url}{found}")
        lines.append("")
    lines.append(
        "_porygon-mitigator reports steps; it never runs them. Commands are shown only when they appear verbatim in "
        "the cited source. Review every change before applying it._"
    )
    return "\n".join(lines) + "\n"
