"""Turn one advisory's extraction into trusted records.

Nothing the model says is kept on its word: every evidence quote must appear verbatim (after normalisation) in the
exact text the model read, every command must too, actions are re-normalised to the closed vocabulary, and commands
are linted for risk. Mitigations with no verified quote are dropped.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date

from porygon_mitigator.extract.derive import derive_rollback, derive_verify
from porygon_mitigator.extract.lint import lint_command
from porygon_mitigator.extract.schema import RISK_LEVEL, LlmExtraction, LlmMitigation
from porygon_mitigator.match.cpe import products_match
from porygon_mitigator.models.actions import KIND_PLATFORM, normalize_action, vendor_key
from porygon_mitigator.models.common import Platform
from porygon_mitigator.models.cve import CveFacts
from porygon_mitigator.models.mitigation import (
    MAX_QUOTE_CHARS,
    Action,
    AppliesTo,
    Evidence,
    Mitigation,
    Note,
    Remediation,
    Step,
    mitigation_id,
)
from porygon_mitigator.sources.documents import SourceDoc
from porygon_mitigator.text import clamp, contains_normalized, normalize_text

MAX_RECORDS_PER_SOURCE = 8
_PRODUCT_KINDS = {"set_config", "disable_app_feature", "remove_component", "block_request_pattern",
                  "avoid_untrusted_input"}
_TOOL_VENDORS = ("microsoft", "crowdstrike", "sentinelone", "palo alto", "trellix", "sophos", "trend micro",
                 "symantec", "broadcom", "bitdefender", "eset", "kaspersky", "carbon black", "vmware", "cisco",
                 "elastic", "cybereason", "fortinet", "check point", "malwarebytes", "withsecure")


@dataclass
class DocStats:
    proposed: int = 0
    kept: int = 0
    dropped_unverified: int = 0
    commands_dropped: int = 0
    quotes_dropped: int = 0
    notes: list[str] = field(default_factory=list)


@dataclass
class DocResult:
    mitigations: list[Mitigation]
    remediation: Remediation | None
    negative: Evidence | None
    stats: DocStats


def tool_key(name: str) -> str:
    """'Microsoft Defender for Endpoint' -> 'microsoft:defender_for_endpoint'."""
    lowered = name.strip().lower()
    for vendor in _TOOL_VENDORS:
        if lowered.startswith(vendor):
            rest = lowered[len(vendor):].strip()
            hint = "_".join(rest.split()[:2])
            return f"{vendor_key(vendor)}:{hint}" if hint else vendor_key(vendor)
    return vendor_key(lowered)


def _products_for(kind: str, target: str, facts: CveFacts) -> list[str]:
    if kind not in _PRODUCT_KINDS:
        return []
    target_product = target.split(":", 1)[0]
    matches = [key for key in facts.product_keys() if products_match(key.split(":", 1)[1], target_product)]
    return matches[:5] or [f":{target_product}"]


def _confidence(doc: SourceDoc) -> str:
    if doc.source_kind in ("vendor", "distro", "government"):
        return "vendor_documented"
    return "third_party"


def build_mitigation(item: LlmMitigation, doc: SourceDoc, facts: CveFacts, today: date,
                     stats: DocStats) -> Mitigation | None:
    quotes: list[Evidence] = []
    for quote in item.evidence_quotes[:3]:
        quote_text = clamp(normalize_text(quote), MAX_QUOTE_CHARS)
        check = quote_text.removesuffix("...") if quote_text.endswith("...") else quote_text
        if contains_normalized(doc.text, check):
            quotes.append(Evidence(url=doc.url, quote=quote_text, retrieved_at=today, verified=True,
                                   source_kind=doc.source_kind))
        else:
            stats.quotes_dropped += 1
    if not quotes:
        stats.dropped_unverified += 1
        return None

    steps: list[Step] = []
    for step in item.steps[:12]:
        command = step.command.strip() if step.command else None
        risk = RISK_LEVEL.get(step.risk, 2)
        warning: str | None = None
        text = normalize_text(step.text)
        if command:
            if contains_normalized(doc.text, command):
                risk, warning = lint_command(command, risk)
            else:
                stats.commands_dropped += 1
                command = None
                text = f"{text} (the exact command is not given in the source)"
        steps.append(Step(text=text, command=command, risk=risk, warning=warning))

    known_products = facts.product_keys()
    kind, target = normalize_action(item.action_kind, item.action_target, known_products)
    rule_ids = list(dict.fromkeys(rule.strip() for rule in item.rule_ids if rule.strip()))[:20]
    if kind in ("apply_ips_signature", "apply_waf_rule") and rule_ids and not target:
        kind, target = normalize_action(item.action_kind, f"{item.device_vendor or 'unknown'}:{rule_ids[0]}")
    action = Action(kind=kind, target=target)  # type: ignore[arg-type]

    platforms: list[Platform] = list(dict.fromkeys(item.platforms))
    implied = KIND_PLATFORM.get(kind)
    if implied and implied not in platforms and item.layer == "host":
        platforms.append(implied)  # type: ignore[arg-type]  # KIND_PLATFORM values are Platform literals
    device_roles = [item.device_role] if item.device_role != "none" else []
    device_vendors = [vendor_key(item.device_vendor)] if item.device_vendor else []
    security_tools = [tool_key(item.security_tool)] if item.security_tool else []
    applies_to = AppliesTo(
        platforms=platforms if item.layer in ("host", "edr") else [],
        products=_products_for(kind, target, facts) if item.layer == "host" else [],
        device_roles=device_roles if item.layer not in ("host", "edr") else [],
        device_vendors=device_vendors if item.layer not in ("host", "edr") else [],
        security_tools=security_tools if item.layer == "edr" else [],
        conditions=[normalize_text(c) for c in item.conditions[:5] if c.strip()],
    )

    def note(text: str | None) -> Note | None:
        return Note(text=normalize_text(text), origin="source") if text and text.strip() else None

    title = clamp(normalize_text(item.title), 120)
    record = Mitigation(
        id=mitigation_id(facts.cve_id, item.type, kind, target, rule_ids, title),
        cve_id=facts.cve_id,
        type=item.type,
        layer=item.layer,
        title=title,
        summary=clamp(normalize_text(item.summary), 600),
        steps=steps,
        action=action,
        rule_ids=rule_ids,
        side_effects=note(item.side_effects),
        rollback=note(item.rollback) or derive_rollback(action),
        how_to_verify=derive_verify(action),
        applies_to=applies_to,
        evidence=quotes,
        confidence=_confidence(doc),  # type: ignore[arg-type]
        status=item.status,
        withdrawn_reason=normalize_text(item.withdrawn_reason) if item.withdrawn_reason else None,
        origin="extraction",
        first_seen=today,
        last_confirmed=today,
    )
    return record


def build_records(extraction: LlmExtraction, doc: SourceDoc, facts: CveFacts, today: date) -> DocResult:
    stats = DocStats(proposed=len(extraction.mitigations))
    mitigations: list[Mitigation] = []
    if extraction.discusses_cve:
        for item in extraction.mitigations[:MAX_RECORDS_PER_SOURCE]:
            record = build_mitigation(item, doc, facts, today, stats)
            if record is not None:
                mitigations.append(record)
    stats.kept = len(mitigations)

    remediation: Remediation | None = None
    if extraction.remediation is not None:
        evidence = []
        quote = extraction.remediation.evidence_quote
        if quote and contains_normalized(doc.text, quote):
            evidence.append(Evidence(url=doc.url, quote=clamp(normalize_text(quote), MAX_QUOTE_CHARS),
                                     retrieved_at=today, verified=True, source_kind=doc.source_kind))
        if evidence:
            remediation = Remediation(summary=clamp(normalize_text(extraction.remediation.summary), 400),
                                      fixed_versions=extraction.remediation.fixed_versions[:20], evidence=evidence)

    negative: Evidence | None = None
    if extraction.no_workaround_quote and contains_normalized(doc.text, extraction.no_workaround_quote):
        negative = Evidence(url=doc.url, quote=clamp(normalize_text(extraction.no_workaround_quote), MAX_QUOTE_CHARS),
                            retrieved_at=today, verified=True, source_kind=doc.source_kind)
    return DocResult(mitigations=mitigations, remediation=remediation, negative=negative, stats=stats)
