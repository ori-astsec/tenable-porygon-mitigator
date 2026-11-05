"""Merge the same mitigation found in several sources into one record.

Records with a normalised action group on (action kind, target) - plus rule IDs for signatures - whatever their
wording. Records whose action stayed `other` group by title similarity within one type, and the arbiter can merge
what similarity alone can't decide. A verified "withdrawn" from any source beats "active".
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from porygon_mitigator.models.mitigation import Evidence, Mitigation

_CONFIDENCE_ORDER = {"vendor_documented": 0, "third_party": 1, "derived": 2}
_WORD = re.compile(r"[a-z0-9]+")
_STOP = {"the", "a", "an", "to", "of", "for", "on", "in", "and", "or", "by", "with", "via", "from", "cve"}
MAX_EVIDENCE = 4


def group_key(item: Mitigation) -> str:
    if item.action.kind != "other" and item.action.target:
        if item.action.kind in ("apply_ips_signature", "apply_waf_rule"):
            return f"{item.action.kind}|{item.action.target.split(':')[0]}|{','.join(sorted(item.rule_ids))}"
        return f"{item.action.kind}|{item.action.target}"
    return f"other|{item.type}|{item.id}"


def _tokens(text: str) -> set[str]:
    return {word for word in _WORD.findall(text.lower()) if word not in _STOP}


def similarity(left: Mitigation, right: Mitigation) -> float:
    a, b = _tokens(left.title + " " + left.summary), _tokens(right.title + " " + right.summary)
    return len(a & b) / len(a | b) if a and b else 0.0


def _richness(item: Mitigation) -> tuple[int, int, int, int]:
    return (
        _CONFIDENCE_ORDER.get(item.confidence, 9),
        -len(item.verified_evidence),
        -sum(1 for step in item.steps if step.command),
        -len(item.steps),
    )


def merge_group(items: list[Mitigation]) -> Mitigation:
    """One record for a group: the richest member, with evidence, rule IDs and conditions pooled."""
    best = sorted(items, key=_richness)[0].model_copy(deep=True)
    # One quote from each distinct source first (corroboration), then further quotes, without exact repeats.
    first_per_url: list[Evidence] = []
    extra: list[Evidence] = []
    seen: set[tuple[str, str]] = set()
    urls: set[str] = set()
    for item in sorted(items, key=_richness):
        for quote in item.evidence:
            key = (quote.url, quote.quote)
            if key in seen:
                continue
            seen.add(key)
            (extra if quote.url in urls else first_per_url).append(quote)
            urls.add(quote.url)
    best.evidence = (first_per_url + extra)[:MAX_EVIDENCE]
    best.rule_ids = list(dict.fromkeys(rule for item in items for rule in item.rule_ids))[:20]
    best.applies_to.conditions = list(dict.fromkeys(c for item in items for c in item.applies_to.conditions))[:6]
    for field_name in ("side_effects", "rollback"):
        current = getattr(best, field_name)
        if current is None or current.origin == "derived":
            sourced = next((getattr(i, field_name) for i in items if getattr(i, field_name) is not None
                            and getattr(i, field_name).origin == "source"), None)
            if sourced is not None:
                setattr(best, field_name, sourced)
    withdrawn = [item for item in items if item.status == "withdrawn"]
    if withdrawn:
        best.status = "withdrawn"
        best.withdrawn_reason = withdrawn[0].withdrawn_reason or "a source says this measure is no longer effective"
    best.first_seen = min(item.first_seen for item in items)
    best.last_confirmed = max(item.last_confirmed for item in items)
    best.confidence = sorted(items, key=lambda i: _CONFIDENCE_ORDER.get(i.confidence, 9))[0].confidence
    return best


def dedupe(items: Iterable[Mitigation], *, similarity_threshold: float = 0.6) -> tuple[list[Mitigation],
                                                                                      list[list[Mitigation]]]:
    """Merge duplicates. Returns (merged records, ambiguous clusters the arbiter may want to look at)."""
    groups: dict[str, list[Mitigation]] = {}
    for item in items:
        groups.setdefault(group_key(item), []).append(item)
    merged = [merge_group(members) for members in groups.values()]

    # Unclassified records: fold near-identical ones (same type, very similar wording) into each other.
    others = [item for item in merged if item.action.kind == "other"]
    keyed = [item for item in merged if item.action.kind != "other"]
    clusters: list[list[Mitigation]] = []
    for item in others:
        for cluster in clusters:
            if cluster[0].type == item.type and similarity(cluster[0], item) >= similarity_threshold:
                cluster.append(item)
                break
        else:
            clusters.append([item])
    folded = [merge_group(cluster) if len(cluster) > 1 else cluster[0] for cluster in clusters]
    ambiguous = [
        [left, right]
        for index, left in enumerate(folded)
        for right in folded[index + 1:]
        if left.type == right.type and 0.3 <= similarity(left, right) < similarity_threshold
    ]
    return keyed + folded, ambiguous
