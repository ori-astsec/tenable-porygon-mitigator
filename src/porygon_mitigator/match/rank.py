"""Order the mitigations and decide the machine verdict. Every ordering rule is explainable in one line."""

from __future__ import annotations

from porygon_mitigator.models.assessment import AffectednessResult, MitigationAssessment
from porygon_mitigator.models.common import MachineVerdict
from porygon_mitigator.models.mitigation import Evidence

_STATUS_ORDER = {"applicable": 0, "already_applied": 1, "needs_device": 2, "unknown": 3, "not_applicable": 4}
_CONFIDENCE_ORDER = {"vendor_documented": 0, "third_party": 1, "derived": 2}
# Network controls change nothing on the host, so when the device is already in the path they go first.
_LAYER_ORDER = {"waf": 0, "ips": 0, "network_device": 1, "host": 2, "edr": 3}


def _key(item: MitigationAssessment) -> tuple[int, int, int, int, int, str]:
    mitigation = item.mitigation
    return (
        _STATUS_ORDER.get(item.status, 9),
        _CONFIDENCE_ORDER.get(mitigation.confidence, 9),
        -min(len(mitigation.verified_evidence), 2),
        mitigation.max_risk,
        _LAYER_ORDER.get(mitigation.layer, 9),
        mitigation.title.lower(),
    )


def rank(assessments: list[MitigationAssessment]) -> list[MitigationAssessment]:
    """Sort by status, then confidence, verified evidence, lower step risk, less intrusive layer. Number the
    applicable ones 1..n."""
    ordered = sorted(assessments, key=_key)
    position = 0
    for item in ordered:
        if item.status == "applicable":
            position += 1
            item.rank = position
        else:
            item.rank = None
    return ordered


def decide_verdict(
    affected: AffectednessResult,
    assessments: list[MitigationAssessment],
    negative_evidence: list[Evidence],
) -> tuple[MachineVerdict, str]:
    applicable = [item for item in assessments if item.status == "applicable"]
    already = [item for item in assessments if item.status == "already_applied"]
    needs = [item for item in assessments if item.status == "needs_device"]
    active = [item for item in assessments if item.mitigation.status == "active"]

    if affected.status == "not_affected":
        return "not_affected", "; ".join(affected.reasons) or "the machine does not run an affected version"
    if already:
        names = ", ".join(item.mitigation.title for item in already)
        extra = f"; {len(applicable)} more can be added" if applicable else ""
        return "already_mitigated", f"a documented mitigation is already in place: {names}{extra}"
    if applicable:
        count = len(applicable)
        noun = "mitigation applies" if count == 1 else "mitigations apply"
        return "mitigations_available", f"{count} documented {noun} to this machine"
    if needs:
        count = len(needs)
        plural = "s" if count != 1 else ""
        return "needs_additional_controls", f"{count} mitigation{plural} need a device or tool the machine doesn't have"
    if not active:
        if negative_evidence:
            return "no_documented_mitigation", (
                "the sources state there is no workaround: patch, or isolate the machine until you can"
            )
        return "no_documented_mitigation", (
            "no source documents a workaround for this CVE: patch, or isolate the machine until you can"
        )
    return "unknown", "mitigations exist but none could be matched to this machine's profile"
