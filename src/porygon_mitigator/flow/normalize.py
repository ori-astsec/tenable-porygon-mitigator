"""The checks every normalized vulnerability goes through, whoever produced it (the flow's subagent or `porygon tag`).

A flaw class is kept only with a quote of at least a few characters found in the source text. Lists are capped and
trimmed, and what an attacker needs from the CVSS vector is added by code.
"""

from __future__ import annotations

from porygon_mitigator.flow.models import VulnerabilityProfile

MAX_FIELD_CHARS = 300
MAX_FIELD_ITEMS = 12
MIN_EVIDENCE_CHARS = 8
REQUIREMENTS = {
    "PR:N": "No privileges needed",
    "PR:L": "Needs low privileges",
    "PR:H": "Needs high privileges",
    "Au:N": "No authentication needed",
    "Au:S": "Needs one authentication",
    "UI:N": "No user interaction",
    "UI:R": "Needs user interaction",
    "AC:L": "Low attack complexity",
    "AC:M": "Medium attack complexity",
    "AC:H": "High attack complexity",
}


def clean_list(values: list[str]) -> list[str]:
    return [value.strip()[:MAX_FIELD_CHARS] for value in values[:MAX_FIELD_ITEMS] if value.strip()]


def requirements_from_vector(vector: str) -> list[str]:
    return [text for part, text in REQUIREMENTS.items() if part in vector.split("/")]


def check_profile(profile: VulnerabilityProfile, source_text: str, vector: str) -> tuple[VulnerabilityProfile, str]:
    """The profile as it may be kept, and why its class was dropped (empty when it wasn't)."""
    dropped = ""
    evidence = profile.class_evidence.strip()
    if profile.vulnerability_class and (len(evidence) < MIN_EVIDENCE_CHARS or evidence not in source_text):
        profile = profile.model_copy(update={"vulnerability_class": "", "class_evidence": ""})
        dropped = "class dropped: its evidence isn't in the source text"
    kept = profile.model_copy(
        update={
            "processes": clean_list(profile.processes),
            "libraries": clean_list(profile.libraries),
            "protocols": clean_list(profile.protocols),
            "affected_versions": clean_list(profile.affected_versions),
            "exploitation_requirements": clean_list(
                list(dict.fromkeys([*requirements_from_vector(vector), *profile.exploitation_requirements]))
            ),
            "constraints": profile.constraints.strip()[:MAX_FIELD_CHARS],
        }
    )
    return kept, dropped
