"""A stored mitigation record: one concrete compensating control for one CVE, with verified evidence."""

from __future__ import annotations

import hashlib
from datetime import date
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from porygon_mitigator.models.actions import ActionKind
from porygon_mitigator.models.common import Confidence, DeviceRole, Layer, MitigationType, Platform

SourceKind = Literal["vendor", "distro", "government", "third_party", "catalog", "user_content"]
NoteOrigin = Literal["source", "derived"]

MAX_QUOTE_CHARS = 300


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Step(_Model):
    text: str
    command: str | None = Field(default=None, description="Only present when it appears verbatim in the source.")
    risk: int = Field(default=0, ge=0, le=3, description="0 none, 1 read-only, 2 changes system, 3 disruptive.")
    warning: str | None = None


class Note(_Model):
    text: str
    origin: NoteOrigin = Field(description="'source' when the advisory states it, 'derived' when we inferred it.")


class Action(_Model):
    kind: ActionKind
    target: str = ""


class Evidence(_Model):
    url: str
    quote: str = Field(description=f"Verbatim excerpt from the source, at most {MAX_QUOTE_CHARS} characters.")
    retrieved_at: date
    verified: bool = Field(description="True when the code found the quote in the fetched text.")
    source_kind: SourceKind = "third_party"


class AppliesTo(_Model):
    """What a machine needs for this mitigation to apply. Empty lists mean 'no constraint'."""

    platforms: list[Platform] = Field(default_factory=list)
    products: list[str] = Field(default_factory=list, description="vendor:product keys, e.g. 'openbsd:openssh'.")
    device_roles: list[DeviceRole] = Field(default_factory=list)
    device_vendors: list[str] = Field(default_factory=list, description="Normalised vendor keys of the device.")
    device_products: list[str] = Field(default_factory=list, description="Optional product hints, e.g. 'meraki_mx'.")
    security_tools: list[str] = Field(
        default_factory=list, description="'vendor' or 'vendor:product_hint' keys, e.g. 'microsoft:defender'."
    )
    conditions: list[str] = Field(default_factory=list, description="Prerequisites the source states, in words.")


class Mitigation(_Model):
    id: str
    cve_id: str
    type: MitigationType
    layer: Layer
    title: str
    summary: str
    steps: list[Step] = Field(default_factory=list)
    action: Action
    rule_ids: list[str] = Field(default_factory=list)
    side_effects: Note | None = None
    rollback: Note | None = None
    how_to_verify: Note | None = None
    applies_to: AppliesTo = Field(default_factory=AppliesTo)
    evidence: list[Evidence] = Field(default_factory=list)
    confidence: Confidence = "third_party"
    status: Literal["active", "withdrawn"] = "active"
    withdrawn_reason: str | None = None
    origin: Literal["extraction", "catalog", "manual"] = "extraction"
    first_seen: date
    last_confirmed: date

    @property
    def max_risk(self) -> int:
        return max((step.risk for step in self.steps), default=0)

    @property
    def verified_evidence(self) -> list[Evidence]:
        return [item for item in self.evidence if item.verified]


class Remediation(_Model):
    """Patch information, kept apart from mitigations: what fixes the CVE once you *can* patch."""

    summary: str
    fixed_versions: list[str] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)


def mitigation_id(cve_id: str, mitigation_type: str, kind: str, target: str, rule_ids: list[str], title: str) -> str:
    """Stable id: the same change from two sources (or two runs) gets the same id.

    Uses the normalised action when there is one; for `other` actions the title stands in, so distinct unclassified
    mitigations don't collide.
    """
    basis = target if kind != "other" else title.strip().lower()
    key = "|".join([cve_id.upper(), mitigation_type, kind, basis, ",".join(sorted(rule_ids))])
    return "m_" + hashlib.sha256(key.encode("utf-8")).hexdigest()[:12]
