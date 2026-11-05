"""The answer for one (CVE, machine) pair: is it affected, and which mitigations apply."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from porygon_mitigator.models.common import Affectedness, ApplicabilityStatus, MachineVerdict
from porygon_mitigator.models.cve import CveFacts, GenerationCost, SourceRecord
from porygon_mitigator.models.mitigation import Evidence, Mitigation, Remediation


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class AffectednessResult(_Model):
    status: Affectedness
    reasons: list[str] = Field(default_factory=list)
    matched_software: list[str] = Field(default_factory=list)


class MitigationAssessment(_Model):
    mitigation: Mitigation
    status: ApplicabilityStatus
    reasons: list[str] = Field(default_factory=list, description="Why: which machine facts matched or were missing.")
    rank: int | None = Field(default=None, description="1 = try first. Only set for applicable mitigations.")


class CacheInfo(_Model):
    computed_at: datetime
    age_days: int
    fresh: bool
    layer: Literal["seed", "local", "live"]


class MachineAssessment(_Model):
    cve_id: str
    machine: str
    verdict: MachineVerdict
    verdict_reason: str
    affected: AffectednessResult
    facts: CveFacts
    mitigations: list[MitigationAssessment] = Field(default_factory=list)
    remediation: list[Remediation] = Field(default_factory=list)
    negative_evidence: list[Evidence] = Field(default_factory=list)
    sources: list[SourceRecord] = Field(default_factory=list)
    cache: CacheInfo
    run_cost: GenerationCost | None = Field(default=None, description="Present when this call searched live.")
    generated_at: datetime

    def by_status(self, status: ApplicabilityStatus) -> list[MitigationAssessment]:
        return [item for item in self.mitigations if item.status == status]
