"""The scan coverage report: what a scanner could not see on each machine, and what to fix first."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

GapKind = Literal[
    "no_scan_data",
    "no_scan_metadata",
    "credential_failure",
    "login_not_used",
    "no_credentials",
    "patch_assessment_failed",
    "stale_findings",
    "partial_login_failure",
    "insufficient_privilege",
    "patch_assessment_unavailable",
    "ports_not_probed",
    "web_tests_disabled",
    "superseded_patches",
    "not_recently_seen",
    "ambiguous_os",
    "shared_identity",
]
GapImpact = Literal["high", "medium", "low"]
CoverageStatus = Literal["surface_only", "partial", "unknown", "no_scan_data", "covered"]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class CoverageGap(_Strict):
    kind: GapKind
    impact: GapImpact
    detail: str = Field(description="What this machine's own scan data shows.")
    plugin_ids: list[int] = Field(default_factory=list, description="Tenable plugins the gap was read from.")


class MachineCoverage(_Strict):
    asset_id: str
    name: str
    os: str | None = None
    system_types: list[str] = Field(default_factory=list)
    sources: list[str] = Field(default_factory=list)
    status: CoverageStatus
    severe_findings: int = Field(description="Open critical and high findings.")
    looks_clean: bool = Field(description="No severe findings, but no local checks ran.")
    gaps: list[CoverageGap] = Field(default_factory=list)


class GapSummary(_Strict):
    kind: GapKind
    impact: GapImpact
    machines: int
    meaning: str
    fix: str


class StatusSummary(_Strict):
    status: CoverageStatus
    machines: int
    severe_findings: int
    median_severe_findings: float


class CoverageReport(_Strict):
    as_of: datetime | None = Field(default=None, description="The newest timestamp in the data.")
    machines_total: int
    open_findings: int
    statuses: list[StatusSummary]
    gaps: list[GapSummary]
    warnings: list[str] = Field(default_factory=list, description="Reasons the whole report may be unreliable.")
    scan_settings: dict[str, dict[str, int]] = Field(
        default_factory=dict, description="Each scan setting and how many machines were scanned with each value."
    )
    machines: list[MachineCoverage]
