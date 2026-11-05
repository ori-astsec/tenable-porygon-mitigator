"""CVE facts and the per-CVE cache record (the JSON file committed under data/cache)."""

from __future__ import annotations

from datetime import date, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from porygon_mitigator.models.common import SourceStatusValue
from porygon_mitigator.models.mitigation import Evidence, Mitigation, Remediation, SourceKind


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Cvss(_Model):
    version: str
    base_score: float
    severity: str | None = None
    vector: str | None = None


class AffectedRange(_Model):
    """One vulnerable product range, from NVD CPE configurations or the CNA's affected list."""

    vendor: str
    product: str
    cpe: str | None = None
    version_start_including: str | None = None
    version_start_excluding: str | None = None
    version_end_including: str | None = None
    version_end_excluding: str | None = None
    exact_versions: list[str] = Field(default_factory=list)


class Reference(_Model):
    url: str
    tags: list[str] = Field(default_factory=list)


class DistroFix(_Model):
    """A Linux distribution's verdict for one package in one release (from Red Hat / Ubuntu data)."""

    distro: str = Field(description="ubuntu, rhel...")
    release: str = Field(description="Release key: '22.04' / 'jammy' for Ubuntu, '8' / '9' for RHEL.")
    package: str
    status: str = Field(description="fixed, not_affected, affected, wont_fix, deferred, unknown")
    fixed_version: str | None = None


class KevInfo(_Model):
    date_added: date | None = None
    due_date: date | None = None
    required_action: str | None = None
    known_ransomware: bool | None = None
    notes: str | None = None


class CveFacts(_Model):
    cve_id: str
    title: str | None = None
    description: str = ""
    published: date | None = None
    last_modified: date | None = None
    cvss: Cvss | None = None
    cwes: list[str] = Field(default_factory=list)
    affected: list[AffectedRange] = Field(default_factory=list)
    references: list[Reference] = Field(default_factory=list)
    kev: KevInfo | None = None
    cna_workarounds: list[str] = Field(default_factory=list)
    cna_solutions: list[str] = Field(default_factory=list)
    distro_fixes: list[DistroFix] = Field(default_factory=list)
    fact_sources: list[str] = Field(default_factory=list, description="Where these facts came from: cve.org, nvd...")

    def product_keys(self) -> list[str]:
        """Vulnerable products as 'vendor:product' keys, deduplicated in order."""
        keys = [f"{item.vendor.lower()}:{item.product.lower()}" for item in self.affected]
        return list(dict.fromkeys(keys))

    def network_reachable(self) -> bool:
        """Exploitable over the network (CVSS AV:N), so an IPS or WAF in the path can carry a signature for it.
        Without a vector it is unknown, and unknown counts as reachable."""
        vector = (self.cvss.vector if self.cvss else None) or ""
        return not vector or "AV:N" in vector.upper()


class SourceRecord(_Model):
    url: str
    publisher: str = Field(description="Short source name: redhat, msrc, ubuntu, nvd-ref, web-search...")
    origin: Literal["structured_api", "template", "reference", "search", "catalog", "gap_fill"]
    source_kind: SourceKind = "third_party"
    status: SourceStatusValue
    fetched_at: datetime | None = None
    content_sha256: str | None = None
    mitigations: int = 0
    note: str | None = None


class PipelineInfo(_Model):
    tool_version: str
    model: str | None = None
    prompt_version: str | None = None
    effort: str | None = None


class GenerationCost(_Model):
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_input_tokens: int = 0
    cache_creation_input_tokens: int = 0
    web_searches: int = 0
    cost_usd: float = 0.0


class CveRecord(_Model):
    """Everything porygon knows about mitigating one CVE. Contains public data only, never machine data."""

    schema_version: Literal[1] = 1
    cve_id: str
    computed_at: datetime
    pipeline: PipelineInfo
    facts: CveFacts
    sources: list[SourceRecord] = Field(default_factory=list)
    mitigations: list[Mitigation] = Field(default_factory=list)
    remediation: list[Remediation] = Field(default_factory=list)
    negative_evidence: list[Evidence] = Field(
        default_factory=list,
        description="Source statements that no workaround exists, or that a workaround was withdrawn.",
    )
    generation_cost: GenerationCost = Field(default_factory=GenerationCost)

    def active_mitigations(self) -> list[Mitigation]:
        return [item for item in self.mitigations if item.status == "active"]
