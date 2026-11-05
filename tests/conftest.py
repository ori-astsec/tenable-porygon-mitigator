from __future__ import annotations

import json
from datetime import UTC, date, datetime
from pathlib import Path

import pytest

from porygon_mitigator.models import (
    Action,
    AffectedRange,
    AppliesTo,
    CveFacts,
    CveRecord,
    Evidence,
    MachineProfile,
    Mitigation,
    PipelineInfo,
    mitigation_id,
)

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples" / "machines"


@pytest.fixture(autouse=True)
def _isolated_cache(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Never let a test write into the repo's committed cache."""
    cache = tmp_path / "cache"
    monkeypatch.setenv("PORYGON_CACHE_DIR", str(cache))
    monkeypatch.setenv("PORYGON_WORK_DIR", str(tmp_path / "work"))
    return cache


def load_machine(name: str) -> MachineProfile:
    return MachineProfile.model_validate(json.loads((EXAMPLES / name).read_text(encoding="utf-8")))


def make_mitigation(cve: str = "CVE-2099-0001", **overrides: object) -> Mitigation:
    action = overrides.pop("action", Action(kind="disable_service", target="spooler"))
    assert isinstance(action, Action)
    fields: dict[str, object] = {
        "type": "DISABLE",
        "layer": "host",
        "title": "Disable the Print Spooler service",
        "summary": "Stops the vulnerable service.",
        "applies_to": AppliesTo(platforms=["windows"]),
        "evidence": [
            Evidence(url="https://msrc.microsoft.com/x", quote="Stop and disable the Print Spooler service",
                     retrieved_at=date(2026, 11, 1), verified=True, source_kind="vendor")
        ],
        "confidence": "vendor_documented",
    }
    fields.update(overrides)
    mid = mitigation_id(cve, str(fields["type"]), action.kind, action.target, [], str(fields["title"]))
    return Mitigation(id=mid, cve_id=cve, action=action, first_seen=date(2026, 11, 1),
                      last_confirmed=date(2026, 11, 1), **fields)  # type: ignore[arg-type]


def make_record(cve: str = "CVE-2099-0001", mitigations: list[Mitigation] | None = None,
                affected: list[AffectedRange] | None = None, published: date | None = None,
                computed_at: datetime | None = None) -> CveRecord:
    return CveRecord(
        cve_id=cve,
        computed_at=computed_at or datetime(2026, 11, 1, tzinfo=UTC),
        pipeline=PipelineInfo(tool_version="0.1.0"),
        facts=CveFacts(cve_id=cve, description="test", affected=affected or [], published=published),
        mitigations=mitigations or [],
    )
