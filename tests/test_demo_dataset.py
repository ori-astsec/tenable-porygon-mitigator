"""The committed demo snapshot holds what its README states, keeps only public per-CVE fields, and its overlays load."""

import json
import runpy
from pathlib import Path

import pytest

from porygon_mitigator.models import MachineProfile

DEMO = Path(__file__).resolve().parents[1] / "demo" / "tenable-lab"
EXAMPLE_CVES = {"CVE-2019-0708", "CVE-2020-1350", "CVE-2021-34527", "CVE-2021-44228", "CVE-2023-44487"}


def test_overlays_load_as_profile_fields() -> None:
    config = json.loads((DEMO / "hosts.json").read_text(encoding="utf-8"))
    for host in config["hosts"]:
        overlay = json.loads((DEMO / "overlays" / f"{host['name']}.json").read_text(encoding="utf-8"))
        profile = MachineProfile.model_validate({"name": host["name"], "os": {"platform": host["platform"]}, **overlay})
        assert [device.role for device in profile.network_path] == ["ngfw", "router"]


def test_the_snapshot_keeps_public_fields_and_five_example_cves() -> None:
    """Per-CVE scores, severities, flaw classes and the full plan set came from a private dataset and stay out."""
    for line in (DEMO / "cves.jsonl").read_text(encoding="utf-8").splitlines():
        assert set(json.loads(line)) == {"cve", "vector", "kev"}
    plans = [json.loads(line) for line in (DEMO / "plans.jsonl").read_text(encoding="utf-8").splitlines()]
    assert {plan["cve"] for plan in plans} == EXAMPLE_CVES


def test_reproduce_matches_the_readme(capsys: pytest.CaptureFixture[str]) -> None:
    runpy.run_path(str(DEMO / "reproduce.py"), run_name="__main__")
    out = capsys.readouterr().out
    assert "CVEs on the 8 hosts' open findings: 10,933, 4,049 with a network attack vector, 218 on CISA KEV" in out
    assert "Palo Alto threat IDs: 22 CVEs, 22 on CISA KEV, 20 with a network attack vector" in out
    assert "Documented plans kept as examples: 57 for 5 CVEs" in out
