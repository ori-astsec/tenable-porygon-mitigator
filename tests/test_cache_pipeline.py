import json
from datetime import UTC, date, datetime
from pathlib import Path

import pytest

from porygon_mitigator.cache.store import CacheStore, dump_record, freshness
from porygon_mitigator.cli import main
from porygon_mitigator.config import Settings
from porygon_mitigator.models import Action, AppliesTo, CveRecord
from porygon_mitigator.pipeline import assess, gap_fill_focus

from .conftest import EXAMPLES, load_machine, make_mitigation, make_record

SEED = Path(__file__).resolve().parents[1] / "src/porygon_mitigator/data/cache/cves/2022/CVE-2022-30190.json"


def test_put_get_roundtrip(tmp_path: Path) -> None:
    store = CacheStore(write_dir=tmp_path / "w", seed_dir=tmp_path / "s")
    record = make_record(mitigations=[make_mitigation()])
    path = store.put(record)
    assert path == tmp_path / "w" / "cves" / "2099" / "CVE-2099-0001.json"
    loaded = store.get("cve-2099-0001")
    assert loaded is not None and loaded.layer == "local"
    assert loaded.record == record
    assert dump_record(record) == path.read_text(encoding="utf-8")  # stable serialisation


def test_newest_layer_wins(tmp_path: Path) -> None:
    store = CacheStore(write_dir=tmp_path / "w", seed_dir=tmp_path / "s")
    CacheStore(write_dir=tmp_path / "s", seed_dir=tmp_path / "s").put(
        make_record(computed_at=datetime(2026, 1, 1, tzinfo=UTC)))
    store.put(make_record(computed_at=datetime(2026, 6, 1, tzinfo=UTC)))
    got = store.get("CVE-2099-0001")
    assert got is not None and got.layer == "local"
    assert [item.record.cve_id for item in store.list()] == ["CVE-2099-0001"]


def test_freshness_gates() -> None:
    now = datetime(2026, 11, 2, tzinfo=UTC)
    fresh, _ = freshness(make_record(computed_at=datetime(2026, 10, 1, tzinfo=UTC)), now)
    assert fresh
    stale, why = freshness(make_record(computed_at=datetime(2026, 8, 1, tzinfo=UTC)), now)
    assert not stale and "max" in why
    # Published Oct 30: computed at day 1, now day 3 -> no gate crossed; at day 8 the 7-day gate is crossed.
    young = make_record(published=date(2026, 10, 30), computed_at=datetime(2026, 10, 31, tzinfo=UTC))
    assert freshness(young, now)[0]
    assert not freshness(young, datetime(2026, 11, 7, tzinfo=UTC))[0]


def test_seed_record_is_valid_and_verified() -> None:
    record = CveRecord.model_validate_json(SEED.read_text(encoding="utf-8"))
    active = record.active_mitigations()
    assert active and all(m.evidence and all(e.verified for e in m.evidence) for m in record.mitigations)
    for mitigation in record.mitigations:
        for step in mitigation.steps:
            if step.command:
                assert any(step.command in e.quote for e in mitigation.evidence), "command must be quoted verbatim"


def test_follina_on_workstation_and_already_mitigated() -> None:
    record = CveRecord.model_validate_json(SEED.read_text(encoding="utf-8"))
    machine = load_machine("win10-office-workstation.json")
    result = assess(record, machine)
    assert result.verdict == "mitigations_available"
    assert result.affected.status == "affected"
    first = result.mitigations[0]
    assert first.rank == 1 and first.mitigation.action.target == "hkcr\\ms-msdt"
    assert machine.config_state is not None
    machine.config_state.registry["hkcr\\ms-msdt"] = None
    again = assess(record, machine)
    assert again.verdict == "already_mitigated"


def test_signature_gap_fill_only_for_network_cves_behind_a_device() -> None:
    record = CveRecord.model_validate_json(SEED.read_text(encoding="utf-8"))
    machine = load_machine("win10-office-workstation.json")  # behind a FortiGate; host mitigations apply
    assert gap_fill_focus(assess(record, machine), machine) is None  # Follina is AV:L: no IPS sees the exploit
    assert record.facts.cvss is not None
    record.facts.cvss.vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert gap_fill_focus(assess(record, machine), machine) == "ips"
    machine.network_path = []
    assert gap_fill_focus(assess(record, machine), machine) is None


def test_follina_protected_view_not_on_print_server() -> None:
    record = CveRecord.model_validate_json(SEED.read_text(encoding="utf-8"))
    result = assess(record, load_machine("win2019-print-server.json"))
    statuses = {item.mitigation.title: item.status for item in result.mitigations}
    assert statuses["Keep Office Protected View on for internet files"] == "unknown"


def test_cli_offline_markdown_and_json(capsys: pytest.CaptureFixture[str]) -> None:
    machine = str(EXAMPLES / "win10-office-workstation.json")
    assert main(["mitigate", "CVE-2022-30190", "--machine", machine, "--offline"]) == 0
    out = capsys.readouterr().out
    assert "Verdict: MITIGATIONS AVAILABLE" in out and "reg delete HKEY_CLASSES_ROOT\\ms-msdt /f" in out
    out.encode("ascii")  # terminal-safe
    assert main(["mitigate", "CVE-2022-30190", "--machine", machine, "--offline", "--format", "json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["verdict"] == "mitigations_available"


def test_cli_offline_not_cached(capsys: pytest.CaptureFixture[str]) -> None:
    machine = str(EXAMPLES / "win10-office-workstation.json")
    assert main(["mitigate", "CVE-2099-9999", "--machine", machine, "--offline"]) == 3
    assert Settings().writable_cache_dir() != Settings().seed_cache_dir()


def test_catalogue_record_skipped_when_an_advisory_gave_the_same_rule() -> None:
    advisory_ips = make_mitigation(
        "CVE-2021-44228", action=Action(kind="apply_ips_signature", target="snort:58722"), type="IPS", layer="ips",
        title="Enable Talos Snort rules", rule_ids=["1:58722", "58723"], applies_to=AppliesTo(device_roles=["ips"]))
    result = assess(make_record("CVE-2021-44228", [advisory_ips]), load_machine("java-app-server.json"))
    targets = [item.mitigation.action.target for item in result.mitigations]
    assert targets.count("snort:58722") == 1  # the Snort 3 catalogue record would repeat the advisory's rule
    assert any(target.startswith("cisco_secure_firewall:") for target in targets)  # other products still listed
