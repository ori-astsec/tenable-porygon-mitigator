"""Scan coverage report: which machines the scanner really saw. All fixtures are synthetic."""

import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, ClassVar

import pytest

from porygon_mitigator.cli import main
from porygon_mitigator.integrations.tenable_one.client import (
    ASSETS_PER_CHUNK,
    EXPORT_MAX_BYTES,
    TenableError,
    TenableOneClient,
)
from porygon_mitigator.integrations.tenable_one.coverage import scan_coverage
from porygon_mitigator.mcp_server import server
from porygon_mitigator.models.coverage import MachineCoverage
from porygon_mitigator.report.coverage import render_coverage_markdown

NOW = "2026-11-01T00:00:00.000Z"
SCAN_OK = (
    "Credentialed checks : yes, as 'root' via ssh\nPort scanner(s) : nessus_syn_scanner\nPort range : default\n"
    "CGI scanning : disabled\nWeb application tests : disabled\n"
    "Display superseded patches : yes (supersedence plugin did not launch)\n"
)
SCAN_BASE = "Credentialed checks : yes\nPort scanner(s) : x\n"
SCAN_NO_LOGIN = SCAN_OK.replace("yes, as 'root' via ssh", "no")
SCAN_NETSTAT = SCAN_OK.replace("nessus_syn_scanner", "netstat")


def asset(asset_id: str, **fields: Any) -> dict[str, Any]:
    return {
        "id": asset_id,
        "network": {
            "hostnames": [asset_id],
            "ipv4s": fields.pop("ipv4s", []),
            "network_interfaces": fields.pop("interfaces", []),
        },
        "operating_systems": fields.pop("operating_systems", ["Ubuntu 22.04"]),
        "system_types": fields.pop("system_types", ["general-purpose"]),
        "sources": fields.pop("sources", [{"name": "NESSUS_SCAN"}]),
        "timestamps": {"last_seen": fields.pop("last_seen", NOW)},
        **fields,
    }


def row(asset_id: str, plugin_id: int, **fields: Any) -> dict[str, Any]:
    return {
        "asset": {"uuid": asset_id},
        "plugin": {"id": plugin_id, **fields.pop("plugin", {})},
        "port": fields.pop("port", {"port": 0}),
        "severity": fields.pop("severity", "info"),
        "state": fields.pop("state", "OPEN"),
        "last_found": fields.pop("last_found", NOW),
        **fields,
    }


def scan(asset_id: str, output: str = SCAN_OK, **fields: Any) -> dict[str, Any]:
    return row(asset_id, 19506, output=output, **fields)


def machine(findings: list[dict[str, Any]], name: str = "host", **asset_fields: Any) -> MachineCoverage:
    report = scan_coverage([asset(name, **asset_fields)], findings)
    return next(item for item in report.machines if item.name == name)


def kinds(item: MachineCoverage) -> set[str]:
    return {gap.kind for gap in item.gaps}


def detail(item: MachineCoverage, kind: str) -> str:
    return next(gap.detail for gap in item.gaps if gap.kind == kind)


def test_no_rows_means_no_scan_data_and_names_source_and_last_scan() -> None:
    item = machine([], sources=[{"name": "OTSensor"}], scan={"last_scan_time": "2026-08-23T00:00:00Z"})
    assert item.status == "no_scan_data" and not item.looks_clean
    assert "OTSensor" in detail(item, "no_scan_data") and "2026-08-23" in detail(item, "no_scan_data")


def test_no_login_recorded_with_no_findings_looks_clean() -> None:
    item = machine([scan("host", SCAN_NO_LOGIN)])
    assert (item.status, item.looks_clean) == ("surface_only", True)
    assert "no_credentials" in kinds(item)


def test_severe_findings_stop_a_machine_looking_clean() -> None:
    item = machine([scan("host", SCAN_NO_LOGIN), row("host", 1, severity="high")])
    assert (item.status, item.looks_clean, item.severe_findings) == ("surface_only", False, 1)


def test_failed_login_with_no_other_login_is_credential_failure() -> None:
    failure = row("host", 104410, output="\n  Protocol        : SSH\n  Port            : 22\n")
    item = machine([scan("host", SCAN_NO_LOGIN), failure])
    assert item.status == "surface_only" and "SSH" in detail(item, "credential_failure")
    assert "no_credentials" not in kinds(item)


def test_failed_login_beside_working_checks_is_only_partial() -> None:
    failure = row("host", 104410, output="Protocol : SMB\n")
    item = machine([scan("host"), failure, row("host", 141118, output="Proto:      SSH\n"), row("host", 117887)])
    assert item.status == "partial" and "partial_login_failure" in kinds(item)
    assert "credential_failure" not in kinds(item)


def test_login_the_scan_did_not_use_is_named_as_such() -> None:
    login = row("host", 141118, output="User:       'admin'\nPort:       22\nProto:      SSH\n")
    item = machine([scan("host", SCAN_NO_LOGIN), login])
    assert item.status == "surface_only" and "SSH" in detail(item, "login_not_used")
    assert "no_credentials" not in kinds(item)


def test_available_patch_assessment_counts_as_local_checks() -> None:
    item = machine([scan("host", SCAN_NO_LOGIN), row("host", 117887)])
    assert item.status != "surface_only" and "no_credentials" not in kinds(item)


def test_access_rows_from_an_old_scan_say_nothing_about_the_latest() -> None:
    latest = scan("host", SCAN_NO_LOGIN, last_found="2026-10-01T00:00:00Z")
    old_login = row("host", 117887, last_found="2026-01-01T00:00:00Z")
    assert machine([latest, old_login]).status == "surface_only"
    credentialed = scan("host", last_found="2026-10-01T00:00:00Z")
    old_failure = row("host", 104410, output="Proto:      SSH\n", last_found="2026-01-01T00:00:00Z")
    old_patch_failure = row("host", 21745, last_found="2026-01-01T00:00:00Z")
    assert machine([credentialed, old_failure, old_patch_failure]).status == "covered"


def test_the_scan_id_decides_which_rows_belong_to_the_latest_scan() -> None:
    latest = scan("host", SCAN_NO_LOGIN, last_found="2026-10-01T12:00:00Z", scan={"uuid": "b"})
    earlier_that_day = row("host", 117887, last_found="2026-10-01T08:00:00Z", scan={"uuid": "a"})
    assert machine([latest, earlier_that_day]).status == "surface_only"
    long_scan = row("host", 117887, last_found="2026-09-28T08:00:00Z", scan={"uuid": "b"})
    assert machine([latest, long_scan]).status != "surface_only"


def test_older_rows_still_count_for_what_isnt_about_access() -> None:
    latest = scan("host", last_found="2026-10-01T00:00:00Z")
    old_os = row("host", 11936, output="Confidence level : 50\n", last_found="2026-01-01T00:00:00Z")
    assert "ambiguous_os" in kinds(machine([latest, old_os], operating_systems=["Linux"]))


def test_failed_assessment_makes_a_credentialed_scan_surface_only() -> None:
    item = machine([scan("host"), row("host", 21745)])
    assert item.status == "surface_only" and "patch_assessment_failed" in kinds(item)


@pytest.mark.parametrize(("plugin_id", "kind"), [(110385, "insufficient_privilege")])
def test_limited_access_is_partial(plugin_id: int, kind: str) -> None:
    item = machine([scan("host"), row("host", plugin_id)])
    assert item.status == "partial" and kind in kinds(item)


def test_unavailable_assessment_only_matters_without_local_checks() -> None:
    assert "patch_assessment_unavailable" not in kinds(machine([scan("host"), row("host", 117886)]))
    assert "patch_assessment_unavailable" in kinds(machine([scan("host", SCAN_NO_LOGIN), row("host", 117886)]))


def test_findings_without_scan_information_are_unknown_not_unscanned() -> None:
    item = machine([row("host", 1, severity="critical")])
    assert item.status == "unknown" and "no_scan_metadata" in kinds(item) and item.severe_findings == 1


def test_scan_row_that_omits_credentials_does_not_fail_open() -> None:
    item = machine([scan("host", "Port scanner(s) : nessus_syn_scanner\n")])
    assert item.status == "unknown"


def test_export_without_informational_rows_warns() -> None:
    report = scan_coverage([asset("host")], [row("host", 1, severity="high")])
    assert "informational" in report.warnings[0]
    assert "No machine in this data" in render_coverage_markdown(report)


def test_empty_field_value_does_not_read_the_next_line() -> None:
    output = "Credentialed checks : yes\nPort scanner(s) : \nPort range : default\n"
    assert "ports_not_probed" in kinds(machine([scan("host", output)]))


@pytest.mark.parametrize("reverse", [False, True])
def test_newest_scan_row_wins_in_any_order(reverse: bool) -> None:
    rows = [scan("host", SCAN_NO_LOGIN, last_found="2026-01-01T00:00:00.000Z"), scan("host", SCAN_OK)]
    report = scan_coverage([asset("host")], rows[::-1] if reverse else rows)
    assert report.machines[0].status != "surface_only"
    assert report.scan_settings["Port range"] == {"default": 1}


def test_severe_findings_the_latest_scan_did_not_recheck_are_stale() -> None:
    findings = [
        scan("host", SCAN_NO_LOGIN),
        row("host", 1, severity="critical", last_found="2026-10-10T00:00:00.000Z"),
        row("host", 2, severity="high", last_found="2026-10-25T00:00:00.000Z"),
        row("host", 3, severity="high", last_found="2026-10-25T00:00:01.000Z"),
        row("host", 4, severity="low", last_found="2026-01-01T00:00:00.000Z"),
    ]
    text = detail(machine(findings), "stale_findings")
    assert text.startswith("2 severe findings") and "22 days" in text


def test_fixed_rows_are_ignored_everywhere() -> None:
    findings = [
        scan("host"),
        row("host", 1, severity="critical", state="FIXED"),
        row("gone", 19506, output=SCAN_NO_LOGIN, state="FIXED"),
    ]
    report = scan_coverage([asset("host"), asset("gone")], findings)
    by_name = {item.name: item for item in report.machines}
    assert by_name["host"].severe_findings == 0 and by_name["gone"].status == "no_scan_data"
    assert report.open_findings == 1


@pytest.mark.parametrize(
    ("scanners", "expected"),
    [
        ("nessus_syn_scanner", False),
        ("netstat", True),
        ("wmi_netstat", True),
        ("snmp_scanner", True),
        ("netstat, nessus_syn_scanner", False),
        ("netstat, snmp_scanner", True),
        (None, True),
    ],
)
def test_ports_not_probed_only_without_a_network_scanner(scanners: str | None, expected: bool) -> None:
    line = "Port scanner(s) : nessus_syn_scanner\n"
    output = SCAN_OK.replace(line, f"Port scanner(s) : {scanners}\n" if scanners else "")
    assert ("ports_not_probed" in kinds(machine([scan("host", output)]))) is expected


@pytest.mark.parametrize(
    ("web_row", "expected"),
    [
        (None, False),
        (row("host", 2, port={"port": 8080, "service": "www"}), True),
        (row("host", 2, port={"port": 8443, "service": "https"}), True),
        (row("host", 24260), True),
        (row("host", 2, port={"port": 22, "service": "ssh"}), False),
    ],
)
def test_web_gap_needs_a_web_service(web_row: dict[str, Any] | None, expected: bool) -> None:
    findings = [scan("host"), *([web_row] if web_row else [])]
    assert ("web_tests_disabled" in kinds(machine(findings))) is expected


@pytest.mark.parametrize(
    ("output", "expected"),
    [
        (
            f"{SCAN_BASE}CGI scanning : enabled\nWeb application tests : enabled\n",
            False,
        ),
        (
            f"{SCAN_BASE}CGI scanning : disabled\nWeb application tests : enabled\n",
            True,
        ),
        (
            f"{SCAN_BASE}CGI scanning : enabled\nWeb application tests : disabled\n",
            True,
        ),
    ],
)
def test_web_gap_needs_tests_disabled(output: str, expected: bool) -> None:
    findings = [scan("host", output), row("host", 24260)]
    assert ("web_tests_disabled" in kinds(machine(findings))) is expected


def test_superseded_gap_needs_a_patch_finding() -> None:
    assert "superseded_patches" not in kinds(machine([scan("host")]))
    assert "superseded_patches" in kinds(machine([scan("host"), row("host", 2, plugin={"has_patch": True})]))


@pytest.mark.parametrize(
    ("names", "output", "expected"),
    [
        (["Ubuntu 22.04"], "Confidence level : 100", False),
        (["Ubuntu 22.04"], "Confidence level : 70", False),
        (["Ubuntu 22.04"], "Confidence level : 69", True),
        (["Linux 4\nLinux 5"], "Confidence level : 100", False),
        (["Linux 4", "Linux 5"], "", True),
        (["Linux 4", "Linux 4"], "", False),
        ([], "Confidence level : 100", True),
    ],
)
def test_ambiguous_os(names: list[str], output: str, expected: bool) -> None:
    item = machine([scan("host"), row("host", 11936, output=output)], operating_systems=names)
    assert ("ambiguous_os" in kinds(item)) is expected


def test_low_gaps_alone_still_count_as_covered() -> None:
    assert machine([scan("host"), row("host", 2, plugin={"has_patch": True})]).status == "covered"


def test_shared_addresses_and_macs_count_but_non_identifying_ones_do_not() -> None:
    mac = [{"name": "eth0", "mac_addresses": ["AA:BB:CC:00:00:01"]}]
    assets = [
        asset("a", ipv4s=["10.0.0.5", "127.0.0.1", "128.0.0.1"]),
        asset("b", ipv4s=["10.0.0.5"]),
        asset("c", ipv4s=["127.0.0.1", "128.0.0.1"]),
        asset("d", ipv4s=["128.0.0.1", "169.254.1.1"]),
        asset("e", ipv4s=["169.254.1.1"]),
        asset("m1", interfaces=mac),
        asset("m2", interfaces=[{"name": "eth1", "mac_addresses": ["aa:bb:cc:00:00:01"]}]),
        asset("v1", interfaces=[{"name": "vip", "virtual": True, "mac_addresses": ["aa:bb:cc:00:00:09"]}]),
        asset("v2", interfaces=[{"name": "vip", "virtual": True, "mac_addresses": ["aa:bb:cc:00:00:09"]}]),
    ]
    by_name = {item.name: "shared_identity" in kinds(item) for item in scan_coverage(assets, []).machines}
    assert by_name == {
        "a": True,
        "b": True,
        "c": False,
        "d": False,
        "e": False,
        "m1": True,
        "m2": True,
        "v1": False,
        "v2": False,
    }


def test_not_recently_seen_is_measured_from_the_newest_data() -> None:
    assets = [
        asset("old", last_seen="2026-08-02T23:59:59.000Z"),
        asset("edge", last_seen="2026-08-03T00:00:00.000Z"),
        asset("new"),
    ]
    by_name = {item.name: item for item in scan_coverage(assets, []).machines}
    assert "not_recently_seen" in kinds(by_name["old"])
    assert "not_recently_seen" not in kinds(by_name["edge"]) | kinds(by_name["new"])
    later = scan_coverage([asset("new")], [], as_of=datetime(2027, 6, 1, tzinfo=UTC))
    assert "not_recently_seen" in kinds(later.machines[0])


def test_finding_for_an_asset_missing_from_the_export_is_kept() -> None:
    finding = scan("ghost", SCAN_NO_LOGIN)
    finding["asset"] = {"uuid": "ghost", "hostname": "ghost-host", "device_type": "router"}
    item = scan_coverage([], [finding]).machines[0]
    assert (item.name, item.status, item.system_types) == ("ghost-host", "surface_only", ["router"])


def test_summary_counts_and_ordering() -> None:
    assets = [
        asset("server"),
        asset("gear", system_types=["router"]),
        asset("passive", sources=[{"name": "PVS"}]),
        asset("good"),
        asset("noisy"),
    ]
    findings = [
        scan("server", SCAN_NO_LOGIN),
        scan("gear", SCAN_NO_LOGIN),
        scan("good"),
        scan("noisy", SCAN_NO_LOGIN),
        row("noisy", 1, severity="critical"),
        row("noisy", 2, severity="high"),
        row("good", 1, severity="low"),
    ]
    report = scan_coverage(assets, findings)
    by_status = {item.status: item for item in report.statuses}
    assert by_status["surface_only"].machines == 3 and by_status["surface_only"].severe_findings == 2
    assert by_status["surface_only"].median_severe_findings == 0
    assert by_status["no_scan_data"].machines == 1 and by_status["covered"].machines == 1
    assert [item.name for item in report.machines] == ["gear", "server", "noisy", "passive", "good"]
    assert report.gaps[0].impact == "high" and report.scan_settings["Port range"] == {"default": 4}
    assert report.open_findings == 7


def test_scan_settings_keep_only_the_most_common_values() -> None:
    assets = [asset(f"h{index}") for index in range(8)]
    findings = [scan(f"h{index}", f"Credentialed checks : yes\nPort range : {index}\n") for index in range(8)]
    assert len(scan_coverage(assets, findings).scan_settings["Port range"]) == 5


def test_markdown_is_ascii_escapes_cells_and_states_the_scope() -> None:
    name = "a|b—c"
    text = render_coverage_markdown(scan_coverage([asset(name)], [scan(name, SCAN_NO_LOGIN)]))
    assert text.isascii() and "a/b" in text and "a|b" not in text
    assert "1 of 1 scanned machines had no local checks" in text and "no local checks ran (1)" in text
    assert "Tenable VM scan data only" in text and "| Port range | default | 1 |" in text
    assert "`no_credentials`" in text


def test_markdown_denominator_leaves_out_assets_without_scan_data() -> None:
    report = scan_coverage([asset("host"), asset("passive")], [scan("host", SCAN_NO_LOGIN)])
    assert "1 of 1 scanned" in render_coverage_markdown(report)


@pytest.mark.parametrize("limit", [2, 0, -1])
def test_markdown_limit_truncates_lists_and_stays_positive(limit: int) -> None:
    assets = [asset(f"h{index}") for index in range(4)]
    report = scan_coverage(assets, [scan(f"h{i}", SCAN_NO_LOGIN) for i in range(4)])
    shown = max(1, limit)
    text = render_coverage_markdown(report, limit=limit)
    assert f"- and {4 - shown} more" in text and f"first {shown} of 4" in text


def test_markdown_leaves_passive_assets_out_of_the_machine_list() -> None:
    report = scan_coverage([asset("passive")], [])
    assert "Machines with gaps" not in render_coverage_markdown(report)


@pytest.mark.parametrize(
    "bad",
    [
        {"asset": {"uuid": "h"}, "plugin": 5, "port": None, "last_found": "soon"},
        {"asset": {"uuid": "h"}, "plugin": {"id": 2}, "port": {"port": [1]}, "severity": ["high"]},
        {"asset": {"uuid": "h"}, "plugin": {"id": 2}, "port": {"port": {"a": 1}}, "severity": {"a": 1}},
        {"asset": None},
        "not a row",
    ],
)
def test_malformed_rows_do_not_crash(bad: Any) -> None:
    report = scan_coverage([{"id": "h", "sources": 5, "timestamps": "x"}, "x"], [scan("h"), bad])  # type: ignore[list-item]
    assert [item.name for item in report.machines] == ["h"]


def test_severity_case_does_not_hide_a_finding() -> None:
    assert machine([scan("host"), row("host", 1, severity="Critical")]).severe_findings == 1


def test_cli_from_files(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assets, findings = tmp_path / "assets.json", tmp_path / "findings.json"
    assets.write_text(json.dumps([asset("h1"), asset("h2")]), encoding="utf-8")
    findings.write_text(json.dumps([scan("h1", SCAN_NO_LOGIN), scan("h2", SCAN_NO_LOGIN)]), encoding="utf-8")
    args = ["tenable", "coverage", "--assets-file", str(assets), "--findings-file", str(findings)]
    assert main([*args, "--limit", "1"]) == 0
    assert "- and 1 more" in capsys.readouterr().out
    out = tmp_path / "report.json"
    assert main([*args, "--format", "json", "--out", str(out)]) == 0
    assert json.loads(out.read_text(encoding="utf-8"))["machines"][0]["looks_clean"] is True


def test_cli_needs_both_files(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["tenable", "coverage", "--assets-file", "a.json"]) == 1
    assert "both" in capsys.readouterr().err


def test_cli_live_without_keys_reports_it(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.delenv("TENABLE_ACCESS_KEY", raising=False)
    monkeypatch.delenv("TENABLE_SECRET_KEY", raising=False)
    assert main(["tenable", "coverage"]) == 1
    assert "TENABLE_ACCESS_KEY" in capsys.readouterr().err


class FakeExportHttp:
    """Answers Tenable's export endpoints from canned status and chunk responses."""

    def __init__(self, status: Any = None, chunk: Any = None, **_: Any) -> None:
        self.status = status if status is not None else {"status": "FINISHED", "chunks_available": [1]}
        self.chunk = chunk
        self.bodies: dict[str, Any] = {}

    async def post_json(self, url: str, body: Any, **_: Any) -> dict[str, str]:
        kind = "assets" if "assets" in url else "vulns"
        self.bodies[kind] = body
        return {"export_uuid": kind}

    async def get_json(self, url: str, **_: Any) -> Any:
        if url.endswith("/status"):
            return self.status
        return self.chunk if self.chunk is not None else [{"source": "assets" if "/assets/" in url else "vulns"}]


@pytest.fixture
def tenable_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TENABLE_ACCESS_KEY", "synthetic-access")
    monkeypatch.setenv("TENABLE_SECRET_KEY", "synthetic-secret")


@pytest.mark.usefixtures("tenable_keys")
def test_tenant_read_asks_for_open_findings_only() -> None:
    http = FakeExportHttp()
    assets, findings = asyncio.run(TenableOneClient(http).scan_inventory())  # type: ignore[arg-type]
    assert assets == [{"source": "assets"}] and findings == [{"source": "vulns"}]
    assert http.bodies["vulns"]["filters"]["state"] == ["OPEN", "REOPENED"]
    assert http.bodies["vulns"]["num_assets"] == ASSETS_PER_CHUNK


@pytest.mark.usefixtures("tenable_keys")
@pytest.mark.parametrize(
    ("status", "chunk"),
    [
        ({"status": "FINISHED", "chunks_available": [1], "chunks_failed": [2]}, None),
        ({"status": "FINISHED", "chunks_available": [1], "chunks_cancelled": [2]}, None),
        ({"status": "ERROR", "chunks_available": []}, None),
        ("not a status", None),
        (None, {"error": "expired"}),
    ],
)
def test_incomplete_export_fails_instead_of_looking_complete(status: Any, chunk: Any) -> None:
    http = FakeExportHttp(status=status, chunk=chunk)
    with pytest.raises(TenableError):
        asyncio.run(TenableOneClient(http).scan_inventory())  # type: ignore[arg-type]


class CapturingHttp(FakeExportHttp):
    kwargs: ClassVar[dict[str, Any]] = {}

    def __init__(self, **kwargs: Any) -> None:
        super().__init__()
        CapturingHttp.kwargs.update(kwargs)

    async def __aenter__(self) -> "CapturingHttp":
        return self

    async def __aexit__(self, *_: object) -> None:
        return None


@pytest.mark.usefixtures("tenable_keys")
def test_cli_and_mcp_live_reads_use_the_tenant_export_size_cap(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("porygon_mitigator.integrations.tenable_one.client.Http", CapturingHttp)
    CapturingHttp.kwargs.clear()
    assert main(["tenable", "coverage"]) == 0
    assert CapturingHttp.kwargs["max_bytes"] == EXPORT_MAX_BYTES
    capsys.readouterr()
    CapturingHttp.kwargs.clear()
    assert "error" not in _tool({})
    assert CapturingHttp.kwargs["max_bytes"] == EXPORT_MAX_BYTES


def _tool(arguments: dict[str, Any]) -> dict[str, Any]:
    result = asyncio.run(server.call_tool("scan_coverage", arguments))
    content = getattr(result, "structured_content", None)
    assert isinstance(content, dict)
    return content


def test_mcp_tool_lists_scanned_machines_first_and_limits_them() -> None:
    assets = [asset(f"p{index}", sources=[{"name": "PVS"}]) for index in range(3)]
    assets += [asset(f"h{index}") for index in range(3)] + [asset("good")]
    findings = [scan(f"h{index}", SCAN_NO_LOGIN) for index in range(3)] + [scan("good")]
    result = _tool({"tenable_assets": assets, "tenable_findings": findings, "max_machines": 2})
    assert [item["name"] for item in result["machines"]] == ["h0", "h1"]
    assert result["machines_with_gaps"] == 3 and result["machines_total"] == 7
    assert "first 2 of 3" in result["report_markdown"] and "tenant data" in result["note"]
    assert sorted(result["machines_without_scan_data"]) == ["p0", "p1"]
    section = result["report_markdown"].split("Known machines with no scan data (first 2 of 3)")[1]
    assert "p0" in section and "p1" in section and "p2" not in section


@pytest.mark.parametrize(("requested", "expected"), [(0, 1), (-3, 1), (9999, 3)])
def test_mcp_tool_clamps_the_limit(requested: int, expected: int) -> None:
    assets = [asset(f"h{index}") for index in range(3)]
    findings = [scan(f"h{index}", SCAN_NO_LOGIN) for index in range(3)]
    result = _tool({"tenable_assets": assets, "tenable_findings": findings, "max_machines": requested})
    assert len(result["machines"]) == expected


def test_mcp_tool_needs_both_lists_or_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    assert "both" in _tool({"tenable_assets": []})["error"]
    monkeypatch.delenv("TENABLE_ACCESS_KEY", raising=False)
    monkeypatch.delenv("TENABLE_SECRET_KEY", raising=False)
    assert "TENABLE_ACCESS_KEY" in _tool({})["error"]


def test_mcp_tool_is_read_only_and_open_world() -> None:
    tools = {tool.name: tool for tool in asyncio.run(server.list_tools())}
    hints = tools["scan_coverage"].annotations
    assert hints is not None and hints.read_only_hint is True and hints.open_world_hint is True
