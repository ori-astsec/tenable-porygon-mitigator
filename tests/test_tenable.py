import json

import pytest

from porygon_mitigator.cli import main
from porygon_mitigator.integrations.tenable_one import plugin_outputs
from porygon_mitigator.integrations.tenable_one.config import TenableConfig
from porygon_mitigator.integrations.tenable_one.mapper import os_info, profile_from_tenable
from porygon_mitigator.models.actions import identifier

from .conftest import ROOT

ASSET = json.loads((ROOT / "examples/tenable/asset.json").read_text(encoding="utf-8"))
FINDINGS = json.loads((ROOT / "examples/tenable/findings.json").read_text(encoding="utf-8"))


def test_profile_from_tenable_export() -> None:
    profile = profile_from_tenable(ASSET, FINDINGS)
    assert profile.name == "bastion-01.example.internal" and profile.source == "tenable_one"
    assert (profile.os.platform, profile.os.distribution, profile.os.version) == ("linux", "ubuntu", "22.04")
    packages = {s.package: s.version for s in profile.installed_software if s.package}
    assert packages["openssh-server"] == "1:8.9p1-3ubuntu0.6"
    assert [f.cve for f in profile.findings] == ["CVE-2024-6387"]
    assert [t.vendor for t in profile.security_tools] == ["CrowdStrike"]
    assert profile.internet_exposed is True and profile.open_ports[0].port == 22


@pytest.mark.parametrize(
    ("name", "platform", "distribution", "vendor"),
    [
        ("Microsoft Windows Server 2019 Standard Build 17763", "windows", "windows", None),
        ("Palo Alto Networks PAN-OS 10.2.8-h3", "network_os", "panos", "Palo Alto Networks"),
        ("Fortinet FortiOS 7.2.5", "network_os", "fortios", "Fortinet"),
        ("Linux Kernel 3.10 on Check Point Gaia R81.20", "network_os", "gaia", "Check Point"),
        ("Red Hat Enterprise Linux 8.6", "linux", "rhel", None),
        ("Mac OS X 14.5", "macos", "macos", None),
    ],
)
def test_os_info(name: str, platform: str, distribution: str, vendor: str | None) -> None:
    info, found_vendor = os_info([name])
    assert (info.platform, info.distribution, found_vendor) == (platform, distribution, vendor)


def test_plugin_output_parsers() -> None:
    rpm = "openssh-server-8.7p1-38.el9.x86_64|(none)\nsudo-1.9.5p2-10.el9_3.x86_64|(none)\n"
    found = plugin_outputs.installed_software(22869, rpm)
    assert ("openssh-server", "8.7p1-38.el9") in [(s.package, s.version) for s in found]
    windows = "Microsoft Office Professional Plus 2019  [version 16.0.10386.20017]  [installed on 2022/01/10]"
    assert plugin_outputs.installed_software(20811, windows)[0].product == "Microsoft Office Professional Plus 2019"
    wmi = "+ Process 'svchost.exe' (pid 1100) is listening on 0.0.0.0:135 (tcp)"
    assert [(p.port, p.protocol) for p in plugin_outputs.listening_ports(34252, wmi)] == [(135, "tcp")]
    assert plugin_outputs.service_states(10456, "Spooler : Print Spooler")["spooler"] == "running"


def test_profile_reads_listener_json_and_service_lists() -> None:
    listeners = json.dumps({
        "listening": [
            {"port": 445, "protocol": "TCP", "service_name": None},
            {"port": 5353, "protocol": "UDP", "service_name": "mdns"},
        ],
        "closed": {"TCP": {"discrete": [], "ranges": [[1, 444]]}},
    })
    services = (
        "\nActive Services :\n\nPrint Spooler [ Spooler ] \nExample Agent [ Example Agent ] \n"
        "\nInactive Services :\n\nFax [ Fax ] \nHub [ Example.Hub.service ] \n"
    )
    profile = profile_from_tenable({"id": "synthetic"}, [
        {"plugin": {"id": 34252}, "output": listeners},
        {"plugin": {"id": 10456}, "output": services},
    ])
    assert [(p.port, p.protocol, p.service_names) for p in profile.open_ports] == [
        (445, "tcp", []), (5353, "udp", ["mdns"]),
    ]
    assert profile.config_state is not None
    assert profile.config_state.services == {
        "spooler": "running", "example_agent": "running", "fax": "stopped", "example.hub": "stopped",
    }


@pytest.mark.parametrize("reverse", [False, True])
def test_disabled_start_type_beats_inactive_but_not_running(reverse: bool) -> None:
    states = "\nActive Services :\n\nBusy [ Busy ] \n\nInactive Services :\n\nOff [ Off ] \nIdle [ Idle ] \n"
    config = (
        "\nThe following services must be started manually :\n\n  Idle startup parameters :\n    Service name : Idle\n"
        "\nThe following services are disabled :\n\n  Off startup parameters :\n    Service name : Off\n"
        "\n  Busy startup parameters :\n    Service name : Busy\n"
    )
    rows = [{"plugin": {"id": 10456}, "output": states}, {"plugin": {"id": 44401}, "output": config}]
    profile = profile_from_tenable({"id": "synthetic"}, rows[::-1] if reverse else rows)
    assert profile.config_state is not None
    assert profile.config_state.services == {"busy": "running", "off": "disabled", "idle": "stopped"}


@pytest.mark.parametrize(
    "output",
    [
        "[1]",
        "3",
        '{"listening": {"x": 1}}',
        '{"closed": {}}',
        '{"listening": [{"port": ' + "1" * 5000 + "}]}",
        "[" * 200000,
    ],
)
def test_listener_output_that_is_not_the_json_form_falls_back_safely(output: str) -> None:
    assert plugin_outputs.listening_ports(34252, output) == []


def test_listener_json_skips_bad_items() -> None:
    output = json.dumps({"listening": ["x", {"port": "445"}, {"port": 70000}, {"port": 22, "protocol": "TCP"}]})
    assert [p.port for p in plugin_outputs.listening_ports(25221, output)] == [22]


def test_listener_json_ignores_ports_in_other_fields() -> None:
    output = json.dumps({"listening": [], "note": "see 80/tcp"})
    assert plugin_outputs.listening_ports(25221, output) == []


def test_bracket_text_without_section_headers_uses_the_text_form() -> None:
    assert plugin_outputs.service_states(10456, "See note [ KB1 ]\nSpooler : Print Spooler") == {"spooler": "running"}


def test_service_keys_match_disable_service_targets() -> None:
    output = "\nActive Services :\n\nDb [ MSSQL$MICROSOFT##WID ] \nEmpty [   ] \n"
    assert plugin_outputs.service_states(10456, output) == {identifier("mssql$microsoft##wid"): "running"}


def test_profile_from_single_asset_lookup() -> None:
    """GET /assets/{uuid} uses singular field names; ports also come from the findings' own port field."""
    asset = {"id": "1f3c9a20", "fqdn": ["srv1.lab.example"], "hostname": ["srv1"], "ipv4": ["10.0.48.38"],
             "operating_system": ["Microsoft Windows Server 2019 Standard Build 17763"],
             "system_type": ["general-purpose"]}
    findings = [{"plugin": {"id": 10940, "cve": []}, "port": {"port": 3389, "protocol": "TCP", "service": "msrdp"},
                 "state": "OPEN"},
                {"plugin": {"id": 97833, "cve": ["CVE-2017-0144"]}, "port": {"port": 445, "protocol": "TCP"},
                 "state": "FIXED"}]
    profile = profile_from_tenable(asset, findings)
    assert (profile.os.platform, profile.roles) == ("windows", ["general-purpose"])
    assert [(p.port, p.service_names) for p in profile.open_ports] == [(3389, ["msrdp"])]  # a fixed finding is no port
    assert [(f.cve, f.state) for f in profile.findings] == [("CVE-2017-0144", "fixed")]


def test_asset_with_findings_scopes_the_vuln_export_by_address(monkeypatch: pytest.MonkeyPatch) -> None:
    import asyncio
    from typing import Any

    from porygon_mitigator.integrations.tenable_one.client import TenableOneClient

    monkeypatch.setenv("TENABLE_ACCESS_KEY", "a" * 8)
    monkeypatch.setenv("TENABLE_SECRET_KEY", "b" * 8)
    posted: list[dict[str, Any]] = []

    class FakeHttp:
        async def get_json(self, url: str, **_kwargs: Any) -> Any:
            if url.endswith("/assets/uuid-1"):
                return {"id": "uuid-1", "ipv4": ["10.0.0.5"], "operating_system": ["Ubuntu Linux 24.04"]}
            if url.endswith("/status"):
                return {"status": "FINISHED", "chunks_available": [1]}
            return [{"asset": {"uuid": "uuid-1"}, "plugin": {"id": 1}},
                    {"asset": {"uuid": "uuid-2"}, "plugin": {"id": 2}}]

        async def post_json(self, url: str, body: dict[str, Any], **_kwargs: Any) -> Any:
            posted.append(body)
            return {"export_uuid": "export-1"}

    asset, findings = asyncio.run(TenableOneClient(FakeHttp()).asset_with_findings("uuid-1"))  # type: ignore[arg-type]
    assert asset["id"] == "uuid-1" and [row["plugin"]["id"] for row in findings] == [1]
    assert posted[0]["filters"]["cidr_range"] == "10.0.0.5/32" and "asset_uuid" not in posted[0]["filters"]


def test_config_never_exposes_keys_in_repr(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TENABLE_ACCESS_KEY", "a" * 8)
    monkeypatch.setenv("TENABLE_SECRET_KEY", "b" * 8)
    config = TenableConfig()
    assert config.configured and "a" * 8 not in repr(config)


def test_cli_tenable_profile_and_mitigate(capsys: pytest.CaptureFixture[str]) -> None:
    asset, findings = str(ROOT / "examples/tenable/asset.json"), str(ROOT / "examples/tenable/findings.json")
    assert main(["tenable", "profile", "--asset-file", asset, "--findings-file", findings]) == 0
    assert json.loads(capsys.readouterr().out)["source"] == "tenable_one"
    code = main(["mitigate", "CVE-2022-30190", "--tenable-asset", asset, "--tenable-findings", findings,
                 "--offline"])
    assert code == 0 and "Verdict:" in capsys.readouterr().out
