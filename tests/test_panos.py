"""PAN-OS collection from canned XML API answers: no device is contacted."""

from __future__ import annotations

import asyncio
import json
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

import httpx
import pytest

from porygon_mitigator.flow.models import Device, Environment, FirewallRule, Zone
from porygon_mitigator.flow.sources import _device_from_firewall
from porygon_mitigator.integrations.panos import mock
from porygon_mitigator.integrations.panos.client import PanosClient, PanosError, members
from porygon_mitigator.integrations.panos.collect import _rule, collect, cve_coverage

DG = "/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='branch']"
VSYS = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']"


def ok(body: str) -> str:
    return f'<response status="success"><result>{body}</result></response>'


SIGNATURES = ok("""<vulnerability>
<entry name="55001"><threatname>Windows DNS Server RCE</threatname><severity>critical</severity>
 <category>code-execution</category><cve><member>CVE-2020-1350</member></cve><default-action>reset-both</default-action>
 <affected-host><server>yes</server><client>no</client></affected-host></entry>
<entry name="55002"><threatname>Browser Memory Corruption</threatname><severity>high</severity>
 <category>overflow</category><cve><member>CVE-2099-0002</member></cve><default-action>alert</default-action>
 <affected-host><server>no</server><client>yes</client></affected-host></entry>
<entry name="55003"><threatname>Old Low Bug</threatname><severity>low</severity><category>info-leak</category>
 <cve><member>CVE-2099-0003</member></cve><default-action>alert</default-action>
 <affected-host><server>yes</server><client>no</client></affected-host></entry>
</vulnerability>""")

PROFILES = ok("""<vulnerability><entry name="strict">
 <rules>
  <entry name="crit-high-server"><action><reset-both/></action><threat-name>any</threat-name><host>server</host>
   <category>any</category><severity><member>critical</member><member>high</member></severity></entry>
  <entry name="rest"><action><default/></action><threat-name>any</threat-name><host>any</host>
   <category>any</category><severity><member>any</member></severity></entry>
 </rules>
 <threat-exception><entry name="55003"><action><drop/></action></entry></threat-exception>
</entry></vulnerability>""")

LOCAL_RULES = ok("""<rules>
 <entry name="publish-dns"><from><member>untrust</member></from><to><member>dmz</member></to>
  <source><member>any</member></source><destination><member>dns1</member></destination>
  <application><member>dns</member></application><service><member>application-default</member></service>
  <action>allow</action><profile-setting><group><member>default-group</member></group></profile-setting></entry>
</rules>""")

PRE_RULES = ok("""<rules><entry name="block-bad"><from><member>any</member></from><to><member>any</member></to>
 <source><member>any</member></source><destination><member>any</member></destination>
 <application><member>any</member></application><service><member>any</member></service><action>deny</action>
</entry></rules>""")

ROUTES = ok("""<flags>flags: A:active</flags>
 <entry><virtual-router>default</virtual-router><destination>0.0.0.0/0</destination><nexthop>198.51.100.1</nexthop>
  <flags>A S</flags><interface>ethernet1/1</interface></entry>
 <entry><virtual-router>default</virtual-router><destination>10.9.9.0/24</destination><nexthop>0.0.0.0</nexthop>
  <flags>S</flags><interface>ethernet1/2</interface></entry>""")

ANSWERS = {
    "<show><system><info></info></system></show>": ok(
        "<system><hostname>edge-fw</hostname><model>PA-820</model><sw-version>11.1.1</sw-version>"
        "<threat-version>8842-9130</threat-version></system>"),
    "<show><predefined><xpath>/predefined/threats/vulnerability</xpath></predefined></show>": SIGNATURES,
    "<show><routing><route></route></routing></show>": ROUTES,
    f"{VSYS}/profiles/vulnerability": PROFILES,
    f"{VSYS}/profile-group": ok("<profile-group><entry name='default-group'><vulnerability><member>strict</member>"
                                "</vulnerability></entry></profile-group>"),
    f"{VSYS}/rulebase/security/rules": LOCAL_RULES,
    f"{VSYS}/zone": ok("<zone><entry name='untrust'><network><layer3><member>ethernet1/1</member></layer3></network>"
                       "</entry><entry name='dmz'><network><layer3><member>ethernet1/2</member></layer3></network>"
                       "</entry></zone>"),
    f"{VSYS}/address": ok("<address><entry name='dns1'><ip-netmask>10.9.9.53/32</ip-netmask></entry></address>"),
    f"{DG}/pre-rulebase/security/rules": PRE_RULES,
}


def handler(seen: list[dict[str, str]]) -> httpx.MockTransport:
    def respond(request: httpx.Request) -> httpx.Response:
        params = {key: values[0] for key, values in parse_qs(request.url.query.decode()).items()}
        seen.append(params)
        assert request.headers["X-PAN-KEY"] == "test-key"
        if params["type"] == "log":
            if "job-id" in params:
                return httpx.Response(200, text=ok(
                    "<job><status>FIN</status></job><log><logs>"
                    "<entry><threatid>Windows DNS Server RCE(55001)</threatid><action>reset-both</action>"
                    "<repeatcnt>3</repeatcnt></entry>"
                    "<entry><tid>55001</tid><action>alert</action></entry></logs></log>"))
            return httpx.Response(200, text=ok("<job>7</job>"))
        key = params.get("cmd") or params.get("xpath", "")
        return httpx.Response(200, text=ANSWERS.get(key, ok("")))

    return httpx.MockTransport(respond)


def _collect(seen: list[dict[str, str]]) -> dict[str, object]:
    async def run() -> dict[str, object]:
        transport = handler(seen)
        async with PanosClient("fw.example.test", api_key="test-key", transport=transport) as client, \
                PanosClient("fw.example.test", api_key="test-key", transport=transport) as panorama:
            return await collect(client, panorama=panorama, device_group="branch")

    return asyncio.run(run())


def test_profile_rules_resolve_to_what_is_blocked() -> None:
    export = _collect([])
    profile = export["vulnerability_profiles"]["strict"]  # type: ignore[index]
    # 55001: critical server sig -> reset-both. 55002: client sig falls to `rest`, default action alert.
    # 55003: low, `rest` says alert, but the threat exception drops it.
    assert profile["blocked_threat_ids"] == ["55001", "55003"]
    assert profile["alerted_threat_ids"] == ["55002"]


def test_export_reads_as_a_flow_device() -> None:
    export = _collect([])
    assert [rule["name"] for rule in export["security_rules"]] == ["block-bad", "publish-dns"]  # type: ignore[index]
    assert export["virtual_router"]["routes"] == [  # type: ignore[index]
        {"destination": "0.0.0.0/0", "nexthop": "198.51.100.1", "interface": "ethernet1/1", "zone": "untrust",
         "nexthop_device": None}]
    device = _device_from_firewall(export)  # type: ignore[arg-type]
    assert device.threat_prevention
    assert device.vulnerability_profiles["strict"] == ["55001", "55003"]
    publish = next(rule for rule in device.rules if rule.name == "publish-dns")
    assert publish.vulnerability_profile == "strict"
    assert publish.destination == ["10.9.9.53/32"]


def test_threat_exceptions_are_never_read_as_blocks() -> None:
    export = _collect([])
    for profile in export["vulnerability_profiles"].values():  # type: ignore[attr-defined]
        profile.pop("blocked_threat_ids")
        profile["threat_exceptions"] = ["55002"]  # an override, which may be allow or alert
    device = _device_from_firewall(export)  # type: ignore[arg-type]
    assert device.vulnerability_profiles["strict"] == []


def test_coverage_needs_a_blocking_profile_on_an_allow_rule() -> None:
    rows = {row["cve"]: row for row in cve_coverage(_collect([]), ["CVE-2020-1350", "CVE-2099-0002",
                                                                     "CVE-2021-44228"])}
    assert rows["CVE-2020-1350"]["enforced"] and rows["CVE-2020-1350"]["enforcing_rules"] == ["publish-dns"]
    assert rows["CVE-2020-1350"]["hits"] == 4 and rows["CVE-2020-1350"]["blocked_hits"] == 3
    assert rows["CVE-2099-0002"]["installed"] and not rows["CVE-2099-0002"]["enforced"]
    assert not rows["CVE-2021-44228"]["installed"]


def test_only_read_calls_reach_the_device() -> None:
    seen: list[dict[str, str]] = []
    _collect(seen)
    assert {call["type"] for call in seen} <= {"op", "config", "log"}
    assert all(call["cmd"].startswith("<show>") for call in seen if call["type"] == "op")
    assert all(call["action"] in ("get", "show") for call in seen if call["type"] == "config")


@pytest.mark.parametrize("params", [
    {"type": "op", "cmd": "<request><restart><system/></restart></request>"},
    {"type": "config", "action": "set", "xpath": "/config", "element": "<x/>"},
    {"type": "commit", "cmd": "<commit/>"},
    {"type": "log", "action": "delete", "job-id": "1"},
])
def test_write_calls_are_refused(params: dict[str, str]) -> None:
    async def run() -> None:
        async with PanosClient("fw.example.test", api_key="k", transport=handler([])) as client:
            await client._call(params)

    with pytest.raises(PanosError, match="refusing"):
        asyncio.run(run())


def test_dtd_in_a_response_is_refused() -> None:
    transport = httpx.MockTransport(lambda _request: httpx.Response(
        200, text='<!DOCTYPE x [<!ENTITY a "b">]><response status="success"/>'))

    async def run() -> None:
        async with PanosClient("fw.example.test", api_key="k", transport=transport) as client:
            await client.op("<show><system><info></info></system></show>")

    with pytest.raises(PanosError, match="DTD"):
        asyncio.run(run())


def _mock_device(*rules: FirewallRule, profiles: dict[str, list[str]] | None = None) -> Device:
    return Device(id="fw", rules=list(rules), vulnerability_profiles=profiles or {})


def _mock_environment(device: Device) -> Environment:
    zones = [Zone(id="internet", kind="internet"), Zone(id="servers", kind="server")]
    return Environment(zones=zones, devices=[device])


def _pushed(before: Device, after: Device, folder: Path) -> tuple[Environment, dict[str, Any]]:
    environment = _mock_environment(after)
    return environment, mock.push_plan(folder, _mock_environment(before), environment)


def test_a_push_leaves_the_firewall_holding_the_change_and_the_read_only_client_can_read_it(tmp_path: Path) -> None:
    open_rule = FirewallRule(name="dns", from_zone=["internet"], to_zone=["servers"])
    after = _mock_device(
        FirewallRule(name="porygon-deny", from_zone=["internet"], action="deny"),
        open_rule.model_copy(update={"vulnerability_profile": "strict"}),
        profiles={"strict": ["58691", "59168"]},
    )
    _, receipt = _pushed(_mock_device(open_rule), after, tmp_path)
    assert receipt["devices"][0]["commit_job"] == "2"

    firewalls = mock.MockFirewalls(tmp_path, "key")

    def answer(request: httpx.Request) -> httpx.Response:
        status, body = firewalls.respond(dict(request.url.params), request.headers.get("X-PAN-KEY"))
        return httpx.Response(status, content=body)

    async def read() -> ET.Element | None:
        async with PanosClient("fw", api_key="key", target="fw", transport=httpx.MockTransport(answer)) as client:
            return await client.config(mock.VSYS)

    vsys = asyncio.run(read())
    assert vsys is not None
    rules = vsys.findall("rulebase/security/rules/entry")
    assert [rule.get("name") for rule in rules] == ["porygon-deny", "dns"]
    assert members(rules[1].find("profile-setting/profiles"), "vulnerability") == ["strict"]
    exceptions = vsys.findall("profiles/vulnerability/entry/threat-exception/entry")
    assert [item.get("name") for item in exceptions] == ["58691", "59168"]


@pytest.mark.parametrize(
    "url", ["https://10.0.0.1/api/", "https://fw.example.com/api/", "http://localhost.example.com/api/", "nonsense"]
)
def test_changes_can_only_go_to_this_machine(url: str) -> None:
    with pytest.raises(mock.FirewallError, match="on this machine"):
        mock.FirewallSession(url, "key")


def test_the_mock_refuses_a_wrong_key(tmp_path: Path) -> None:
    assert mock.MockFirewalls(tmp_path, "key").respond({"type": "op"}, "wrong")[0] == 403


def test_a_commit_fails_when_a_rule_names_a_profile_nobody_defined(tmp_path: Path) -> None:
    before = _mock_device(FirewallRule(name="dns"))
    (tmp_path / "fw.json").write_text(
        json.dumps({"versions": [ET.tostring(mock.config_for(before), encoding="unicode")]}), encoding="utf-8"
    )
    with mock.serving(tmp_path) as (session, _firewalls):
        session.call(
            type="config",
            action="set",
            target="fw",
            xpath=f"{mock.RULES}/entry[@name='dns']/profile-setting/profiles/vulnerability",
            element="<member>missing</member>",
        )
        with pytest.raises(mock.FirewallError, match="isn't defined"):
            session.call(type="commit", target="fw", cmd="<commit></commit>")


def test_undoing_a_push_leaves_the_config_it_started_with(tmp_path: Path) -> None:
    before = _mock_device(FirewallRule(name="dns"), profiles={"old": ["1"]})
    after = _mock_device(
        FirewallRule(name="dns", vulnerability_profile="old"), profiles={"old": ["1", "2"]}
    )
    _, receipt = _pushed(before, after, tmp_path)
    undone = mock.undo_plan(tmp_path, receipt)
    assert undone[0]["restored"] and undone[0]["config"] == ET.tostring(mock.config_for(before), encoding="unicode")


def test_a_firewall_that_drifted_from_the_model_is_reported(tmp_path: Path) -> None:
    before = _mock_device(FirewallRule(name="dns"))
    after = _mock_device(
        FirewallRule(name="dns", vulnerability_profile="strict"), profiles={"strict": ["1", "2"]}
    )
    environment, receipt = _pushed(before, after, tmp_path)
    assert mock.firewall_differences(tmp_path, receipt, environment) == []
    state = json.loads((tmp_path / "fw.json").read_text(encoding="utf-8"))
    state["versions"][-1] = state["versions"][-1].replace('<entry name="2">', '<entry name="3">')
    (tmp_path / "fw.json").write_text(json.dumps(state), encoding="utf-8")
    assert mock.firewall_differences(tmp_path, receipt, environment) == [
        "fw: its vulnerability profiles aren't the ones in the model"
    ]


def test_a_device_the_mock_cant_speak_to_is_reported_not_sent(tmp_path: Path) -> None:
    before = _mock_device(FirewallRule(name="dns"))
    before.fw_type = "Fortigate"
    after = before.model_copy(deep=True)
    after.vulnerability_profiles = {"strict": ["1"]}
    _, receipt = _pushed(before, after, tmp_path)
    assert receipt["devices"] == [] and receipt["not_sent"] == ["fw: the mock only speaks PAN-OS"]


def test_a_push_that_didnt_leave_the_planned_config_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(mock, "_calls_for", lambda *_args: [])
    before = _mock_device(FirewallRule(name="dns"))
    after = before.model_copy(update={"vulnerability_profiles": {"strict": ["1"]}})
    with pytest.raises(mock.FirewallError, match="vulnerability profiles"):
        _pushed(before, after, tmp_path)


@pytest.mark.parametrize("device_id", ["../../victim", "a/b", "x" * 300, "bad\x00id"])
def test_a_device_id_cant_choose_where_the_mock_writes(tmp_path: Path, device_id: str) -> None:
    before = _mock_device(FirewallRule(name="dns"))
    before.id = device_id
    after = before.model_copy(update={"vulnerability_profiles": {"strict": ["1"]}})
    folder = tmp_path / "deep" / "mock"
    with pytest.raises(mock.FirewallError, match="can't be used"):
        mock.push_plan(folder, _mock_environment(before), _mock_environment(after))
    assert not list(tmp_path.rglob("victim*"))


def test_the_mock_listens_only_here_and_its_client_ignores_proxies_and_redirects(tmp_path: Path) -> None:
    with mock.serving(tmp_path) as (session, _firewalls):
        assert session._url.startswith("http://127.0.0.1:")
        assert session._client.trust_env is False and session._client.follow_redirects is False


@pytest.mark.parametrize(
    "edit",
    [
        pytest.param(lambda rule: ET.SubElement(rule, "disabled").__setattr__("text", "yes"), id="disabled"),
        pytest.param(lambda rule: ET.SubElement(rule, "negate-destination").__setattr__("text", "yes"), id="negated"),
        pytest.param(lambda rule: rule.find("source/member").__setattr__("text", "192.0.2.9"), id="source"),
        pytest.param(lambda rule: rule.find("application/member").__setattr__("text", "ping"), id="application"),
        pytest.param(lambda rule: rule.find("action").__setattr__("text", "permit"), id="unknown-action"),
    ],
)
def test_a_rule_changed_in_a_way_the_model_has_no_field_for_is_reported(tmp_path: Path, edit: Any) -> None:
    before = _mock_device(FirewallRule(name="dns"))
    after = before.model_copy(update={"vulnerability_profiles": {"strict": ["1"]}})
    environment, receipt = _pushed(before, after, tmp_path)
    state = json.loads((tmp_path / "fw.json").read_text(encoding="utf-8"))
    config = ET.fromstring(state["versions"][-1])
    edit(next(config.iter("rules"))[0])
    state["versions"][-1] = ET.tostring(config, encoding="unicode")
    (tmp_path / "fw.json").write_text(json.dumps(state), encoding="utf-8")
    assert mock.firewall_differences(tmp_path, receipt, environment)


def test_a_rule_on_a_built_in_profile_doesnt_block_a_push(tmp_path: Path) -> None:
    before = _mock_device(FirewallRule(name="dns", vulnerability_profile="strict"))
    after = before.model_copy(update={"vulnerability_profiles": {"new": ["1"]}})
    environment, receipt = _pushed(before, after, tmp_path)
    assert receipt["devices"][0]["commit_job"] == "2"
    assert mock.firewall_differences(tmp_path, receipt, environment) == []


@pytest.mark.parametrize(
    "extra",
    [
        "<target><devices><entry name='OTHER-SERIAL'/></devices></target>",
        "<target><tags><member>branch</member></tags></target>",
        "<hip-profiles><member>managed</member></hip-profiles>",
        "<source-imsi><member>1</member></source-imsi>",
        "<source-user><member>bob</member></source-user>",
        "<category><member>gambling</member></category>",
        "<schedule>weekends</schedule>",
        "<a-field-from-a-later-version>x</a-field-from-a-later-version>",
    ],
)
def test_a_rule_limited_by_something_unread_says_so(extra: str) -> None:
    entry = ET.fromstring(f"<entry name='r'><action>deny</action>{extra}</entry>")
    assert _rule(entry, {}, "pre")["limited_by"]


@pytest.mark.parametrize(
    "extra",
    [
        "<target><negate>no</negate></target>",
        "<rule-type>universal</rule-type>",
        "<source-user><member>any</member></source-user>",
        "<category><member>any</member></category>",
        "<log-end>yes</log-end>",
        "<disable-inspect>no</disable-inspect>",
        "<description>closes the host</description>",
    ],
)
def test_a_rule_with_nothing_narrowing_it_has_no_limit(extra: str) -> None:
    entry = ET.fromstring(f"<entry name='r'><action>deny</action>{extra}</entry>")
    assert "limited_by" not in _rule(entry, {}, "pre")
