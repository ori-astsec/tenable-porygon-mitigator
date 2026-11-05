"""The simulated flow: routes to placement, reachability, tags, what-if, approval, verification, rollback, surfaces."""

import asyncio
import json
import re
from datetime import date
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from mcp.server.mcpserver.exceptions import ToolError

from porygon_mitigator import mcp_server
from porygon_mitigator.cli import main
from porygon_mitigator.flow import agentic, engine, research, runs
from porygon_mitigator.flow import sources as source_files
from porygon_mitigator.flow.engine import (
    apply_plan,
    compute_reachability,
    decide,
    environment_hash,
    flow_passes,
    funnel,
    match_mitigations,
    plan_change,
    recommend,
    tag_cves,
    validate_inputs,
    verify,
    zone_paths,
)
from porygon_mitigator.flow.models import (
    AllowedFlow,
    Change,
    Device,
    Environment,
    Finding,
    FirewallRule,
    FlowMitigation,
    Host,
    ObservedTraffic,
    Route,
    Verification,
    VulnerabilityProfile,
    Zone,
)
from porygon_mitigator.flow.normalize import check_profile
from porygon_mitigator.flow.plans import mitigations_from_plans
from porygon_mitigator.flow.report import render_dashboard, render_summary
from porygon_mitigator.flow.tenable import (
    TenableFollowUp,
    environment_from_tenable,
    execute_follow_up,
    plan_follow_up,
)
from porygon_mitigator.flow.topology import best_route, place_host, place_hosts, route_chain
from porygon_mitigator.integrations.panos import mock
from porygon_mitigator.integrations.tenable_one.client import TenableOneClient
from porygon_mitigator.integrations.tenable_one.plugin_outputs import listener_processes
from porygon_mitigator.mcp_server import DASHBOARD_MIME, DASHBOARD_URI, server
from porygon_mitigator.models.mitigation import Action, AppliesTo, Mitigation

from .conftest import ROOT

EXAMPLES = ROOT / "examples" / "flow"


def rce(cve: str = "CVE-2020-1350", **fields: Any) -> Finding:
    return Finding(
        **{
            "cve": cve,
            "severity": "critical",
            "access_vector": "network",
            "kev": True,
            "family": "DNS",
            "remote_check": True,
            **fields,
        }
    )


def host(name: str = "dc", zone: str | None = "servers", **fields: Any) -> Host:
    defaults: dict[str, Any] = {"id": name, "zone": zone, "ips": ["10.0.0.5"], "findings": [rce()]}
    return Host(**{**defaults, **fields})


def network(
    *hosts: Host, rules: list[FirewallRule] | None = None, flows: list[AllowedFlow] | None = None
) -> Environment:
    firewall = Device(
        id="fw",
        zones=["internet", "servers", "corp"],
        rules=rules
        if rules is not None
        else [
            FirewallRule(
                name="publish-dns", from_zone=["internet"], to_zone=["servers"], destination=["dc"]
            ),
        ],
    )
    return Environment(
        zones=[Zone(id="internet", kind="internet"), Zone(id="servers", kind="server"), Zone(id="corp", kind="corp")],
        devices=[firewall],
        hosts=list(hosts),
        allowed_flows=flows or [],
    )


IPS = FlowMitigation(
    id="ips",
    title="Block it",
    kind="ips_threat_ids",
    cve_ids=["CVE-2020-1350"],
    fw_type="PaloAltoNGFW",
    threat_ids=["58691"],
)


def tag(environment: Environment, cve: str = "CVE-2020-1350", mitigations: tuple[FlowMitigation, ...] = ()) -> Any:
    return next(item for item in tag_cves(environment, mitigations) if item.cve == cve)


def test_most_specific_route_wins_regardless_of_order() -> None:
    routes = [
        Route(destination="0.0.0.0/0", zone="internet"),
        Route(destination="10.0.0.0/24", zone="servers"),
        Route(destination="10.0.0.0/8", zone="corp"),
    ]
    assert best_route(routes, "10.0.0.5").zone == "servers"  # type: ignore[union-attr]
    assert best_route(routes[::-1], "10.1.0.5").zone == "corp"  # type: ignore[union-attr]
    assert best_route(routes, "8.8.8.8").zone == "internet"  # type: ignore[union-attr]
    assert best_route(routes, "not an ip") is None


def test_route_chain_follows_next_hops_and_stops_at_loops() -> None:
    devices = [
        Device(id="edge", routes=[Route(destination="10.0.0.0/8", next_hop_device="core")]),
        Device(
            id="core",
            routes=[
                Route(destination="10.0.0.0/24", zone="servers"),
                Route(destination="10.1.0.0/16", next_hop_device="edge"),
            ],
        ),
    ]
    assert route_chain(devices, "edge", "10.0.0.5") == (["edge", "core"], "servers")
    assert route_chain(devices, "edge", "10.1.0.5") == (["edge", "core"], None)


def test_host_is_placed_by_declaration_then_routes_then_zone_cidr() -> None:
    environment = Environment(
        zones=[Zone(id="internet", kind="internet"), Zone(id="servers", cidrs=["10.0.0.0/8"]), Zone(id="dmz")],
        devices=[Device(id="edge", zones=["internet", "dmz"], routes=[Route(destination="192.0.2.0/24", zone="dmz")])],
        hosts=[
            Host(id="declared", zone="servers", ips=["192.0.2.1"]),
            Host(id="routed", ips=["192.0.2.2"]),
            Host(id="by-cidr", ips=["10.0.0.9"]),
            Host(id="lost", ips=["172.16.0.1"]),
        ],
    )
    methods = {name: place_host(environment, name) for name in ("declared", "routed", "by-cidr", "lost")}
    assert (methods["declared"].zone, methods["declared"].method) == ("servers", "declared")
    assert (methods["routed"].zone, methods["routed"].method, methods["routed"].devices_in_front) == (
        "dmz",
        "route",
        ["edge"],
    )
    assert (methods["by-cidr"].zone, methods["by-cidr"].method) == ("servers", "zone_cidr")
    assert (methods["lost"].zone, methods["lost"].method) == (None, "not_placed")
    assert {item.id: item.zone for item in place_hosts(environment).hosts}["routed"] == "dmz"


def test_first_matching_rule_wins_and_no_match_denies() -> None:
    rules = [FirewallRule(name="deny-dns", action="deny"), FirewallRule(name="allow-all")]
    device = Device(id="fw", rules=rules)
    target = host()
    assert decide(device, "a", "b", target).rule == "deny-dns"
    assert decide(Device(id="fw"), "a", "b", target).rule is None


@pytest.mark.parametrize(
    ("destination", "expected"),
    [
        ("dc", True),
        ("10.0.0.0/24", True),
        ("10.0.0.5", True),
        ("10.9.0.0/24", False),
        ("other", False),
        ("any", True),
    ],
)
def test_destination_matching(destination: str, expected: bool) -> None:
    device = Device(id="fw", rules=[FirewallRule(name="r", destination=[destination])])
    assert (decide(device, "a", "b", host()).action == "allow") is expected


def test_all_devices_on_a_path_must_allow() -> None:
    allow = FirewallRule(name="allow")
    zones = [Zone(id="internet", kind="internet"), Zone(id="dmz"), Zone(id="servers")]

    def environment(core: list[FirewallRule]) -> Environment:
        return Environment(
            zones=zones,
            hosts=[host()],
            devices=[
                Device(id="edge", zones=["internet", "dmz"], rules=[allow]),
                Device(id="core", zones=["dmz", "servers"], rules=core),
            ],
        )

    assert compute_reachability(environment([allow]))[0].reachable is True
    assert compute_reachability(environment([]))[0].reachable is False


def test_no_rule_means_not_reachable() -> None:
    result = tag(network(host(), rules=[]))
    assert (result.tag, result.basis, result.exposed) == ("not_reachable", "no_path", False)


def test_adjacent_needs_an_attacker_on_the_segment() -> None:
    assert tag(network(host(findings=[rce(access_vector="adjacent")]))).tag == "not_reachable"


def test_most_exposed_finding_wins_for_a_pair() -> None:
    environment = network(host(findings=[rce(), rce()]))
    assert [item.tag for item in tag_cves(environment)] == ["reachable"]


TWO_PORTS = [
    FirewallRule(name="r443", from_zone=["internet"], vulnerability_profile="p"),
    FirewallRule(name="r8443", from_zone=["internet"]),
]


def test_a_pair_takes_its_worst_severity_and_most_remote_vector() -> None:
    findings = [rce(severity="high"), rce(), rce(access_vector="local")]
    result = tag(network(host(findings=findings)))
    assert (result.tag, result.severity, result.access_vector) == ("reachable", "critical", "network")


def test_a_pair_merges_every_exposing_vantage_and_any_kev() -> None:
    findings = [rce(kev=False), rce(kev=True)]
    rules = [
        FirewallRule(name="a", from_zone=["internet"]),
        FirewallRule(name="b", from_zone=["guest"]),
    ]
    environment = network(host(findings=findings), rules=rules)
    environment.zones.append(Zone(id="guest", kind="guest"))
    environment.devices[0].zones.append("guest")
    result = tag(environment)
    assert result.vantages == ["guest", "internet"] and result.kev is True


def test_a_map_that_cant_settle_it_is_unknown_not_safe() -> None:
    assert tag(network(host(zone="corp"), rules=[])).basis == "no_path"
    cut_off = Environment(zones=[Zone(id="internet", kind="internet"), Zone(id="servers")], hosts=[host()])
    assert (tag(cut_off).tag, tag(cut_off).basis) == ("unknown", "not_connected")
    chain = [f"z{index}" for index in range(12)]
    devices = [
        Device(id=f"d{index}", zones=[left, right], rules=[FirewallRule(name="all")])
        for index, (left, right) in enumerate(zip(["internet", *chain], [*chain, "servers"], strict=True))
    ]
    far = Environment(
        zones=[Zone(id="internet", kind="internet"), Zone(id="servers"), *(Zone(id=zone) for zone in chain)],
        devices=devices,
        hosts=[host()],
    )
    assert tag(far).tag == "unknown"


def _short_and_long_paths(short: FirewallRule | None = None) -> Environment:
    chain = [f"z{index}" for index in range(12)]
    allow = FirewallRule(name="all")
    devices = [
        Device(id=f"d{index}", zones=[left, right], rules=[allow])
        for index, (left, right) in enumerate(zip(["internet", *chain], [*chain, "servers"], strict=True))
    ]
    devices.append(Device(id="short", zones=["internet", "servers"], rules=[short] if short else []))
    zones = [Zone(id="internet", kind="internet"), Zone(id="servers"), *(Zone(id=zone) for zone in chain)]
    return Environment(zones=zones, devices=devices, hosts=[host()])


def test_paths_past_the_search_limit_keep_it_unknown_even_with_a_blocked_short_path() -> None:
    result = tag(_short_and_long_paths())
    assert (result.tag, result.basis) == ("unknown", "not_connected")


def test_a_long_dead_end_doesnt_make_a_blocked_host_unknown() -> None:
    chain = [f"z{index}" for index in range(12)]
    devices = [
        Device(id=f"d{index}", zones=[left, right], rules=[FirewallRule(name="all")])
        for index, (left, right) in enumerate(zip(["internet", *chain[:-1]], chain, strict=True))
    ]
    devices.append(Device(id="short", zones=["internet", "servers"]))
    zones = [Zone(id="internet", kind="internet"), Zone(id="servers"), *(Zone(id=zone) for zone in chain)]
    result = tag(Environment(zones=zones, devices=devices, hosts=[host()]))
    assert (result.tag, result.basis) == ("not_reachable", "no_path")


def test_ips_on_the_short_path_cant_vouch_for_paths_the_search_never_saw() -> None:
    environment = _short_and_long_paths(FirewallRule(name="r", vulnerability_profile="p"))
    environment.devices[-1].vulnerability_profiles["p"] = ["58691"]
    result = tag(environment, mitigations=(IPS,))
    assert result.tag == "reachable" and result.protected_by == [] and result.exposed is True


def test_closing_the_short_path_doesnt_count_as_protecting_what_the_search_cant_see() -> None:
    environment = _short_and_long_paths(FirewallRule(name="r"))
    acl = FlowMitigation(id="acl", title="ACL", kind="acl_block", cve_ids=["CVE-2020-1350"])
    candidate = match_mitigations(environment, [acl])[0]
    assert candidate.protects == [] and candidate.status == "hold"


def test_one_firewall_with_many_zones_is_one_hop_and_stays_fast() -> None:
    zones = [f"z{index}" for index in range(30)]
    environment = Environment(
        zones=[Zone(id="internet", kind="internet"), Zone(id="servers"), *(Zone(id=zone) for zone in zones)],
        devices=[Device(id="fw", zones=["internet", "servers", *zones])],
        hosts=[host()],
    )
    assert tag(environment).basis == "no_path"
    assert zone_paths(environment, "internet", "servers")[0][0][1:] == ("internet", "servers")
    assert len(zone_paths(environment, "internet", "servers")) == 1


def test_a_known_open_path_beats_a_missing_address() -> None:
    rules = [
        FirewallRule(name="cidr", from_zone=["corp"], destination=["10.0.0.0/8"]),
        FirewallRule(name="open", from_zone=["internet"]),
    ]
    assert tag(network(host(ips=[]), rules=rules)).tag == "reachable"


def test_rules_on_addresses_cant_clear_a_host_with_no_address() -> None:
    rules = [FirewallRule(name="r", from_zone=["internet"], destination=["10.0.0.0/8"])]
    assert tag(network(host(), rules=rules)).tag == "reachable"
    assert tag(network(host(ips=[]), rules=rules)).basis == "no_address"
    assert tag(network(host(ips=["2001:db8::1"]), rules=rules)).basis == "no_address"


def test_broken_references_stop_the_run() -> None:
    assert not validate_inputs(network(host()), [IPS])
    assert any("duplicate host" in item for item in validate_inputs(network(host(), host()), []))
    assert any("no zone 'typo'" in item for item in validate_inputs(network(host(zone="typo")), []))
    flow = AllowedFlow(name="f", source_zone="nope", host="ghost")
    assert len(validate_inputs(network(host(), flows=[flow]), [])) == 2
    quiet = Environment(zones=[Zone(id="servers")], hosts=[host()])
    assert any("attacker vantage" in item for item in validate_inputs(quiet, []))


@pytest.mark.parametrize("field", ["from_zone", "to_zone", "destination"])
def test_an_empty_rule_field_stops_the_run(field: str) -> None:
    rules = [FirewallRule(name="r", **{field: []})]
    assert any(f"{field} is empty" in item for item in validate_inputs(network(host(), rules=rules), []))


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"zones": ["ghost"]}, "no zone 'ghost'"),
        ({"routes": [Route(destination="not-a-cidr")]}, "isn't a CIDR"),
        ({"routes": [Route(destination="10.0.0.0/8", zone="ghost")]}, "unknown zone"),
        ({"routes": [Route(destination="10.0.0.0/8", next_hop_device="ghost")]}, "unknown device"),
    ],
)
def test_bad_device_references_stop_the_run(change: dict[str, Any], message: str) -> None:
    environment = network(host())
    environment.devices.append(Device(id="other", **change))
    assert any(message in item for item in validate_inputs(environment, []))


def test_duplicate_zones_devices_and_mitigations_stop_the_run() -> None:
    environment = network(host())
    environment.zones.append(Zone(id="corp"))
    environment.devices.append(Device(id="fw"))
    problems = validate_inputs(environment, [IPS, IPS])
    assert {"duplicate zone id 'corp'", "duplicate device id 'fw'", "duplicate mitigation id 'ips'"} <= set(problems)


@pytest.mark.parametrize("kind", ["ips_threat_ids", "disable_service", "host_setting"])
def test_a_mitigation_needs_what_its_kind_applies(kind: str) -> None:
    with pytest.raises(ValueError, match="needs its"):
        FlowMitigation(id="m", title="M", kind=kind, cve_ids=["CVE-1"])  # type: ignore[arg-type]


def demo() -> tuple[Environment, list[FlowMitigation]]:
    environment = Environment.model_validate_json((EXAMPLES / "environment.json").read_text(encoding="utf-8"))
    mitigations = json.loads((EXAMPLES / "mitigations.json").read_text(encoding="utf-8"))
    return place_hosts(environment), [FlowMitigation.model_validate(item) for item in mitigations]


def test_candidates_hold_what_breaks_allowed_traffic_and_offer_the_alternative() -> None:
    candidates = {item.mitigation_id: item for item in match_mitigations(*demo())}
    assert candidates["spooler-disable"].status == "hold"
    assert candidates["spooler-disable"].breaks_flows == ["Office printing"]
    assert candidates["spooler-dmz-acl"].status == "proceed" and not candidates["spooler-dmz-acl"].breaks_flows
    assert set(candidates["spooler-disable"].protects) <= set(candidates["spooler-dmz-acl"].protects)


def test_acl_only_blocks_the_zones_that_exposed_the_host() -> None:
    environment, mitigations = demo()
    plan = plan_change(environment, mitigations, ["spooler-dmz-acl"])
    rule = plan.changes[0].deny_rule
    assert rule is not None and rule.from_zone == ["dmz"] and rule.action == "deny"
    office = next(flow for flow in environment.allowed_flows if flow.name == "Office printing")
    assert flow_passes(apply_plan(environment, plan, plan.plan_hash), office)


def test_ips_needs_a_capable_device_on_the_path() -> None:
    environment = network(host())
    environment.devices[0].threat_prevention = False
    candidate = match_mitigations(environment, [IPS])[0]
    assert candidate.status == "hold" and "No capable device" in " ".join(candidate.hold_reasons)
    environment = network(host())
    environment.devices[0].fw_type = "Fortigate"
    assert match_mitigations(environment, [IPS])[0].status == "hold"


def test_nothing_exposed_is_held_and_cant_be_planned() -> None:
    environment = network(host(), rules=[])
    assert match_mitigations(environment, [IPS])[0].status == "hold"
    with pytest.raises(ValueError, match="nothing to apply"):
        plan_change(environment, [IPS], ["ips"])


def test_a_hold_stops_the_plan_unless_accepted_and_is_then_on_the_record() -> None:
    service = FlowMitigation(id="stop", title="Stop", kind="disable_service", cve_ids=["CVE-2020-1350"], service="dns")
    flow = AllowedFlow(name="needs", source_zone="internet", host="dc", service="dns")
    environment = network(host(), flows=[flow])
    with pytest.raises(ValueError, match="held, and not accepted"):
        plan_change(environment, [service], ["stop"])
    plan = plan_change(environment, [service], ["stop"], accept_holds=True)
    assert plan.hold_reasons and plan.expected_breaks == ["needs"]
    result = verify(environment, apply_plan(environment, plan, plan.plan_hash), [service], plan)
    assert result.planned_breaks == ["needs"]
    assert any(check.detail.startswith("BROKEN") for check in result.checks)


def test_selecting_a_mitigation_twice_adds_one_rule() -> None:
    acl = FlowMitigation(id="acl", title="ACL", kind="acl_block", cve_ids=["CVE-2020-1350"])
    assert len(plan_change(network(host()), [acl], ["acl", "acl"]).changes) == 1


def test_ips_keeps_what_a_rule_s_profile_already_blocks() -> None:
    old = rce("CVE-OLD")
    new = rce("CVE-NEW")
    block_old = IPS.model_copy(update={"id": "old", "cve_ids": ["CVE-OLD"], "threat_ids": ["1"]})
    block_new = IPS.model_copy(update={"id": "new", "cve_ids": ["CVE-NEW"], "threat_ids": ["2"]})
    rules = [FirewallRule(name="r", from_zone=["internet"], vulnerability_profile="corp")]
    environment = network(host(findings=[old, new]), rules=rules)
    environment.devices[0].vulnerability_profiles["corp"] = ["1"]
    mitigations = [block_old, block_new]
    assert tag(environment, "CVE-OLD", tuple(mitigations)).exposed is False
    plan = plan_change(environment, mitigations, ["new"])
    assert "profile-setting" not in "\n".join(plan.changes[0].preview)
    assert "vulnerability corp threat-exception 2" in "\n".join(plan.changes[0].preview)
    after = apply_plan(environment, plan, plan.plan_hash)
    assert after.devices[0].rules[0].vulnerability_profile == "corp"
    assert after.devices[0].vulnerability_profiles["corp"] == ["1", "2"]
    result = verify(environment, after, mitigations, plan)
    assert result.passed and result.after.kev_exposed == 0


def test_two_mitigations_with_one_setting_protect_both_cves() -> None:
    settings = [
        FlowMitigation(id=f"m{index}", title="T", kind="host_setting", cve_ids=[cve], setting="Disable SMBv1")
        for index, cve in enumerate(("CVE-1", "CVE-2"))
    ]
    environment = network(host(findings=[rce("CVE-1"), rce("CVE-2")]))
    plan = plan_change(environment, settings, ["m0", "m1"])
    after = apply_plan(environment, plan, plan.plan_hash)
    assert after.hosts[0].host_controls["Disable SMBv1"] == ["CVE-1", "CVE-2"]
    assert not any(item.exposed for item in tag_cves(after, settings))


def test_mitigation_limited_to_an_os_skips_other_hosts() -> None:
    setting = FlowMitigation(
        id="reg", title="Registry", kind="host_setting", cve_ids=["CVE-2020-1350"], setting="x=1", os="Windows"
    )
    assert match_mitigations(network(host(os="Ubuntu 22.04")), [setting])[0].status == "hold"
    assert match_mitigations(network(host(os="Windows Server")), [setting])[0].status == "proceed"


def test_ips_protects_only_with_every_threat_id_on_every_path() -> None:
    environment = network(host())
    assert tag(environment, mitigations=(IPS,)).exposed is True
    plan = plan_change(environment, [IPS], ["ips"])
    after = apply_plan(environment, plan, plan.plan_hash)
    result = tag(after, mitigations=(IPS,))
    assert result.tag == "reachable" and result.protected_by == ["ips"] and not result.exposed
    partial = IPS.model_copy(update={"threat_ids": ["58691", "59168"]})
    assert tag(after, mitigations=(partial,)).exposed is True


def test_plan_previews_the_product_change_and_nothing_runs_it() -> None:
    plan = plan_change(network(host()), [IPS], ["ips"])
    preview = "\n".join(plan.changes[0].preview)
    assert "threat-exception 58691 action reset-both" in preview
    assert "rules publish-dns profile-setting profiles vulnerability" in preview


def test_apply_refuses_a_wrong_hash_a_changed_environment_and_an_edited_plan() -> None:
    environment = network(host())
    plan = plan_change(environment, [IPS], ["ips"])
    with pytest.raises(ValueError, match="doesn't match"):
        apply_plan(environment, plan, "0" * 16)
    changed = environment.model_copy(deep=True)
    changed.hosts[0].processes.append("new")
    with pytest.raises(ValueError, match="environment changed"):
        apply_plan(changed, plan, plan.plan_hash)
    edited = plan.model_copy(deep=True)
    edited.changes[0].threat_ids = ["1"]
    with pytest.raises(ValueError, match="edited"):
        apply_plan(environment, edited, edited.plan_hash)
    promised = plan.model_copy(deep=True)
    promised.expected_protects = []
    with pytest.raises(ValueError, match="edited"):
        apply_plan(environment, promised, promised.plan_hash)
    before = environment_hash(environment)
    apply_plan(environment, plan, plan.plan_hash)
    assert environment_hash(environment) == before


def test_verify_recomputes_instead_of_trusting_the_plan() -> None:
    environment = network(host(), flows=[AllowedFlow(name="dns", source_zone="internet", host="dc")])
    plan = plan_change(environment, [IPS], ["ips"])
    result = verify(environment, apply_plan(environment, plan, plan.plan_hash), [IPS], plan)
    assert result.passed and result.before.kev_exposed == 1 and result.after.kev_exposed == 0
    unchanged = verify(environment, environment, [IPS], plan)
    assert not unchanged.passed
    assert any(not check.passed and "CVE-2020-1350" in check.name for check in unchanged.checks)


def test_verify_catches_new_exposure_and_unpredicted_breakage() -> None:
    flow = AllowedFlow(name="dns", source_zone="internet", host="dc")
    environment = network(host(), flows=[flow])
    plan = plan_change(environment, [IPS], ["ips"])
    broken = apply_plan(environment, plan, plan.plan_hash)
    broken.devices[0].rules.clear()
    assert any(
        check.name == "allowed traffic: dns" and not check.passed
        for check in verify(environment, broken, [IPS], plan).checks
    )
    exposed = apply_plan(environment, plan, plan.plan_hash)
    exposed.hosts.append(host("new", ips=["10.0.0.6"]))
    exposed.devices[0].rules.insert(0, FirewallRule(name="oops", destination=["new"]))
    assert any(
        check.name == "no new exposure" and not check.passed
        for check in verify(environment, exposed, [IPS], plan).checks
    )


def test_stopping_a_service_breaks_only_traffic_that_needs_it() -> None:
    service = FlowMitigation(id="stop", title="Stop", kind="disable_service", cve_ids=["CVE-2020-1350"], service="DNS")
    flows = [
        AllowedFlow(name="needs", source_zone="internet", host="dc", service="dns"),
        AllowedFlow(name="other", source_zone="internet", host="dc"),
    ]
    candidate = match_mitigations(network(host(), flows=flows), [service])[0]
    assert candidate.breaks_flows == ["needs"] and candidate.status == "hold" and candidate.protects


@pytest.fixture
def flow_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("PORYGON_FLOW_DIR", str(tmp_path))
    return tmp_path


def _start_demo() -> str:
    return runs.load_files(str(EXAMPLES / "environment.json"), str(EXAMPLES / "mitigations.json"))


@pytest.mark.usefixtures("flow_dir")
def test_run_lifecycle_applies_verifies_and_rolls_back() -> None:
    run_id = _start_demo()
    before = runs.dashboard_data()["funnel"]
    plan_hash = runs.make_plan(["sigred-ips"])["plan"]["plan_hash"]
    assert runs.dashboard_data()["funnel"] == before
    runs.apply_approved(plan_hash)
    with pytest.raises(runs.FlowError, match="already applied"):
        runs.apply_approved(plan_hash)
    assert runs.verify_applied().passed
    data = runs.dashboard_data(run_id)
    assert data["funnel"]["kev_exposed"] == before["kev_exposed"] - 1 and data["applied_plan"] == plan_hash
    assert data["verification"]["passed"] is True
    assert runs.rollback() == plan_hash
    assert runs.dashboard_data()["funnel"] == before and runs.dashboard_data()["applied_plan"] is None
    assert runs.dashboard_data()["verification"] is None
    with pytest.raises(runs.FlowError, match="nothing to roll back"):
        runs.rollback()


@pytest.mark.usefixtures("flow_dir")
def test_same_inputs_give_the_same_run_and_plan_and_only_an_explicit_restart_undoes_a_plan() -> None:
    first = _start_demo()
    plan = runs.make_plan(["sigred-ips"])["plan"]["plan_hash"]
    runs.apply_approved(plan)
    with pytest.raises(runs.FlowError, match="applied plan"):
        _start_demo()
    assert runs.dashboard_data()["applied_plan"] == plan
    assert "applied plan" in _tool("flow_load_environment", {"bundled_example": True})["error"]
    assert runs.dashboard_data()["applied_plan"] == plan
    environment, mitigations = runs.example_files()
    assert runs.load_files(environment, mitigations, restart=True) == first
    assert runs.dashboard_data()["applied_plan"] is None and runs.make_plan(["sigred-ips"])["plan"]["plan_hash"] == plan


@pytest.mark.usefixtures("flow_dir")
def test_a_crash_during_apply_leaves_a_state_rollback_can_undo(monkeypatch: pytest.MonkeyPatch) -> None:
    _start_demo()
    before = runs.dashboard_data()["funnel"]
    plan = runs.make_plan(["sigred-ips"])["plan"]["plan_hash"]
    real = runs._write

    def crash(path: Path, value: object) -> None:
        if path.name == "environment.json":
            raise OSError("disk full")
        real(path, value)

    monkeypatch.setattr(runs, "_write", crash)
    with pytest.raises(OSError, match="disk full"):
        runs.apply_approved(plan)
    monkeypatch.setattr(runs, "_write", real)
    assert runs.rollback() == plan
    assert runs.dashboard_data()["funnel"] == before
    runs.apply_approved(plan)
    assert runs.verify_applied().passed


@pytest.mark.usefixtures("flow_dir")
def test_bad_input_never_starts_a_run(tmp_path: Path) -> None:
    file = tmp_path / "environment.json"
    rules = [FirewallRule(name="r", destination=["addr-web"])]
    file.write_text(network(host(), rules=rules).model_dump_json(), encoding="utf-8")
    with pytest.raises(runs.FlowError, match="addr-web"):
        runs.load_files(str(file), None)
    assert "addr-web" in _tool("flow_load_environment", {"environment_file": str(file)})["error"]
    with pytest.raises(runs.FlowError, match="no flow run"):
        runs.overview()


@pytest.mark.usefixtures("flow_dir")
def test_dashboard_counts_every_exposed_pair_when_the_table_is_cut(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(runs, "TOP_TAGGED", 1)
    _start_demo()
    data = runs.dashboard_data()
    assert len(data["exposed"]) == 1 and data["exposed_total"] > 1
    assert sum(data["exposed_by_host"].values()) == data["exposed_total"] and len(data["exposed_by_host"]) > 1


@pytest.mark.usefixtures("flow_dir")
@pytest.mark.parametrize("bad", ["../../etc", "abc", "x" * 40])
def test_run_ids_and_hashes_cant_escape_the_flow_directory(bad: str) -> None:
    _start_demo()
    with pytest.raises(runs.FlowError):
        runs.overview(bad)
    with pytest.raises(runs.FlowError):
        runs.apply_approved(bad)


@pytest.mark.usefixtures("flow_dir")
def test_no_run_yet_says_so() -> None:
    with pytest.raises(runs.FlowError, match="no flow run"):
        runs.overview()


@pytest.mark.usefixtures("flow_dir")
def test_cli_runs_the_flow_and_requires_a_real_hash(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    assert main(["flow", "demo"]) == 0
    summary = capsys.readouterr().out
    assert "SIMULATED" in summary and "0 client-side" in summary
    assert main(["flow", "apply", "0" * 16]) == 1
    assert "no plan" in capsys.readouterr().err
    assert main(["flow", "plan", "sigred-ips"]) == 0
    plan = json.loads(capsys.readouterr().out)["plan"]["plan_hash"]
    assert main(["flow", "apply", plan, "--rescan-scan-id", "abc"]) == 1
    assert "nothing was applied" in capsys.readouterr().err and runs.applied_plan() is None
    assert main(["flow", "apply", plan]) == 0
    assert "no real device" in capsys.readouterr().err
    assert main(["flow", "verify"]) == 0
    capsys.readouterr()
    page = tmp_path / "flow.html"
    assert main(["flow", "report", "--out", str(page)]) == 0
    assert plan in page.read_text(encoding="utf-8")
    assert main(["flow", "rollback"]) == 0


def test_dashboard_escapes_tenant_text_and_needs_no_network() -> None:
    page = render_dashboard({"note": "</script><script>alert(1)</script>"})
    assert "</script><script>alert" not in page and "__PORYGON_DATA__" not in page
    assert "http://" not in page.replace("http://www.w3.org/2000/svg", "") and "https://" not in page


def _tool(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    result = asyncio.run(server.call_tool(name, arguments))
    content = getattr(result, "structured_content", None)
    assert isinstance(content, dict)
    return content


def _dashboard() -> dict[str, Any]:
    return asyncio.run(server.call_tool("flow_dashboard", {})).meta["porygon/dashboard"]  # type: ignore[union-attr]


@pytest.mark.usefixtures("flow_dir")
def test_mcp_tools_walk_the_flow_and_cannot_apply() -> None:
    tools = {tool.name for tool in asyncio.run(server.list_tools())}
    assert not any("apply" in name or "rollback" in name for name in tools)
    assert _tool("flow_load_environment", {"bundled_example": True})["label"] == "synthetic"
    assert _tool("flow_reachability", {})["hosts_reachable"] > 0
    assert _tool("flow_tag_cves", {})["funnel"]["kev_exposed"] > 0
    assert _tool("flow_match_mitigations", {})["candidates"]
    planned = _tool("flow_plan_change", {"mitigation_ids": ["sigred-ips"]})
    assert planned["approve_with"].startswith("/porygon-mitigator:porygon-apply ")
    assert "no plan is applied" in _tool("flow_verify", {})["error"]
    assert _dashboard()["plans"]
    assert "unknown mitigation" in _tool("flow_plan_change", {"mitigation_ids": ["nope"]})["error"]
    assert "held" in _tool("flow_plan_change", {"mitigation_ids": ["spooler-disable"]})["error"]
    accepted = _tool("flow_plan_change", {"mitigation_ids": ["spooler-disable"], "accept_holds": True})
    assert accepted["plan"]["hold_reasons"]


@pytest.mark.usefixtures("flow_dir")
def test_dashboard_tool_gives_the_page_the_data_and_the_model_a_summary() -> None:
    _tool("flow_load_environment", {"bundled_example": True})
    result = asyncio.run(server.call_tool("flow_dashboard", {}))
    data = result.meta["porygon/dashboard"]  # type: ignore[union-attr]
    assert data["candidates"] and data["map"]
    assert result.structured_content is None, "Claude Code would give that to the model instead of the summary"  # type: ignore[union-attr]
    text = result.content[0].text  # type: ignore[union-attr]
    assert "Mitigations:" in text and len(text) < len(json.dumps(data)) / 5


@pytest.mark.usefixtures("flow_dir")
def test_mcp_load_reports_bad_files_without_echoing_them(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"hosts": [{"id": "h", "secret": "do-not-echo"}]}), encoding="utf-8")
    result = _tool("flow_load_environment", {"environment_file": str(bad)})
    assert "invalid file" in result["error"] and "do-not-echo" not in json.dumps(result)
    assert "error" in _tool("flow_load_environment", {"environment_file": str(tmp_path / "missing.json")})
    secret_key = tmp_path / "other.json"
    secret_key.write_text(json.dumps({"aws_secret_access_key": "x"}), encoding="utf-8")
    assert "aws_secret" not in json.dumps(_tool("flow_load_environment", {"environment_file": str(secret_key)}))
    assert "absolute" in _tool("flow_load_environment", {"environment_file": "relative.json"})["error"]


def test_dashboard_tool_declares_the_mcp_app_and_its_resource() -> None:
    tools = {tool.name: tool for tool in asyncio.run(server.list_tools())}
    meta = tools["flow_dashboard"].meta or {}
    assert meta["ui"]["resourceUri"] == DASHBOARD_URI
    resources = {str(item.uri): item for item in asyncio.run(server.list_resources())}
    assert resources[DASHBOARD_URI].mime_type == DASHBOARD_MIME == "text/html;profile=mcp-app"


def _frontmatter_list(path: Path, key: str) -> list[str]:
    head = path.read_text(encoding="utf-8").split("---")[1]
    found = re.search(rf"^{key}:\n((?:  - .+\n)+)", head, re.M)
    return [line.strip()[2:] for line in found.group(1).splitlines()] if found else []


def test_agent_and_commands_keep_the_approval_gate() -> None:
    agent, normalizer = ROOT / "agents" / "porygon.md", ROOT / "agents" / "porygon-normalizer.md"
    denied = {"Bash", "Write", "Edit", "NotebookEdit"}
    assert denied <= set(_frontmatter_list(agent, "disallowedTools"))
    assert denied | {"Agent"} <= set(_frontmatter_list(normalizer, "disallowedTools"))
    allowed = _frontmatter_list(agent, "tools")
    assert "Agent(porygon-mitigator:porygon-normalizer)" in allowed
    for tool in allowed:
        assert tool in ("ToolSearch", "Agent(porygon-mitigator:porygon-normalizer)") or tool.startswith(
            "mcp__plugin_porygon-mitigator_porygon__"
        ), tool
    assert _frontmatter_list(normalizer, "tools") == [
        "ToolSearch",
        "mcp__plugin_porygon-mitigator_porygon__flow_vulnerabilities_to_normalize",
        "mcp__plugin_porygon-mitigator_porygon__flow_save_normalized",
    ]
    assert "model: haiku" in normalizer.read_text(encoding="utf-8")
    for name in ("porygon-apply", "porygon-rollback"):
        assert "disable-model-invocation: true" in (ROOT / "commands" / f"{name}.md").read_text(encoding="utf-8")


def test_plans_become_palo_changes_and_one_host_setting_per_cve() -> None:
    plans = [
        {"cve": "CVE-1", "type": "IPS", "vendor": "Palo Alto", "os": "", "title": "Block", "source": "s"},
        {"cve": "CVE-2", "type": "IPS", "vendor": "Palo Alto", "os": "", "title": "Block", "source": "s"},
        {"cve": "CVE-1", "type": "IPS", "vendor": "Checkpoint", "os": "", "title": "Enable", "source": "s"},
        {"cve": "CVE-1", "type": "CONFIGURATION", "vendor": "MS", "os": "Windows", "title": "First", "source": "s"},
        {"cve": "CVE-1", "type": "REGISTRY_KEY", "vendor": "MS", "os": "Windows", "title": "Second", "source": "s"},
        {"cve": "CVE-3", "type": "CONFIGURATION", "vendor": "F5", "os": "", "title": "No OS", "source": "s"},
    ]
    result = {item.id: item for item in mitigations_from_plans(plans, {"CVE-1": ["1", "2"]})}
    assert set(result) == {"palo-cve-1", "host-cve-1"}
    assert result["palo-cve-1"].threat_ids == ["1", "2"] and result["host-cve-1"].title == "First"
    assert result["host-cve-1"].os == "Windows"
    assert set(mitigations_from_plans(plans, {"CVE-1": ["1"]}, cves={"CVE-9"})) == set()


def _tenable_rows() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    assets = [
        {"id": "uuid-1", "network": {"hostnames": ["srv"], "ipv4s": ["10.0.0.5"]}, "operating_systems": ["Win"]},
        {"id": "uuid-2", "network": {"hostnames": ["srv"], "ipv4s": ["10.0.0.6"]}},
        {"id": "uuid-3", "network": {"hostnames": ["quiet"]}},
    ]
    plugin = {
        "cve": ["CVE-2020-1350", "CVE-2099-1", "NOT-A-CVE"],
        "name": "DNS RCE",
        "family": "Windows",
        "cvss3_vector": {"access_vector": "Network"},
        "solution": "Patch.",
        "has_patch": True,
        "id": 7,
    }
    rows = [
        {
            "asset": {"uuid": "uuid-1"},
            "plugin": plugin,
            "severity": "critical",
            "port": {"port": 53, "protocol": "TCP"},
        },
        {
            "asset": {"uuid": "uuid-1"},
            "plugin": {"id": 34252},
            "output": json.dumps(
                {"listening": [{"port": 53, "protocol": "TCP", "plugin_output": "process 'dns.exe'"}]}
            ),
        },
        {
            "asset": {"uuid": "uuid-1"},
            "plugin": {"id": 179200},
            "output": "Gateway Routes:\n  e:\n    ipv4_gateways:\n      10.0.0.1:\n",
        },
        {"asset": {"uuid": "uuid-1"}, "plugin": {"id": 19506}, "output": "Credentialed checks : yes\n"},
        {"asset": {"uuid": "uuid-1"}, "plugin": {"id": 8, "cve": ["CVE-2099-2"]}, "state": "FIXED", "severity": "high"},
        {"asset": {"uuid": "uuid-2"}, "plugin": {"id": 19506}, "output": "Credentialed checks : no\n"},
    ]
    return assets, rows


def test_a_declared_name_places_a_host_only_when_one_asset_has_it() -> None:
    assets, rows = _tenable_rows()
    topology = Environment(hosts=[Host(id="srv", zone="servers"), Host(id="uuid-2", zone="corp")])
    for order in (assets, assets[::-1]):
        by_id = {item.id: item for item in environment_from_tenable(order, rows, {}, topology).hosts}
        assert (by_id["uuid-1"].zone, by_id["uuid-2"].zone) == (None, "corp")
    single = environment_from_tenable(assets[:1], rows[:1], {}, topology)
    assert (single.hosts[0].id, single.hosts[0].zone) == ("srv", "servers")


def test_findings_on_an_asset_the_export_left_out_still_count() -> None:
    plugin = {"id": 7, "cve": ["CVE-1"], "cvss3_vector": {"access_vector": "Network"}}
    row = {
        "asset": {"uuid": "gone", "hostname": "ghost", "ipv4": "10.0.0.9"},
        "plugin": plugin,
        "severity": "critical",
        "port": {"port": 53, "protocol": "TCP"},
    }
    result = environment_from_tenable([], [row], {}, Environment()).hosts[0]
    assert (result.id, result.asset_id, result.ips) == ("ghost", "gone", ["10.0.0.9"]) and result.findings


def test_ipv6_only_assets_keep_an_address() -> None:
    asset = {"id": "six", "network": {"ipv6s": ["2001:db8::1"]}}
    row = {"asset": {"uuid": "six"}, "plugin": {"id": 7, "cve": ["CVE-1"]}, "severity": "high"}
    result = environment_from_tenable([asset], [row], {}, Environment()).hosts[0]
    assert (result.id, result.ips) == ("2001:db8::1", ["2001:db8::1"])


def test_route_placement_compares_devices_and_a_default_route_places_nothing() -> None:
    zones = [Zone(id="internet", kind="internet"), Zone(id="guest", kind="guest"), Zone(id="servers")]
    devices = [
        Device(id="a", zones=["internet"], routes=[Route(destination="0.0.0.0/0", zone="internet")]),
        Device(id="b", zones=["guest", "servers"], routes=[Route(destination="10.0.0.0/24", zone="servers")]),
    ]
    environment = Environment(zones=zones, devices=devices, hosts=[Host(id="h", ips=["10.0.0.5"])])
    assert (place_host(environment, "h").zone, place_host(environment, "h").method) == ("servers", "route")
    broader = Device(id="c", zones=["internet", "guest"], routes=[Route(destination="10.0.0.0/16", zone="guest")])
    for order in ([broader, devices[1]], [devices[1], broader]):
        assert place_host(environment.model_copy(update={"devices": order}), "h").zone == "servers"
    only_default = environment.model_copy(update={"devices": devices[:1], "hosts": [Host(id="h", ips=["8.8.8.8"])]})
    assert place_host(only_default, "h").method == "not_placed"
    edge = [
        Device(id="edge", zones=["internet"], routes=[Route(destination="10.0.0.0/8", next_hop_device="core")]),
        Device(id="core", routes=[Route(destination="10.0.0.0/24", zone="servers")]),
        Device(id="edge2", zones=["guest"], routes=[Route(destination="10.0.0.0/16", zone="guest")]),
    ]
    chained = environment.model_copy(update={"devices": edge})
    assert (place_host(chained, "h").zone, place_host(chained, "h").devices_in_front) == ("servers", ["edge", "core"])
    forwarded = [
        Device(id="vpn", zones=["internet"], routes=[Route(destination="0.0.0.0/0", next_hop_device="core")]),
        edge[1],
    ]
    assert place_host(environment.model_copy(update={"devices": forwarded}), "h").zone == "servers"
    declared = environment.model_copy(update={"hosts": [Host(id="h", zone="guest", ips=["10.0.0.5"])]})
    assert place_host(declared, "h").devices_in_front == []
    with_cidr = Environment(
        zones=[Zone(id="internet", kind="internet"), Zone(id="servers", cidrs=["10.0.0.0/8"])],
        devices=devices[:1],
        hosts=[Host(id="h", ips=["10.0.0.5"])],
    )
    assert (place_host(with_cidr, "h").zone, place_host(with_cidr, "h").method) == ("servers", "zone_cidr")


def _tenant_plan() -> tuple[Environment, Any]:
    target = host(asset_id="uuid-1", findings=[rce(solution="Patch.", has_patch=True)])
    environment = network(target).model_copy(update={"label": "tenant"})
    return environment, plan_change(environment, [IPS], ["ips"])


def test_follow_up_is_a_plan_for_tenant_data_only_and_states_its_limits() -> None:
    environment, plan = _tenant_plan()
    follow_up = plan_follow_up(environment, plan, "42")
    assert follow_up.asset_ids == ["uuid-1"] and follow_up.rescan_targets == ["10.0.0.5"]
    assert follow_up.remediation[0].solution == "Patch." and "can't apply" in follow_up.cannot_do
    assert not follow_up.executed and plan_follow_up(environment, plan).rescan_targets == []
    assert follow_up.tag_value == f"planned-{plan.plan_hash[:8]}"
    with pytest.raises(ValueError, match="scan id"):
        plan_follow_up(environment, plan, "../../users/1")
    with pytest.raises(ValueError, match="isn't from a Tenable tenant"):
        plan_follow_up(environment.model_copy(update={"label": "synthetic"}), plan)


class RecordingHttp:
    def __init__(self) -> None:
        self.posts: list[tuple[str, Any]] = []

    async def post_json(self, url: str, body: Any, **_: Any) -> dict[str, str]:
        self.posts.append((url, body))
        return {"uuid": "tag-uuid"}


def test_execute_tags_assets_and_launches_the_rescan(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TENABLE_ACCESS_KEY", "synthetic-access")
    monkeypatch.setenv("TENABLE_SECRET_KEY", "synthetic-secret")
    environment, plan = _tenant_plan()
    http = RecordingHttp()
    result: TenableFollowUp = asyncio.run(
        execute_follow_up(TenableOneClient(http), plan_follow_up(environment, plan, "42"))
    )  # type: ignore[arg-type]
    urls = [url.rsplit("cloud.tenable.com", 1)[-1] for url, _ in http.posts]
    assert urls == ["/tags/values", "/tags/assets/assignments", "/scans/42/launch"]
    assert http.posts[1][1] == {"action": "add", "assets": ["uuid-1"], "tags": ["tag-uuid"]}
    assert http.posts[2][1] == {"alt_targets": ["10.0.0.5"]} and len(result.executed) == 3


def test_execute_never_sends_an_empty_target_list_or_tags_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TENABLE_ACCESS_KEY", "synthetic-access")
    monkeypatch.setenv("TENABLE_SECRET_KEY", "synthetic-secret")
    environment, plan = _tenant_plan()
    environment.hosts[0].ips = []
    http = RecordingHttp()
    result = asyncio.run(execute_follow_up(TenableOneClient(http), plan_follow_up(environment, plan, "42")))  # type: ignore[arg-type]
    assert not any("/scans/" in url for url, _ in http.posts) and "skipped scan 42" in result.executed[-1]
    empty = TenableFollowUp(plan_hash="h", tag_value="planned-h", asset_ids=[], rescan_scan_id="42")
    http = RecordingHttp()
    result = asyncio.run(execute_follow_up(TenableOneClient(http), empty))  # type: ignore[arg-type]
    assert http.posts == [] and "nothing written" in result.executed[0]


@pytest.mark.usefixtures("flow_dir")
def test_cli_tenant_apply_is_a_dry_run_by_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    environment, _ = _tenant_plan()
    file = tmp_path / "environment.json"
    file.write_text(environment.model_dump_json(), encoding="utf-8")
    mitigations = tmp_path / "mitigations.json"
    mitigations.write_text(json.dumps([IPS.model_dump(mode="json")]), encoding="utf-8")
    assert main(["flow", "load", "--environment", str(file), "--mitigations", str(mitigations)]) == 0
    capsys.readouterr()
    assert main(["flow", "plan", "ips"]) == 0
    plan_hash = json.loads(capsys.readouterr().out)["plan"]["plan_hash"]

    def forbidden(*_: Any, **__: Any) -> None:
        raise AssertionError("a dry run must not touch the tenant")

    monkeypatch.setattr("porygon_mitigator.flow.tenable.execute_follow_up", forbidden)
    assert main(["flow", "apply", plan_hash]) == 0
    captured = capsys.readouterr()
    assert "dry run, nothing written" in captured.err and json.loads(captured.out)["executed"] == []
    assert main(["flow", "tenable-follow-up", plan_hash]) == 0
    assert "dry run" in capsys.readouterr().err
    assert main(["flow", "tenable-follow-up", "0" * 16]) == 1
    assert "isn't the applied plan" in capsys.readouterr().err

    monkeypatch.setattr("porygon_mitigator.flow.runs.verify_applied", lambda _run: Verification(
        plan_hash=plan_hash, passed=False, before=funnel([]), after=funnel([]), checks=[]))
    assert main(["flow", "tenable-follow-up", plan_hash, "--tenable-execute"]) == 1
    assert "nothing was written" in capsys.readouterr().err


def test_the_funnel_counts_a_severity_however_it_is_written() -> None:
    result = funnel(tag_cves(network(host(findings=[rce(severity="CRITICAL")]))))
    assert (result.remote_critical, result.remote_critical_kev, result.kev_exposed) == (1, 1, 1)


def _two_entries(*hosts: Host, first: str = "s1", second: str = "s2", prefix: int = 24) -> Environment:
    return Environment(
        zones=[Zone(id="internet", kind="internet"), Zone(id="guest", kind="guest"), Zone(id="s1"), Zone(id="s2")],
        devices=[
            Device(id="a", zones=["internet", "s1"], routes=[Route(destination=f"10.0.0.0/{prefix}", zone=first)]),
            Device(id="b", zones=["guest", "s2"], routes=[Route(destination=f"10.0.0.0/{prefix}", zone=second)]),
        ],
        hosts=list(hosts),
    )


def test_entry_devices_that_disagree_place_nothing_whichever_is_listed_first() -> None:
    environment = _two_entries(Host(id="h", ips=["10.0.0.5"]))
    for devices in (environment.devices, environment.devices[::-1]):
        placement = place_host(environment.model_copy(update={"devices": devices}), "h")
        assert (placement.zone, placement.method) == (None, "not_placed")
    assert place_host(_two_entries(Host(id="h", ips=["10.0.0.5"]), second="s1"), "h").zone == "s1"


def test_a_conflict_in_the_routes_isnt_settled_by_a_zone_range() -> None:
    environment = _two_entries(Host(id="h", ips=["10.0.0.5"]))
    environment.zones[2].cidrs = ["10.0.0.0/8"]
    assert place_host(environment, "h").zone is None


@pytest.mark.parametrize("other_route", ["192.0.2.0/24", "192.0.0.0/8"])
def test_a_host_with_addresses_in_two_zones_has_no_single_zone(other_route: str) -> None:
    """Keeping one would drop what an attacker can reach through the other, so it stays unknown."""
    routes = [Route(destination="10.0.0.0/24", zone="s1"), Route(destination=other_route, zone="s2")]
    environment = Environment(
        zones=[Zone(id="internet", kind="internet"), Zone(id="s1"), Zone(id="s2")],
        devices=[Device(id="a", zones=["internet", "s1", "s2"], routes=routes)],
        hosts=[Host(id="two", ips=["10.0.0.5", "192.0.2.5"]), Host(id="same", ips=["10.0.0.5", "10.0.0.6"])],
    )
    assert place_host(environment, "two").zone is None and place_host(environment, "same").zone == "s1"


def test_zone_ranges_that_disagree_place_nothing() -> None:
    environment = Environment(
        zones=[Zone(id="s1", cidrs=["10.0.0.0/24"]), Zone(id="s2", cidrs=["198.51.100.0/24", "10.0.0.0/24"])],
        hosts=[
            Host(id="two", ips=["10.0.0.5", "198.51.100.5"]),
            Host(id="tie", ips=["10.0.0.5"]),
            Host(id="one", ips=["198.51.100.5"]),
        ],
    )
    assert place_host(environment, "two").zone is None and place_host(environment, "tie").zone is None
    assert place_host(environment, "one").zone == "s2"


@pytest.mark.usefixtures("flow_dir")
def test_the_run_s_map_says_how_each_host_was_placed() -> None:
    environment = Environment(
        zones=[Zone(id="internet", kind="internet"), Zone(id="dmz"), Zone(id="corp", cidrs=["198.51.100.0/24"])],
        devices=[Device(id="edge", zones=["internet", "dmz"], routes=[Route(destination="192.0.2.0/24", zone="dmz")])],
        hosts=[
            Host(id="routed", ips=["192.0.2.5"]),
            Host(id="by-range", ips=["198.51.100.5"]),
            Host(id="named", zone="dmz", ips=["203.0.113.5"]),
            Host(id="lost", ips=["203.0.113.6"]),
        ],
    )
    run = runs.start_run(environment, [])
    rows = {row["host"]: row for row in runs.overview(run)["map"]["hosts"]}
    assert {name: row["method"] for name, row in rows.items()} == {
        "routed": "route",
        "by-range": "zone_cidr",
        "named": "declared",
        "lost": "not_placed",
    }
    assert rows["routed"]["devices_in_front"] == ["edge"]


def test_rules_are_parsed_once_not_once_per_port_checked(monkeypatch: pytest.MonkeyPatch) -> None:
    """A rule base of a few thousand named destinations took minutes: each check parsed each destination again."""
    engine._network_of.cache_clear()
    calls: list[str] = []
    real = engine.ipaddress.ip_network

    def counted(value: str, strict: bool = True) -> Any:
        calls.append(value)
        return real(value, strict=strict)

    monkeypatch.setattr(engine.ipaddress, "ip_network", counted)
    rules = [FirewallRule(name=f"r{index}", destination=[f"other-{index}", "10.9.0.0/16"]) for index in range(5)]
    for _ in range(3):
        compute_reachability(network(host(), rules=rules))
    assert len(calls) == len(set(calls))


def _mesh(zones: int, rule: FirewallRule | None = None) -> Environment:
    names = ["internet", *(f"z{index}" for index in range(zones - 2)), "servers"]
    devices = [
        Device(id=f"d{left}-{right}", zones=[names[left], names[right]], rules=[rule] if rule else [])
        for left in range(zones)
        for right in range(left + 1, zones)
    ]
    zone_list = [Zone(id=name, kind="internet" if name == "internet" else "unknown") for name in names]
    return Environment(zones=zone_list, devices=devices, hosts=[host()])


def test_a_meshy_map_stops_searching_and_says_so() -> None:
    """A firewall per pair of zones has millions of simple paths by a dozen zones. Enumerating them hung the flow."""
    closed = _mesh(9)
    assert len(zone_paths(closed, "internet", "servers")) <= engine.MAX_PATHS
    assert (tag(closed).tag, tag(closed).basis) == ("unknown", "not_connected")
    opened = _mesh(9, FirewallRule(name="all"))
    assert tag(opened).tag == "reachable" and tag(opened, mitigations=(IPS,)).protected_by == []


def test_the_path_search_remembers_a_map_but_uses_each_copy_s_rules() -> None:
    environment = network(host())
    assert compute_reachability(environment)[0].reachable is True
    environment.devices[0].rules.clear()
    assert compute_reachability(environment)[0].reachable is False


def test_a_scan_says_when_not_reachable_only_means_it_could_not_tell() -> None:
    chain = [f"z{index}" for index in range(12)]
    far = Environment(
        zones=[Zone(id="internet", kind="internet"), Zone(id="servers"), *(Zone(id=zone) for zone in chain)],
        devices=[
            Device(id=f"d{index}", zones=[left, right], rules=[FirewallRule(name="all")])
            for index, (left, right) in enumerate(zip(["internet", *chain], [*chain, "servers"], strict=True))
        ],
        hosts=[host()],
    )
    assert [(row.reachable, row.settled) for row in compute_reachability(far)] == [(False, False)]
    assert [row.settled for row in compute_reachability(network(host(zone=None)))] == [False]
    no_address = [FirewallRule(name="r", from_zone=["internet"], destination=["10.0.0.0/8"])]
    assert [row.settled for row in compute_reachability(network(host(ips=[]), rules=no_address))] == [False]
    assert [row.settled for row in compute_reachability(network(host(), rules=[]))] == [True]
    assert [row.settled for row in compute_reachability(network(host()))] == [True]


def _applied_ips() -> tuple[Environment, Any, Environment]:
    flow = AllowedFlow(name="dns", source_zone="internet", host="dc")
    other = host("other", ips=["10.0.0.6"], findings=[rce("CVE-2"), rce("CVE-3")])
    rules = [FirewallRule(name="publish", from_zone=["internet"])]
    environment = network(host(), other, rules=rules, flows=[flow])
    plan = plan_change(environment, [IPS], ["ips"])
    return environment, plan, apply_plan(environment, plan, plan.plan_hash)


def _open_a_port_with_no_finding(after: Environment) -> None:
    after.devices[0].rules.insert(0, FirewallRule(name="oops", destination=["dc"]))


def _forge_a_host_control(after: Environment) -> None:
    after.hosts[1].host_controls["forged"] = ["CVE-2"]


def _hide_a_finding(after: Environment) -> None:
    after.hosts[1].findings = []


def _stop_counting_an_attacker_zone(after: Environment) -> None:
    after.zones[0].attacker_vantage = False


def _downgrade(after: Environment) -> None:
    after.hosts[1].findings[0].severity = "low"


@pytest.mark.parametrize(
    "sabotage",
    [_open_a_port_with_no_finding, _forge_a_host_control, _hide_a_finding, _stop_counting_an_attacker_zone, _downgrade],
)
def test_verify_fails_on_anything_the_plan_did_not_change(sabotage: Any) -> None:
    """None of these adds an exposed pair or breaks traffic, and each makes the funnel look better or stays hidden."""
    environment, plan, after = _applied_ips()
    assert verify(environment, after, [IPS], plan).passed
    sabotage(after)
    result = verify(environment, after, [IPS], plan)
    assert not result.passed
    assert any(check.name == "only the planned changes" and not check.passed for check in result.checks)


def test_verify_says_what_changed_besides_the_plan() -> None:
    environment, plan, after = _applied_ips()
    _forge_a_host_control(after)
    check = next(item for item in verify(environment, after, [IPS], plan).checks if not item.passed)
    assert check.detail == "Also changed: host other."


def test_stopping_a_service_can_t_be_undone_behind_verify() -> None:
    service = FlowMitigation(
        id="stop", title="Stop", kind="disable_service", cve_ids=["CVE-2020-1350"], service="dns"
    )
    environment = network(host())
    plan = plan_change(environment, [service], ["stop"])
    after = apply_plan(environment, plan, plan.plan_hash)
    assert verify(environment, after, [service], plan).passed
    after.hosts[0].services["dns"] = "running"
    assert not verify(environment, after, [service], plan).passed


def test_verify_won_t_trust_a_baseline_or_mitigations_other_than_the_plan_s() -> None:
    environment, plan, after = _applied_ips()
    other_baseline = environment.model_copy(deep=True)
    other_baseline.hosts[1].findings = []
    assert not verify(other_baseline, after, [IPS], plan).passed
    forged = FlowMitigation(id="f", title="F", kind="host_setting", cve_ids=["CVE-9"], setting="x")
    assert not verify(environment, after, [IPS, forged], plan).passed


@pytest.mark.usefixtures("flow_dir")
def test_a_pass_from_before_the_network_changed_isn_t_shown_as_a_pass() -> None:
    run = _start_demo()
    runs.apply_approved(runs.make_plan(["sigred-ips"])["plan"]["plan_hash"])
    assert runs.verify_applied().passed and runs.dashboard_data()["verification"]["passed"] is True
    path = runs.flow_dir() / run / "environment.json"
    edited = json.loads(path.read_text(encoding="utf-8"))
    edited["devices"][0]["rules"].insert(0, {"name": "oops"})
    path.write_text(json.dumps(edited), encoding="utf-8")
    assert runs.dashboard_data()["verification"] is None


@pytest.mark.usefixtures("flow_dir")
def test_another_network_can_t_be_loaded_over_an_applied_plan(tmp_path: Path) -> None:
    """It would move `latest`, so the dashboard shows nothing applied and the rollback command finds nothing."""
    _start_demo()
    plan = runs.make_plan(["sigred-ips"])["plan"]["plan_hash"]
    runs.apply_approved(plan)
    file = tmp_path / "other.json"
    file.write_text(network(host()).model_dump_json(), encoding="utf-8")
    assert "applied plan" in _tool("flow_load_environment", {"environment_file": str(file)})["error"]
    with pytest.raises(runs.FlowError, match="applied plan"):
        runs.load_files(str(file), None)
    assert runs.applied_plan() is not None and runs.rollback() == plan
    runs.apply_approved(plan)
    other = runs.load_files(str(file), None, restart=True)
    assert runs.overview()["run_id"] == other


@pytest.mark.usefixtures("flow_dir")
def test_a_damaged_plan_file_is_refused_with_a_message(capsys: pytest.CaptureFixture[str]) -> None:
    run = _start_demo()
    plan = runs.make_plan(["sigred-ips"])["plan"]["plan_hash"]
    path = runs.flow_dir() / run / f"plan-{plan}.json"
    for damage in ('{"half', '{"plan_hash": "x"}'):
        path.write_text(damage, encoding="utf-8")
        assert main(["flow", "apply", plan]) == 1
        assert "can't be read" in capsys.readouterr().err and runs.applied_plan() is None


LAB = ROOT / "demo" / "tenable-lab" / "flow"


def _collect_everything(sources: Path) -> None:
    for step in runs.COLLECT_STEPS:
        result = runs.collect(step, str(sources))
        assert "No firewall, router or scanner was contacted" in result["source_note"]


@pytest.mark.parametrize(
    "folder",
    [
        EXAMPLES,
        pytest.param(
            LAB,
            marks=pytest.mark.skipif(
                not (LAB / "environment.json").exists(), reason="the lab environment is built locally, never committed"
            ),
        ),
    ],
)
def test_collecting_the_exports_gives_the_same_network_back(folder: Path) -> None:
    scanned = Environment.model_validate_json((folder / "environment.json").read_text(encoding="utf-8"))
    placed, collected = place_hosts(scanned), source_files.normalize(folder / "sources", scanned)
    assert not validate_inputs(collected, [])
    decided = [
        {(item.vantage, item.host, item.reachable) for item in compute_reachability(env)}
        for env in (placed, collected)
    ]
    assert decided[0] == decided[1] and funnel(tag_cves(placed)) == funnel(tag_cves(collected))
    assert {flow.name for flow in collected.allowed_flows} == {flow.name for flow in placed.allowed_flows}


@pytest.mark.usefixtures("flow_dir")
def test_mapping_needs_every_source_and_shows_the_rule_deciding_each_path() -> None:
    sources = EXAMPLES / "sources"
    with pytest.raises(runs.FlowError, match="collect these first"):
        runs.map_routes(str(sources))
    runs.collect("firewall", str(sources))
    with pytest.raises(runs.FlowError, match=r"router, assets"):
        runs.map_routes(str(sources))
    _collect_everything(sources)
    mapped = runs.map_routes(str(sources))
    rules = {tuple(item["rules"]) for item in mapped["rule_mapping"]["open_paths"]}
    assert ("pa-edge: dns-published (allow)", "pa-core: dmz-dns (allow)") in rules
    routed = next(item for item in mapped["rule_mapping"]["open_paths"] if item["host"] == "dc-01")
    assert routed["routes"][0].startswith("pa-edge: 203.0.113.0/25 via pa-core")
    assert "pa-core: corp-to-dc" in mapped["rule_mapping"]["rules_no_attacker_path_reaches"]
    data = runs.dashboard_data()
    assert data["collection"]["router"]["routers"][0]["routes"] == 2 and data["rule_mapping"]["paths_mapped"] > 0
    assert "open_paths" not in data["rule_mapping"]


@pytest.mark.usefixtures("flow_dir")
def test_collecting_a_missing_or_broken_source_says_which(tmp_path: Path) -> None:
    with pytest.raises(runs.FlowError, match=r"assets\.json"):
        runs.collect("assets", str(tmp_path))
    (tmp_path / "firewalls").mkdir()
    (tmp_path / "firewalls" / "fw.json").write_text("{}", encoding="utf-8")
    with pytest.raises(runs.FlowError, match="expected shape"):
        runs.collect("firewall", str(tmp_path))
    with pytest.raises(runs.FlowError, match="unknown step"):
        runs.collect("nmap", str(tmp_path))
    assert "absolute" in _tool("flow_collect", {"step": "firewall", "sources_dir": "relative"})["error"]


def test_recommendation_covers_the_most_without_breaking_anything() -> None:
    environment, mitigations = demo()
    advice = recommend(environment, mitigations)
    picked = [item.mitigation_id for item in advice.selected]
    assert "spooler-disable" not in picked and not advice.breaks
    assert (advice.kev_exposed_now, advice.kev_exposed_after, advice.left_exposed) == (6, 0, [])
    assert "breaks" not in advice.not_selected and "Office printing" in advice.not_selected["spooler-disable"]
    plan = plan_change(environment, mitigations, picked)
    assert plan.expected_after.kev_exposed == advice.kev_exposed_after


def test_recommendation_skips_a_mitigation_that_adds_nothing_and_says_what_stays_exposed() -> None:
    def block(name: str, cves: list[str], threat: str) -> FlowMitigation:
        return FlowMitigation(id=name, title=name, kind="ips_threat_ids", cve_ids=cves, threat_ids=[threat])

    environment = network(host(findings=[rce("CVE-1"), rce("CVE-2"), rce("CVE-3")]))
    mitigations = [block("both", ["CVE-1", "CVE-2"], "1"), block("one", ["CVE-1"], "2")]
    advice = recommend(environment, mitigations)
    assert [item.mitigation_id for item in advice.selected] == ["both"] and advice.selected[0].adds_kev == 2
    assert "already covered" in advice.not_selected["one"]
    assert advice.left_exposed == ["CVE-3 on dc"] and advice.kev_exposed_after == 1


def test_recommending_changes_nothing() -> None:
    environment, mitigations = demo()
    before = environment_hash(environment)
    recommend(environment, mitigations)
    assert environment_hash(environment) == before


def test_plan_says_what_approving_it_means() -> None:
    environment, mitigations = demo()
    plan = plan_change(environment, mitigations, ["sigred-ips", "winverifytrust-registry"])
    impact = {item.mitigation_id: item for item in plan.impact}
    ips = impact["sigred-ips"]
    assert ips.devices == ["pa-core"] and ips.hosts_changed == []
    assert ips.rules == ["pa-core: dmz-dns", "pa-core: temp-rdp-core"]
    assert ips.hosts_protected == ["dc-01"] and ips.protects_kev == 1 and ips.side_effects and ips.rollback
    assert "Corporate DNS" not in ips.traffic_crossing
    host_change = impact["winverifytrust-registry"]
    assert host_change.hosts_changed == ["dc-01", "print-01"] and "Office printing" in host_change.traffic_crossing
    tests = {item.runs_on: item for item in plan.test_first}
    assert any("VM-Series" in item.image and "pa-core" in item.targets for item in tests.values())
    assert any("Windows Server evaluation" in item.image and "print-01" in item.targets for item in tests.values())
    edited = plan.model_copy(deep=True)
    edited.impact[0].protects = 99
    with pytest.raises(ValueError, match="edited"):
        apply_plan(environment, edited, edited.plan_hash)


def test_traffic_crossing_a_changed_rule_is_listed() -> None:
    flow = AllowedFlow(name="public dns", source_zone="internet", host="dc")
    plan = plan_change(network(host(), flows=[flow]), [IPS], ["ips"])
    assert plan.impact[0].traffic_crossing == ["public dns"] and not plan.impact[0].breaks


def _start_network(tmp_path: Path, *hosts: Host, mitigations: list[FlowMitigation] | None = None) -> None:
    file = tmp_path / "environment.json"
    file.write_text(network(*hosts).model_dump_json(), encoding="utf-8")
    other = tmp_path / "mitigations.json"
    other.write_text(json.dumps([item.model_dump(mode="json") for item in mitigations or []]), encoding="utf-8")
    runs.load_files(str(file), str(other), restart=True)


@pytest.mark.usefixtures("flow_dir")
def test_normalizing_rejects_unknown_cves_bad_shapes_and_cleans_fields(tmp_path: Path) -> None:
    _start_network(tmp_path, host())
    result = runs.save_normalized([
        {"cve": "CVE-9"},
        {"cve": "CVE-2020-1350", "made_up_field": 1},
        {"cve": "CVE-2020-1350", "processes": ["  dns.exe  ", ""]},
    ])
    assert [item["cve"] for item in result["rejected"]] == ["CVE-9", "CVE-2020-1350"] and result["saved"] == 1
    saved = runs.environment_state()["vulnerabilities"]["CVE-2020-1350"]
    assert saved["processes"] == ["dns.exe"]


@pytest.mark.usefixtures("flow_dir")
def test_normalizing_lists_urgent_first_and_invalidates_old_plans(tmp_path: Path) -> None:
    quiet = rce("CVE-QUIET", kev=False, severity="low")
    _start_network(tmp_path, host(findings=[quiet, rce("CVE-2020-1350")]), mitigations=[IPS])
    batch = runs.vulnerabilities_to_normalize()
    assert [item["cve"] for item in batch["batch"]] == ["CVE-2020-1350", "CVE-QUIET"] and batch["remaining"] == 2
    plan = runs.make_plan(["ips"])["plan"]["plan_hash"]
    runs.save_normalized([{"cve": "CVE-2020-1350"}])
    assert runs.vulnerabilities_to_normalize()["remaining"] == 1
    with pytest.raises(runs.FlowError, match="no plan"):
        runs.apply_approved(plan)
    fresh = runs.make_plan(["ips"])["plan"]["plan_hash"]
    runs.apply_approved(fresh)
    with pytest.raises(runs.FlowError, match=r"plan is applied"):
        runs.save_normalized([{"cve": "CVE-QUIET"}])


def _researched(kind: str, target: str, **fields: Any) -> Mitigation:
    today = date(2026, 11, 3)
    return Mitigation(
        id="m1", cve_id="CVE-1", type=fields.pop("type", "OTHER"), layer=fields.pop("layer", "host"), title="T",
        summary="S", action=Action(kind=kind, target=target), first_seen=today, last_confirmed=today,  # type: ignore[arg-type]
        **fields,
    )


@pytest.mark.parametrize(
    ("kind", "target"),
    [("apply_ips_signature", "snort:1"), ("apply_waf_rule", "cloudflare:1"), ("restrict_network_access", "confluence")],
)
def test_what_the_simulation_cant_enforce_says_why(kind: str, target: str) -> None:
    assert isinstance(research.to_flow_mitigation(_researched(kind, target)), str)


def test_finding_mitigations_says_which_key_is_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "PALO_ALTO_THREAT_VAULT_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    with pytest.raises(ValueError, match="ANTHROPIC_API_KEY"):
        asyncio.run(research.find(["CVE-1"], "websearch"))
    with pytest.raises(ValueError, match="PALO_ALTO_THREAT_VAULT_API_KEY"):
        asyncio.run(research.find(["CVE-1"], "threat_vault"))


@pytest.mark.usefixtures("flow_dir")
def test_threat_vault_signatures_join_the_run(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("PALO_ALTO_THREAT_VAULT_API_KEY", "synthetic")
    monkeypatch.setattr(
        research, "load_indexes", lambda _settings: {"threat_vault": {"CVE-2020-1350": {"rules": ["58691", "59168"]}}}
    )
    found, skipped = asyncio.run(research.find(["CVE-2020-1350", "CVE-404"], "threat_vault"))
    assert found[0].threat_ids == ["58691", "59168"] and skipped[0]["cve"] == "CVE-404"
    _start_network(tmp_path, host())
    assert not match_mitigations(Environment.model_validate(runs.environment_state()), [])
    assert runs.add_mitigations(found)["added"] == [found[0].id]
    assert runs.candidates()["candidates"][0]["mitigation_id"] == found[0].id
    plan = runs.make_plan([found[0].id])["plan"]["plan_hash"]
    assert runs.add_mitigations([])["total"] == 1
    runs.add_mitigations(found)
    more = [IPS.model_copy(update={"id": "another"})]
    assert runs.add_mitigations(more)["added"] == ["another"]
    with pytest.raises(runs.FlowError, match="no plan"):
        runs.apply_approved(plan)


def test_a_route_on_one_address_and_a_zone_range_on_the_other_don_t_make_one_zone() -> None:
    route = Route(destination="10.0.0.0/24", zone="srv")
    environment = Environment(
        zones=[Zone(id="internet", kind="internet"), Zone(id="srv"), Zone(id="dmz", cidrs=["203.0.113.0/24"])],
        devices=[Device(id="a", zones=["internet", "srv", "dmz"], routes=[route])],
        hosts=[
            Host(id="two", ips=["10.0.0.5", "203.0.113.5"]),
            Host(id="routed", ips=["10.0.0.6", "198.51.100.6"]),
            Host(id="by-range", ips=["203.0.113.7", "198.51.100.7"]),
        ],
    )
    assert place_host(environment, "two").zone is None
    assert (place_host(environment, "routed").zone, place_host(environment, "routed").method) == ("srv", "route")
    by_range = place_host(environment, "by-range")
    assert (by_range.zone, by_range.method) == ("dmz", "zone_cidr")


def test_verify_won_t_trust_a_plan_edited_to_cover_a_sabotage() -> None:
    environment, plan, after = _applied_ips()
    after.hosts[1].host_controls["forged"] = ["CVE-2"]
    forged = plan.model_copy(deep=True)
    forged.changes.append(
        Change(kind="set_host_control", target="other", mitigation_id="ips", setting="forged", cve_ids=["CVE-2"])
    )
    assert not verify(environment, after, [IPS], forged).passed


@pytest.mark.usefixtures("flow_dir")
def test_a_plan_file_swapped_after_it_was_applied_is_refused() -> None:
    run = _start_demo()
    plan = runs.make_plan(["sigred-ips"])["plan"]["plan_hash"]
    other = runs.make_plan(["bluekeep-ips"])["plan"]
    runs.apply_approved(plan)
    (runs.flow_dir() / run / f"plan-{plan}.json").write_text(json.dumps(other), encoding="utf-8")
    with pytest.raises(runs.FlowError, match="isn't the plan that was approved"):
        runs.verify_applied()


@pytest.mark.usefixtures("flow_dir")
def test_a_damaged_plan_file_gets_a_message_everywhere(tmp_path: Path) -> None:
    run = _start_demo()
    plan = runs.make_plan(["sigred-ips"])["plan"]["plan_hash"]
    runs.apply_approved(plan)
    (runs.flow_dir() / run / f"plan-{plan}.json").write_text('{"half', encoding="utf-8")
    with pytest.raises(runs.FlowError, match="can't be read"):
        runs.verify_applied()
    assert "can't be read" in _dashboard()["error"]
    assert runs.rollback() == plan


def test_an_executable_path_with_spaces_keeps_its_name() -> None:
    """Cut at the space it was the name `program`, so the listener looked named and ruled the real product out."""
    output = json.dumps(
        {"listening": [{"port": 14330, "protocol": "TCP", "plugin_output":
                        "Executable : C:\\Program Files\\Microsoft SQL Server\\Binn\\sqlservr.exe\nMore : x"}]}
    )
    assert listener_processes(34252, output) == {14330: "sqlservr.exe"}


def test_the_search_stops_at_its_step_limit_too(monkeypatch: pytest.MonkeyPatch) -> None:
    """A map where the target can't be reached finds no path to count, so only the steps stop it."""
    monkeypatch.setattr(engine, "MAX_SEARCH_STEPS", 5)
    engine._walk_zones.cache_clear()
    environment = _mesh(9)
    environment.devices = [device for device in environment.devices if "servers" not in device.zones]
    assert engine._search_zone_paths(environment, "internet", "servers") == ([], True)
    engine._walk_zones.cache_clear()


def test_a_reachable_row_is_settled_even_where_the_search_was_cut_short() -> None:
    row = compute_reachability(_mesh(9, FirewallRule(name="all")))[0]
    assert (row.reachable, row.settled) == (True, True)
    assert (compute_reachability(_mesh(9))[0].reachable, compute_reachability(_mesh(9))[0].settled) == (False, False)


@pytest.mark.usefixtures("flow_dir")
def test_a_run_with_an_applied_plan_won_t_restart_even_when_latest_moved_on(tmp_path: Path) -> None:
    first = _start_demo()
    plan = runs.make_plan(["sigred-ips"])["plan"]["plan_hash"]
    runs.apply_approved(plan)
    (runs.flow_dir() / "latest").write_text("0" * 16 + "\n", encoding="utf-8")
    (runs.flow_dir() / ("0" * 16)).mkdir()
    with pytest.raises(runs.FlowError, match="applied plan"):
        _start_demo()
    assert runs.applied_plan(first) is not None


def test_verify_compares_the_baseline_with_the_plan_s_even_if_the_network_agrees() -> None:
    environment, plan, _ = _applied_ips()
    rewritten = environment.model_copy(deep=True)
    rewritten.hosts[1].findings = []
    edited_after = apply_plan(environment, plan, plan.plan_hash)
    edited_after.hosts[1].findings = []
    result = verify(rewritten, edited_after, [IPS], plan)
    assert any(check.name == "the inputs the plan was made on" and not check.passed for check in result.checks)


@pytest.mark.usefixtures("flow_dir")
def test_a_mistyped_argument_doesn_t_load_the_example_instead() -> None:
    """Measured on the real agent: it passed `file_path`, the tool ignored it, and it reported the synthetic network's
    numbers as the answer about the person's files."""
    with pytest.raises(ToolError, match="environment_file"):
        _tool("flow_load_environment", {"file_path": "/some/environment.json"})
    assert "environment_file" in _tool("flow_load_environment", {})["error"]
    with pytest.raises(runs.FlowError, match="no flow run"):
        runs.overview()
    assert _tool("flow_load_environment", {"bundled_example": True})["label"] == "synthetic"
    both = {"environment_file": str(EXAMPLES / "environment.json"), "bundled_example": True}
    assert "not both" in _tool("flow_load_environment", both)["error"]


def test_a_normalizer_leaving_fields_null_still_saves(tmp_path: Path) -> None:
    _start_network(tmp_path, host())
    result = runs.save_normalized(
        [{"cve": "CVE-2020-1350", "vulnerability_class": None, "processes": None, "affected_versions": ""}]
    )
    assert result["saved"] == 1 and not result["rejected"]


def test_an_out_of_support_os_doesnt_point_at_an_image_nobody_offers() -> None:
    windows = host(os="Microsoft Windows Server 2008 R2 Datacenter")
    plan = plan_change(network(windows), [IPS], ["ips"])
    assert next(item for item in plan.test_first if "dc" in item.targets).image.startswith("Out of support")


def test_a_rule_behind_a_deny_is_one_no_attacker_path_reaches() -> None:
    environment = Environment(
        zones=[Zone(id="internet", kind="internet"), Zone(id="dmz"), Zone(id="servers")],
        devices=[
            Device(id="edge", zones=["internet", "dmz"], rules=[FirewallRule(name="block", action="deny")]),
            Device(id="core", zones=["dmz", "servers"], rules=[FirewallRule(name="behind")]),
        ],
        hosts=[host()],
    )
    assert source_files.map_routes_to_rules(environment)["rules_no_attacker_path_reaches"] == ["core: behind"]


def test_a_rule_on_any_blocked_path_counts_as_reached_not_only_the_closest() -> None:
    environment = Environment(
        zones=[Zone(id="internet", kind="internet"), Zone(id="dmz"), Zone(id="servers")],
        devices=[
            Device(id="direct", zones=["internet", "servers"], rules=[FirewallRule(name="a", action="deny")]),
            Device(id="edge", zones=["internet", "dmz"], rules=[FirewallRule(name="b")]),
            Device(id="core", zones=["dmz", "servers"], rules=[FirewallRule(name="c", action="deny")]),
        ],
        hosts=[host()],
    )
    assert source_files.map_routes_to_rules(environment)["rules_no_attacker_path_reaches"] == []


def _firewall_folder(tmp_path: Path, rules: list[dict[str, Any]], **fields: Any) -> Path:
    export = {
        "hostname": "fw",
        "type": "PaloAltoNGFW",
        "threat_prevention_license": True,
        "zones": [{"name": "internet", "kind": "internet"}, {"name": "servers"}, {"name": "corp"}],
        "virtual_router": {"routes": []},
        "security_rules": rules,
        **fields,
    }
    sources = tmp_path / "sources"
    (sources / "firewalls").mkdir(parents=True, exist_ok=True)
    (sources / "firewalls" / "fw.json").write_text(json.dumps(export), encoding="utf-8")
    (sources / "assets.json").write_text(json.dumps({"hosts": [], "network_events": []}), encoding="utf-8")
    apps = {"PaloAltoNGFW": {"applications": {"ssl": ["443/tcp"], "dns": ["53/tcp"]}}}
    (sources / "vendor_mappings.json").write_text(json.dumps(apps), encoding="utf-8")
    return sources


PUBLISH_DNS = {
    "name": "publish",
    "from": ["internet"],
    "to": ["servers"],
    "destination": ["any"],
    "service": ["53/tcp"],
}


def test_a_disabled_rule_doesnt_count(tmp_path: Path) -> None:
    off = {"name": "off", "action": "deny", "service": ["any"], "disabled": True}
    environment = source_files.normalize(_firewall_folder(tmp_path, [off, PUBLISH_DNS]), network(host()))
    assert tag(environment).tag == "reachable" and [rule.name for rule in environment.devices[0].rules] == ["publish"]


def test_a_firewall_export_without_a_licence_isnt_assumed_licensed(tmp_path: Path) -> None:
    folder = _firewall_folder(tmp_path, [], threat_prevention_license=False)
    assert source_files.normalize(folder, network(host())).devices[0].threat_prevention is False
    export = json.loads((folder / "firewalls" / "fw.json").read_text(encoding="utf-8"))
    del export["threat_prevention_license"]
    (folder / "firewalls" / "fw.json").write_text(json.dumps(export), encoding="utf-8")
    assert source_files.normalize(folder, network(host())).devices[0].threat_prevention is False


def test_assets_need_their_events_keep_a_scanned_zone_and_cant_contradict_routes(tmp_path: Path) -> None:
    folder = _firewall_folder(tmp_path, [PUBLISH_DNS])
    assert source_files.normalize(folder, network(host())).hosts[0].zone == "servers"
    (folder / "assets.json").write_text(json.dumps({"hosts": []}), encoding="utf-8")
    with pytest.raises(source_files.SourceError, match="network_events"):
        source_files.normalize(folder, network(host()))
    routed = _firewall_folder(
        tmp_path, [PUBLISH_DNS], virtual_router={"routes": [{"destination": "10.0.0.0/24", "zone": "servers"}]}
    )
    assets = {"hosts": [{"host": "dc", "zone": "corp", "ips": ["10.0.0.9"]}], "network_events": []}
    (routed / "assets.json").write_text(json.dumps(assets), encoding="utf-8")
    with pytest.raises(source_files.SourceError, match="routes say servers"):
        source_files.normalize(routed, network(host()))


def test_rule_mapping_counts_blocked_paths_and_gives_a_route_row_per_hop(tmp_path: Path) -> None:
    allow = FirewallRule(name="allow", from_zone=["internet"])
    environment = Environment(
        zones=[Zone(id="internet", kind="internet"), Zone(id="servers")],
        devices=[
            Device(id="a", zones=["internet", "servers"], rules=[FirewallRule(name="deny-all", action="deny")]),
            Device(id="b", zones=["internet", "servers"], rules=[allow]),
        ],
        hosts=[host()],
    )
    mapped = source_files.map_routes_to_rules(environment)
    assert mapped["rules_no_attacker_path_reaches"] == [] and mapped["paths_mapped"] == 2 and mapped["paths_open"] == 1
    assert mapped["open_paths"][0]["routes"] == ["b: no route known"]
    assert mapped["open_paths"][0]["rules"] == ["b: allow (allow)"]


@pytest.mark.usefixtures("flow_dir")
def test_source_problems_read_as_messages_not_crashes(tmp_path: Path) -> None:
    with pytest.raises(runs.FlowError, match="no sources folder"):
        runs.collect("firewall", str(tmp_path / "missing"))
    folder = _firewall_folder(tmp_path, [{"service": ["53/tcp"]}])
    for step in runs.COLLECT_STEPS:
        runs.collect(step, str(folder))
    with pytest.raises(runs.FlowError, match=r"no environment\.json"):
        runs.map_routes(str(folder))
    (folder.parent / "environment.json").write_text(network(host()).model_dump_json(), encoding="utf-8")
    with pytest.raises(runs.FlowError, match="expected shape"):
        runs.map_routes(str(folder))


OPENSSH = {"port": None, "family": "Misc.", "title": "OpenSSH RCE", "product": "OpenSSH"}
SSH_OPEN = [FirewallRule(name="ssh", from_zone=["internet"])]


@pytest.mark.usefixtures("flow_dir")
def test_too_short_evidence_is_dropped_and_a_save_of_nothing_keeps_plans(tmp_path: Path) -> None:
    _start_network(tmp_path, host(), mitigations=[IPS])
    plan = runs.make_plan(["ips"])["plan"]["plan_hash"]
    plan_file = runs.flow_dir() / runs.overview()["run_id"] / f"plan-{plan}.json"
    assert runs.save_normalized([{"cve": "CVE-9"}])["saved"] == 0
    assert runs.add_mitigations([])["added"] == []
    assert plan_file.exists()
    result = runs.save_normalized([{"cve": "CVE-2020-1350", "vulnerability_class": "server", "class_evidence": "e"}])
    assert "evidence" in result["rejected"][0]["why"]
    assert runs.environment_state()["vulnerabilities"]["CVE-2020-1350"]["vulnerability_class"] == ""
    assert not plan_file.exists()


@pytest.mark.usefixtures("flow_dir")
def test_saves_keep_baseline_and_current_together_and_a_reload_wont_lose_them(tmp_path: Path) -> None:
    _start_network(tmp_path, host(), mitigations=[IPS])
    run = runs.overview()["run_id"]
    runs.save_normalized([{"cve": "CVE-2020-1350", "processes": ["dns.exe"]}])
    baseline = json.loads((runs.flow_dir() / run / "baseline.json").read_text(encoding="utf-8"))
    assert "CVE-2020-1350" in baseline["vulnerabilities"]
    with pytest.raises(runs.FlowError, match="would lose"):
        runs.load_files(str(tmp_path / "environment.json"), str(tmp_path / "mitigations.json"))
    runs.load_files(str(tmp_path / "environment.json"), str(tmp_path / "mitigations.json"), restart=True)
    assert runs.environment_state()["vulnerabilities"] == {}


@pytest.mark.usefixtures("flow_dir")
def test_mapping_reads_saved_normalization_and_mitigations_beside_the_sources(tmp_path: Path) -> None:
    folder = _firewall_folder(tmp_path, [PUBLISH_DNS])
    (folder.parent / "environment.json").write_text(network(host()).model_dump_json(), encoding="utf-8")
    saved = {"CVE-2020-1350": {"cve": "CVE-2020-1350", "processes": ["dns.exe"]}}
    (folder.parent / "normalized.json").write_text(json.dumps(saved), encoding="utf-8")
    (folder.parent / "mitigations.json").write_text(json.dumps([IPS.model_dump(mode="json")]), encoding="utf-8")
    for step in runs.COLLECT_STEPS:
        runs.collect(step, str(folder))
    result = runs.map_routes(str(folder))
    assert "No firewall" in result["source_note"]
    assert "CVE-2020-1350" in runs.environment_state()["vulnerabilities"]
    assert runs.candidates()["candidates"][0]["mitigation_id"] == "ips"


def _block(name: str, cves: list[str], threat: str = "1", **fields: Any) -> FlowMitigation:
    return FlowMitigation(id=name, title=name, kind="ips_threat_ids", cve_ids=cves, threat_ids=[threat], **fields)


def test_a_held_mitigation_is_offered_and_kept_apart_from_what_nothing_can_stop() -> None:
    flow = AllowedFlow(name="dns", source_zone="internet", host="dc", service="dns")
    environment = network(host(findings=[rce("CVE-1"), rce("CVE-2")]), flows=[flow])
    stop = FlowMitigation(id="stop", title="Stop", kind="disable_service", cve_ids=["CVE-1"], service="dns")
    advice = recommend(environment, [stop])
    assert advice.selected == [] and advice.left_exposed == ["CVE-1 on dc", "CVE-2 on dc"]
    assert advice.no_option == ["CVE-2 on dc"] and advice.held_options[0].would_stop == ["CVE-1 on dc"]


def test_a_held_acl_is_offered_for_every_cve_on_the_port_it_closes() -> None:
    flow = AllowedFlow(name="dns", source_zone="internet", host="dc", service="dns")
    environment = network(host(findings=[rce("CVE-1"), rce("CVE-2")]), flows=[flow])
    close = FlowMitigation(id="close", title="Close", kind="acl_block", cve_ids=["CVE-1"])
    advice = recommend(environment, [close])
    assert advice.selected == [] and advice.no_option == []
    assert advice.held_options[0].would_stop == ["CVE-1 on dc", "CVE-2 on dc"]


def test_recommendation_counts_kev_like_the_funnel_and_reports_the_rest() -> None:
    findings = [rce("HIGH", severity="high"), rce("PLAIN", kev=False), rce("NEAR", access_vector="adjacent")]
    environment = network(host(findings=findings))
    advice = recommend(environment, [])
    assert advice.left_exposed == ["HIGH on dc"] and advice.kev_exposed_now == 0 and advice.other_exposed_after == 1


@pytest.mark.parametrize(
    ("name", "image"),
    [
        ("Windows Server 2003", "Out of support"),
        ("Windows XP", "Out of support"),
        ("CentOS Linux 7", "Out of support"),
        ("RHEL 8", "RHEL"),
        ("Microsoft Windows Server 2019", "Windows Server evaluation"),
    ],
)
def test_image_advice_matches_the_os(name: str, image: str) -> None:
    plan = plan_change(network(host(os=name)), [IPS], ["ips"])
    assert next(item for item in plan.test_first if "dc" in item.targets).image.startswith(image)


def test_researched_signature_keeps_every_threat_id_and_a_change_is_never_risk_zero() -> None:
    item = _researched("apply_ips_signature", "paloaltonetworks:58691", rule_ids=["58691", "59168", "not-a-number"])
    converted = research.to_flow_mitigation(item)
    assert isinstance(converted, FlowMitigation) and converted.threat_ids == ["58691", "59168"] and converted.risk == 2


@pytest.mark.parametrize(
    ("kind", "target", "platforms", "expected"),
    [
        ("disable_service", "spooler", ["windows"], "Windows"),
        ("set_registry_value", "hklm\\x=1", [], "Windows"),
        ("set_sysctl", "a=0", [], "Linux"),
        ("set_config", "a:b=1", ["windows", "linux"], None),
    ],
)
def test_researched_change_stays_on_its_platform(
    kind: str, target: str, platforms: list[str], expected: str | None
) -> None:
    item = _researched(kind, target, applies_to=AppliesTo(platforms=platforms))  # type: ignore[arg-type]
    converted = research.to_flow_mitigation(item)
    assert isinstance(converted, FlowMitigation) and converted.os == expected


def test_a_change_for_a_platform_not_on_this_network_isnt_widened() -> None:
    item = _researched("set_config", "a:b=1", applies_to=AppliesTo(platforms=["macos"]))
    assert isinstance(research.to_flow_mitigation(item), str)


def test_linux_mitigation_reaches_a_named_distribution() -> None:
    setting = FlowMitigation(
        id="s", title="S", kind="host_setting", cve_ids=["CVE-2020-1350"], setting="x", os="Linux"
    )
    assert match_mitigations(network(host(os="Ubuntu 22.04")), [setting])[0].status == "proceed"
    assert match_mitigations(network(host(os="Windows Server")), [setting])[0].status == "hold"


def test_websearch_converts_what_it_finds_and_one_failure_keeps_the_rest(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "synthetic")
    items = [_researched("disable_service", "spooler"), _researched("apply_waf_rule", "cloudflare:1")]

    async def fake(cve: str, **_: Any) -> tuple[Any, str, None]:
        if cve == "CVE-BAD":
            raise RuntimeError("boom")
        return SimpleNamespace(active_mitigations=lambda: items), "live", None

    monkeypatch.setattr(research, "get_record", fake)
    found, skipped = asyncio.run(research.find(["CVE-1", "CVE-BAD"], "websearch"))
    assert [item.kind for item in found] == ["disable_service"]
    assert {item["cve"] for item in skipped} == {"CVE-1", "CVE-BAD"} and "RuntimeError" in str(skipped)


def test_threat_vault_syncs_when_it_has_no_index(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PALO_ALTO_THREAT_VAULT_API_KEY", "synthetic")
    index: dict[str, Any] = {}
    calls = []

    async def fake_sync(sources: list[str], _settings: Any) -> list[Any]:
        calls.append(sources)
        index["threat_vault"] = {"CVE-1": {"rules": ["7"]}}
        return []

    monkeypatch.setattr(research, "load_indexes", lambda _settings: index)
    monkeypatch.setattr(research, "sync", fake_sync)
    monkeypatch.setattr(research, "reload_indexes", lambda: None)
    found, _ = asyncio.run(research.find(["CVE-1"], "threat_vault"))
    assert calls == [["threat_vault"]] and found[0].threat_ids == ["7"]


@pytest.mark.usefixtures("flow_dir")
def test_find_tool_checks_the_run_first_and_reports_failures(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    async def broken(*_: Any, **__: Any) -> Any:
        raise RuntimeError("secret detail")

    monkeypatch.setattr(research, "find", broken)
    arguments = {"cve_ids": ["CVE-1"], "source": "websearch"}
    assert "no flow run" in _tool("flow_find_mitigations", arguments)["error"]
    _start_network(tmp_path, host())
    error = _tool("flow_find_mitigations", arguments)["error"]
    assert "RuntimeError" in error and "secret detail" not in error


@pytest.mark.usefixtures("flow_dir")
def test_mitigations_cant_be_added_over_an_applied_plan(tmp_path: Path) -> None:
    _start_network(tmp_path, host(), mitigations=[IPS])
    runs.apply_approved(runs.make_plan(["ips"])["plan"]["plan_hash"])
    with pytest.raises(runs.FlowError, match=r"plan is applied"):
        runs.add_mitigations([_block("other", ["CVE-2020-1350"])])


def test_normalized_ports_dont_turn_a_local_or_client_flaw_reachable() -> None:
    rules = [FirewallRule(name="r", from_zone=["internet"])]
    for finding in (rce("CVE-1", access_vector="local"), rce("CVE-1", vulnerability_class="client")):
        environment = network(host(findings=[finding]), rules=rules)
        environment.vulnerabilities["CVE-1"] = VulnerabilityProfile(cve="CVE-1")
        assert tag(environment, "CVE-1").exposed is False


@pytest.mark.usefixtures("flow_dir")
def test_collecting_refuses_a_source_that_isnt_one_object(tmp_path: Path) -> None:
    """A Tenable export dropped in as assets.json is a list: refuse it with a reason, don't crash or misread it."""
    sources = tmp_path / "sources"
    sources.mkdir()
    (sources / "assets.json").write_text(json.dumps([{"id": "a", "network": {}, "sources": []}]), encoding="utf-8")
    for step in ("assets",):
        with pytest.raises(runs.FlowError, match=r"holds a JSON array, not the object"):
            runs.collect(step, str(sources))
        assert "holds a JSON array" in _tool("flow_collect", {"step": step, "sources_dir": str(sources)})["error"]
    (sources / "assets.json").write_text("null", encoding="utf-8")
    assert "holds a JSON null" in _tool("flow_collect", {"step": "assets", "sources_dir": str(sources)})["error"]


def test_two_exports_that_disagree_about_a_zone_stop_the_run() -> None:
    """Keeping the first would read a zone one export calls an attacker's as safe, depending on which sorts first."""
    first = {"zones": [{"name": "dmz", "kind": "dmz", "attacker_vantage": False}]}
    second = {"zones": [{"name": "dmz", "kind": "dmz", "attacker_vantage": True}]}
    with pytest.raises(source_files.SourceError, match="disagree"):
        source_files._zones([first, second])
    other_range = {"zones": [{"name": "dmz", "kind": "dmz", "attacker_vantage": False, "cidrs": ["10.0.0.0/8"]}]}
    with pytest.raises(source_files.SourceError, match="disagree"):
        source_files._zones([first, other_range])
    renamed = {"zones": [{"name": "dmz", "kind": "dmz", "attacker_vantage": False, "display_name": "DMZ"}]}
    assert len(source_files._zones([first, renamed])) == 1


def test_a_change_that_also_covers_macos_still_applies_to_the_hosts_here() -> None:
    """Log4Shell's JndiLookup removal says linux, macos and windows. Skipping it lost it for the hosts that are here."""
    every = research.to_flow_mitigation(
        _researched("remove_component", "log4j:x", applies_to=AppliesTo(platforms=["linux", "macos", "windows"]))
    )
    assert isinstance(every, FlowMitigation) and every.kind == "host_setting" and every.os is None
    one = research.to_flow_mitigation(
        _researched("remove_component", "log4j:x", applies_to=AppliesTo(platforms=["linux", "macos"]))
    )
    assert isinstance(one, FlowMitigation) and one.os == "Linux"


@pytest.mark.usefixtures("flow_dir")
@pytest.mark.parametrize(
    ("claim", "quote"),
    [("local", "Microsoft DNS"), ("client", "DNS Server Remote"), ("client", "Apply the July 2020 security update.")],
)
def test_a_recorded_class_needs_words_that_say_it(claim: str, quote: str) -> None:
    """A person reads the class, so `local` on the words "Microsoft DNS" would mislead even if no verdict moves."""
    _start_demo()
    result = runs.save_normalized([{"cve": "CVE-2020-1350", "vulnerability_class": claim, "class_evidence": quote}])
    saved = runs.environment_state()["vulnerabilities"]["CVE-2020-1350"]
    assert result["rejected"] and saved["vulnerability_class"] == ""


@pytest.mark.usefixtures("flow_dir")
def test_a_list_field_sent_as_one_string_is_kept() -> None:
    """Measured on Haiku: it sent affected_versions as a string, and the whole item was rejected until it retried."""
    _start_demo()
    result = runs.save_normalized([{"cve": "CVE-2020-1350", "affected_versions": "2.0 < 2.3", "protocols": "DNS"}])
    saved = runs.environment_state()["vulnerabilities"]["CVE-2020-1350"]
    assert result["saved"] == 1 and saved["affected_versions"] == ["2.0 < 2.3"] and saved["protocols"] == ["DNS"]


@pytest.mark.parametrize(
    ("tool", "arguments"),
    [
        ("flow_collect", {"step": "firewall", "source_dir": "/nowhere"}),
        ("flow_match_mitigations", {"mitigations_file": "/nowhere.json"}),
        ("scan_coverage", {"findings": []}),
    ],
)
def test_a_tool_refuses_an_argument_it_does_not_have(tool: str, arguments: dict[str, Any]) -> None:
    with pytest.raises(ToolError, match="has no argument"):
        asyncio.run(server.call_tool(tool, arguments))


@pytest.mark.usefixtures("flow_dir")
def test_collect_says_which_folder_it_read(tmp_path: Path) -> None:
    folder = _firewall_folder(tmp_path, [PUBLISH_DNS])
    assert runs.collect("firewall", str(folder))["read_from"] == str(folder)
    assert runs.collect("firewall")["read_from"] == "the bundled example"


@pytest.mark.usefixtures("flow_dir")
def test_map_names_the_collected_folder_instead_of_reusing_it(tmp_path: Path) -> None:
    folder = _firewall_folder(tmp_path, [PUBLISH_DNS])
    (folder.parent / "environment.json").write_text(network(host()).model_dump_json(), encoding="utf-8")
    for step in runs.COLLECT_STEPS:
        runs.collect(step, str(folder))
    with pytest.raises(runs.FlowError, match=str(folder)):
        runs.map_routes()
    assert runs.map_routes(str(folder))["read_from"] == str(folder)


@pytest.mark.usefixtures("flow_dir")
def test_match_says_when_the_run_has_no_mitigations(tmp_path: Path) -> None:
    path = tmp_path / "environment.json"
    path.write_text(network(host()).model_dump_json(), encoding="utf-8")
    runs.load_files(str(path), None)
    result = runs.candidates()
    assert result["candidates"] == []
    assert "no_mitigations_loaded" in result
    assert "no_mitigations_loaded" in runs.recommendation()


@pytest.mark.usefixtures("flow_dir")
def test_summary_and_verification_name_the_plan() -> None:
    runs.load_files(*runs.example_files())
    plan = runs.make_plan(["sigred-ips"])["plan"]["plan_hash"]
    other = runs.make_plan(["bluekeep-ips"])["plan"]["plan_hash"]
    both = ", ".join(sorted([plan, other]))
    assert f"waiting for approval: {both}" in render_summary(runs.dashboard_data())
    runs.apply_approved(plan)
    summary = render_summary(runs.dashboard_data())
    assert f"Applied plan: {plan}" in summary
    assert "waiting for approval" not in summary
    assert f"rolled back: {other}" in summary
    with pytest.raises(runs.FlowError, match="already applied"):
        runs.apply_approved(other)
    assert runs.verify_applied().mitigation_ids == ["sigred-ips"]
    with pytest.raises(runs.FlowError, match="roll it back"):
        runs.make_plan(["tomcat-ips"])
    runs.rollback()
    assert {plan["plan_hash"]: plan["state"] for plan in runs.dashboard_data()["plans"]}[other] == "waiting"


@pytest.mark.usefixtures("flow_dir")
@pytest.mark.parametrize(
    ("claimed", "quote", "kept"),
    [
        ("local", "Web UI Privilege Escalation Vulnerability", False),
        ("local", "Windows Kernel Elevation of Privilege Vulnerability", True),
        ("local", "Sudo Heap Overflow Privilege Escalation", True),
        ("client", "OpenSSH Signal Handler Race", False),
        ("client", "The victim opens a crafted file", True),
    ],
)
def test_a_class_needs_words_that_say_so(claimed: str, quote: str, kept: bool, tmp_path: Path) -> None:
    path = tmp_path / "environment.json"
    path.write_text(network(host(findings=[rce(title=quote)])).model_dump_json(), encoding="utf-8")
    runs.load_files(str(path), None)
    item = {"cve": "CVE-2020-1350", "vulnerability_class": claimed, "class_evidence": quote}
    runs.save_normalized([item])
    saved = runs.environment_state()["vulnerabilities"]["CVE-2020-1350"]
    assert (saved.get("vulnerability_class") == claimed) is kept


@pytest.mark.parametrize(("quote", "kept"), [("must visit a malicious web page", True)])
def test_the_shared_check_leaves_the_wording_rule_to_the_flow(quote: str, kept: bool) -> None:
    profile = VulnerabilityProfile(cve="CVE-1", vulnerability_class="client", class_evidence=quote)
    assert bool(check_profile(profile, quote, "")[0].vulnerability_class) is kept


@pytest.mark.usefixtures("flow_dir")
def test_unmitigated_is_what_the_recommended_plan_leaves_open() -> None:
    runs.load_files(*runs.example_files())
    data = runs.dashboard_data()
    assert data["unmitigated"] == len(data["recommendation"]["left_exposed"])
    assert f"Known-exploited left open by what is recommended: {data['unmitigated']}" in render_summary(data)
    plan = runs.make_plan(["sigred-ips"])["plan"]["plan_hash"]
    runs.apply_approved(plan)
    after = runs.dashboard_data()
    assert after["recommendation"] is None
    assert after["unmitigated"] == after["funnel"]["kev_exposed"] > 0
    assert f"left open by the applied plan: {after['unmitigated']}" in render_summary(after)


@pytest.mark.usefixtures("flow_dir")
def test_unmitigated_counts_a_finding_that_went_unknown(tmp_path: Path) -> None:
    pairs = [rce("CVE-1", family="Windows : Microsoft Bulletins", title="KB1"), rce("CVE-2")]
    target = host(findings=pairs, processes=["rdp"])
    block = FlowMitigation(id="b", title="b", kind="acl_block", cve_ids=["CVE-2"])
    environment = network(target, rules=[FirewallRule(name="r", from_zone=["internet"])])
    advice = recommend(environment, [block])
    (tmp_path / "environment.json").write_text(environment.model_dump_json(), encoding="utf-8")
    (tmp_path / "mitigations.json").write_text(json.dumps([block.model_dump(mode="json")]), encoding="utf-8")
    runs.load_files(str(tmp_path / "environment.json"), str(tmp_path / "mitigations.json"))
    assert runs.dashboard_data()["unmitigated"] == len(advice.left_exposed)


def _signature_network(findings: list[Finding], signed: dict[int, bool], process: str) -> Environment:
    listeners = ["svc9", "gadgetd"]
    listeners += ["web", "system"]
    rules = [
        FirewallRule(
            name=f"r{port}",
            from_zone=["internet"],
            to_zone=["servers"],
            destination=["dc"],
            vulnerability_profile="strict" if has_signature else None,
        )
        for port, has_signature in signed.items()
    ]
    environment = network(host(findings=findings, processes=listeners), rules=rules)
    environment.devices[0].fw_type = "PaloAltoNGFW"
    environment.devices[0].threat_prevention = True
    environment.devices[0].vulnerability_profiles = {"strict": ["58691"]}
    environment.vulnerabilities["CVE-2020-1350"] = VulnerabilityProfile(cve="CVE-2020-1350", processes=[process])
    return environment


PATCH_CHECK = {"family": "Windows : Microsoft Bulletins", "title": "KB1", "remote_check": False}


@pytest.mark.parametrize(
    "processes",
    [
        pytest.param(["svchost.exe"], id="a-shared-host"),
        pytest.param(["System"], id="the-kernel-process"),
        pytest.param(["a", "b", "c", "d", "dns.exe"], id="a-list-copied-from-the-machine"),
    ],
)
def test_a_name_that_doesnt_point_at_the_software_ties_no_port(processes: list[str]) -> None:
    patch_check = rce(**PATCH_CHECK)
    listeners = ["dns.exe", "svchost.exe"]
    listeners.append("System")
    rules = [FirewallRule(name="r", from_zone=["internet"])]
    environment = network(host(findings=[patch_check], processes=listeners), rules=rules)
    environment.vulnerabilities["CVE-2020-1350"] = VulnerabilityProfile(cve="CVE-2020-1350", processes=processes)
    assert tag(environment).tag == "host_reachable"


def test_a_shared_host_doesnt_read_as_not_running() -> None:
    environment = network(host(findings=[rce(**PATCH_CHECK)], processes=["dns.exe"]))
    environment.vulnerabilities["CVE-2020-1350"] = VulnerabilityProfile(cve="CVE-2020-1350", processes=["svchost.exe"])
    assert tag(environment).tag == "host_reachable"


def test_applying_sends_the_change_to_the_mock_firewall_and_rollback_takes_it_back(flow_dir: Path) -> None:
    run = _start_demo()
    plan = runs.make_plan(["sigred-ips"])["plan"]["plan_hash"]
    runs.apply_approved(plan)
    receipt = runs.firewall_receipt()
    assert receipt is not None and receipt["devices"][0]["commit_job"] == "2"
    assert any(call["type"] == "commit" for call in receipt["devices"][0]["calls"])
    state = flow_dir / run / "mock-firewalls" / f"{receipt['devices'][0]['device']}.json"
    assert '<entry name="58691">' in json.loads(state.read_text(encoding="utf-8"))["versions"][-1]
    check = next(item for item in runs.verify_applied().checks if item.name == "mock_firewall_matches_the_model")
    assert check.passed
    held = json.loads(state.read_text(encoding="utf-8"))
    held["versions"][-1] = held["versions"][-1].replace('<entry name="58691">', '<entry name="1">')
    state.write_text(json.dumps(held), encoding="utf-8")
    result = runs.verify_applied()
    assert not result.passed
    runs.rollback()
    assert not state.parent.exists() and runs.firewall_receipt() is None
    assert runs.make_plan(["sigred-ips"])["plan"]["plan_hash"] == plan


@pytest.mark.usefixtures("flow_dir")
def test_a_plan_the_mock_firewall_refuses_applies_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    _start_demo()
    plan = runs.make_plan(["sigred-ips"])["plan"]["plan_hash"]
    before = runs.dashboard_data()["funnel"]

    def refused(*_args: Any) -> dict[str, Any]:
        raise mock.FirewallError("commit failed")

    monkeypatch.setattr(runs, "push_plan", refused)
    with pytest.raises(runs.FlowError, match="nothing was applied"):
        runs.apply_approved(plan)
    assert runs.applied_plan() is None and runs.firewall_receipt() is None
    assert runs.dashboard_data()["funnel"] == before


def _load_with_traffic(flow_dir: Path, *, flows: list[dict[str, Any]], traffic: list[dict[str, Any]]) -> None:
    raw = json.loads((EXAMPLES / "environment.json").read_text(encoding="utf-8"))
    raw["allowed_flows"] += flows
    raw["observed_traffic"] += traffic
    path = flow_dir / "with-traffic.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    runs.load_files(str(path), str(EXAMPLES / "mitigations.json"))


NIGHTLY_FLOW = {"name": "Nightly job", "source_zone": "dmz", "host": "dc-01"}
NIGHTLY = {**NIGHTLY_FLOW, "sessions": 48, "threat_ids": ["58691"]}


def test_watching_traffic_reports_what_a_mitigation_would_drop_and_holds_a_false_alarm(flow_dir: Path) -> None:
    _load_with_traffic(flow_dir, flows=[NIGHTLY_FLOW], traffic=[NIGHTLY])
    result = runs.watch_traffic(["sigred-ips"])
    assert result["mitigations"] == [
        {
            "mitigation_id": "sigred-ips",
            "status": "hold",
            "would_drop_needed": ["Nightly job"],
            "would_drop_unknown": [],
            "would_stop_attacks": 12,
        }
    ]
    assert any(item["name"] == "Nightly job" and item["kind"] == "needed" for item in result["traffic"])


def test_watching_traffic_refuses_an_unknown_mitigation(flow_dir: Path) -> None:
    _load_with_traffic(flow_dir, flows=[], traffic=[])
    with pytest.raises(runs.FlowError, match="unknown mitigations: nope"):
        runs.watch_traffic(["nope"])


def test_verify_advises_rollback_when_needed_traffic_starts_being_dropped(flow_dir: Path) -> None:
    _load_with_traffic(flow_dir, flows=[NIGHTLY_FLOW], traffic=[{**NIGHTLY, "only_after_change": True}])
    plan = runs.make_plan(["sigred-ips"])
    assert plan["plan"]["plan_hash"]
    runs.apply_approved(plan["plan"]["plan_hash"])
    result = runs.verify_applied()
    assert not result.passed and result.rollback_advised and result.needed_dropped == ["Nightly job"]
    assert result.attacks_stopped == 12 and "Nightly job" in result.rollback_reason


def test_verify_doesnt_advise_rollback_for_attacks_or_unknown_traffic(flow_dir: Path) -> None:
    _load_with_traffic(flow_dir, flows=[], traffic=[{**NIGHTLY, "only_after_change": True}])
    runs.apply_approved(runs.make_plan(["sigred-ips"])["plan"]["plan_hash"])
    result = runs.verify_applied()
    assert result.passed and not result.rollback_advised and result.attacks_stopped == 60


def test_the_log_reflects_the_firewalls_own_config_so_drift_shows_in_verify(flow_dir: Path) -> None:
    run = _start_demo()
    runs.apply_approved(runs.make_plan(["sigred-ips"])["plan"]["plan_hash"])
    receipt = runs.firewall_receipt()
    assert receipt is not None
    state = flow_dir / run / "mock-firewalls" / f"{receipt['devices'][0]['device']}.json"
    held = json.loads(state.read_text(encoding="utf-8"))
    held["versions"][-1] = held["versions"][-1].replace('<entry name="58691">', '<entry name="1">')
    state.write_text(json.dumps(held), encoding="utf-8")
    assert runs.verify_applied().attacks_stopped == 0


@pytest.mark.usefixtures("flow_dir")
@pytest.mark.parametrize("failure", [OSError("no bind"), ValueError("bad state"), KeyError("versions")])
def test_any_failure_sending_a_plan_applies_nothing(monkeypatch: pytest.MonkeyPatch, failure: Exception) -> None:
    _start_demo()
    plan = runs.make_plan(["sigred-ips"])["plan"]["plan_hash"]

    def broken(*_args: Any) -> dict[str, Any]:
        raise failure

    monkeypatch.setattr(runs, "push_plan", broken)
    with pytest.raises(runs.FlowError, match="nothing was applied"):
        runs.apply_approved(plan)
    assert runs.applied_plan() is None


@pytest.mark.parametrize("damage", ["{nope", "[1]", '{"devices":[{}]}', '{"mock":true}', None])
def test_a_damaged_firewall_record_fails_verify_and_doesnt_block_rollback(flow_dir: Path, damage: str | None) -> None:
    run = _start_demo()
    before = (flow_dir / run / "environment.json").read_bytes()
    runs.apply_approved(runs.make_plan(["sigred-ips"])["plan"]["plan_hash"])
    record = flow_dir / run / "firewall.json"
    if damage is None:
        record.unlink()
    else:
        record.write_text(damage, encoding="utf-8")
    assert not runs.verify_applied().passed
    assert runs.dashboard_data()["firewall"] is None
    runs.rollback()
    assert runs.applied_plan() is None and (flow_dir / run / "environment.json").read_bytes() == before


def test_rollback_restores_the_mock_firewall_and_says_so(flow_dir: Path) -> None:
    run = _start_demo()
    runs.apply_approved(runs.make_plan(["sigred-ips"])["plan"]["plan_hash"])
    runs.rollback()
    receipt = runs.firewall_rollback_receipt()
    assert receipt is not None and receipt["devices"][0]["restored"] is True
    assert receipt["devices"][0]["commit_job"] == "3"
    assert not (flow_dir / run / "mock-firewalls").exists()


@pytest.mark.usefixtures("flow_dir")
def test_a_machine_that_wont_let_the_mock_bind_doesnt_break_verify_or_rollback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _start_demo()
    runs.apply_approved(runs.make_plan(["sigred-ips"])["plan"]["plan_hash"])

    def refused(*_args: Any, **_kwargs: Any) -> None:
        raise PermissionError("bind")

    monkeypatch.setattr(mock._Server, "server_bind", refused)
    assert not runs.verify_applied().passed
    runs.rollback()
    assert runs.applied_plan() is None


def test_naming_a_shared_host_doesnt_read_as_the_software_not_running() -> None:
    environment = network(host(findings=[rce(**PATCH_CHECK)], processes=["svchost.exe"]))
    environment.vulnerabilities["CVE-2020-1350"] = VulnerabilityProfile(
        cve="CVE-2020-1350", processes=["svchost.exe", "termsrv.dll"]
    )
    assert tag(environment).tag == "host_reachable"


CSV_FIREWALL = """rule,from,to,dest,service,verdict
web-in,internet,dmz,203.0.113.7,443/tcp,accept
"""


def _firewall_from_csv() -> dict[str, Any]:
    return {
        "hostname": "web-in",
        "type": "PaloAltoNGFW",
        "zones": [],
        "virtual_router": {"routes": []},
        "security_rules": [
            {"name": "web-in", "from": ["internet"], "to": ["dmz"], "destination": ["addr"], "service": ["svc"],
             "action": "allow"}
        ],
        "address_objects": {"addr": {"ip_netmask": "203.0.113.7"}},
    }


@pytest.mark.usefixtures("flow_dir")
def _start_a_network(folder: Path) -> None:
    agentic.allow_source_folder(str(folder))
    scan = folder / "scan.json"
    scan.write_text((EXAMPLES / "environment.json").read_text(encoding="utf-8"), encoding="utf-8")
    agentic.save_source("scan", path=str(scan))


@pytest.mark.usefixtures("flow_dir")
def test_a_converted_source_must_come_from_the_text_that_was_read(tmp_path: Path) -> None:
    _start_a_network(tmp_path)
    source = tmp_path / "export.csv"
    source.write_text(CSV_FIREWALL, encoding="utf-8")
    assert "web-in" in agentic.read_source(str(source))["text"]
    saved = agentic.save_source("firewall", "edge-1", _firewall_from_csv())
    assert saved["checked"] > 0 and Path(saved["sources_dir"]).is_dir()
    invented = _firewall_from_csv()
    invented["security_rules"][0]["name"] = "invented-rule"
    with pytest.raises(runs.FlowError, match="invented-rule"):
        agentic.save_source("firewall", "edge-2", invented)


@pytest.mark.usefixtures("flow_dir")
def test_a_converted_source_in_the_wrong_shape_is_refused(tmp_path: Path) -> None:
    _start_a_network(tmp_path)
    with pytest.raises(runs.FlowError, match="expected shape"):
        agentic.save_source("firewall", "edge-1", {"hostname": "edge-1"})


@pytest.mark.usefixtures("flow_dir")
@pytest.mark.parametrize("name", ["credentials.json", "my-secret.txt", "server.key", "notes.md", "api_key.json"])
def test_reading_a_source_refuses_secrets_and_other_kinds_of_file(tmp_path: Path, name: str) -> None:
    agentic.allow_source_folder(str(tmp_path))
    file = tmp_path / name
    file.write_text("{}", encoding="utf-8")
    with pytest.raises(runs.FlowError, match=r"isn't|secret|looks|kind|read"):
        agentic.read_source(str(file))


@pytest.mark.usefixtures("flow_dir")
def test_reading_a_source_refuses_hidden_folders_and_links(tmp_path: Path) -> None:
    agentic.allow_source_folder(str(tmp_path))
    hidden = tmp_path / ".aws"
    hidden.mkdir()
    (hidden / "config.json").write_text("{}", encoding="utf-8")
    with pytest.raises(runs.FlowError, match="hidden"):
        agentic.read_source(str(hidden / "config.json"))
    link = tmp_path / "link.json"
    link.symlink_to(hidden / "config.json")
    with pytest.raises(runs.FlowError, match="link"):
        agentic.read_source(str(link))
    with pytest.raises(runs.FlowError, match="absolute"):
        agentic.read_source("relative.json")


@pytest.mark.usefixtures("flow_dir")
def test_a_converted_network_maps_and_is_marked_model_converted(tmp_path: Path) -> None:
    sources = EXAMPLES / "sources"
    _start_a_network(tmp_path)
    agentic.allow_source_folder(str(sources))
    for name in ("firewalls/pa-edge", "firewalls/pa-core", "routers/rtr-branch", "assets"):
        agentic.read_source(str(sources / f"{name}.json"))
    for name in ("pa-edge", "pa-core"):
        agentic.save_source("firewall", name, json.loads((sources / "firewalls" / f"{name}.json").read_text("utf-8")))
    agentic.save_source("router", "rtr-branch", json.loads((sources / "routers/rtr-branch.json").read_text("utf-8")))
    saved = agentic.save_source("assets", content=json.loads((sources / "assets.json").read_text("utf-8")))
    assert saved["still_needed"] == []
    for step in runs.COLLECT_STEPS:
        runs.collect(step, saved["sources_dir"])
    mapped = runs.map_routes(saved["sources_dir"])
    assert "firewall: pa-edge" in mapped["model_converted"]
    assert runs.dashboard_data()["model_converted"] == mapped["model_converted"]


def _load_unplaced(flow_dir: Path) -> None:
    placed = host("dark", zone=None, ips=[], findings=[rce()])
    rules = [FirewallRule(name="r", from_zone=["internet"], to_zone=["servers"])]
    path = flow_dir / "unplaced.json"
    path.write_text(network(placed, rules=rules).model_dump_json(), encoding="utf-8")
    runs.load_files(str(path), None)


def test_a_proposed_zone_that_opens_a_path_is_marked_as_the_models_guess(flow_dir: Path) -> None:
    _load_unplaced(flow_dir)
    before = runs.dashboard_data()["funnel"]["kev_exposed"]
    result = agentic.propose_zone("dark", "servers", "its gateway is in the servers range")
    assert result["placed_by"] == "model" and result["kev_exposed"] > before
    with pytest.raises(runs.FlowError, match="already in zone"):
        agentic.propose_zone("dark", "corp", "changed my mind")


def test_a_proposed_zone_that_would_clear_a_finding_is_refused(flow_dir: Path) -> None:
    _load_unplaced(flow_dir)
    with pytest.raises(runs.FlowError, match="would stop counting as open"):
        agentic.propose_zone("dark", "corp", "looks like an office machine")
    assert runs.environment_state()["hosts"][0]["zone"] is None


def test_a_proposal_needs_a_reason_a_real_zone_and_a_real_host(flow_dir: Path) -> None:
    _load_unplaced(flow_dir)
    with pytest.raises(runs.FlowError, match="what in the sources"):
        agentic.propose_zone("dark", "servers", " ")
    with pytest.raises(runs.FlowError, match="no zone"):
        agentic.propose_zone("dark", "mars", "because")
    with pytest.raises(runs.FlowError, match="no host"):
        agentic.propose_zone("nope", "servers", "because")


@pytest.mark.usefixtures("flow_dir")
def test_checking_a_path_answers_for_a_zone_the_scan_skips_and_changes_nothing() -> None:
    _start_demo()
    before = runs.dashboard_data()
    inside = agentic.check_path("corp", "dc-01")
    assert inside["open"] is True and inside["attacker_zone"] is False and inside["paths"]
    assert runs.dashboard_data() == before
    with pytest.raises(runs.FlowError, match="no zone"):
        agentic.check_path("mars", "dc-01")


@pytest.mark.usefixtures("flow_dir")
def test_trying_mitigations_lets_code_judge_the_set() -> None:
    _start_demo()
    recommended = [item["mitigation_id"] for item in runs.recommendation()["selected"]]
    same = agentic.try_mitigations(recommended)
    assert same["verdict"] == "stops the same as the recommendation" and same["reasons"] == []
    fewer = agentic.try_mitigations(recommended[:1])
    assert fewer["verdict"] == "stops less than the recommendation"
    held = agentic.try_mitigations(["spooler-disable"])
    assert held["verdict"] == "not usable as it is"
    assert any("held" in reason for reason in held["reasons"]) and any("breaks" in r for r in held["reasons"])
    with pytest.raises(runs.FlowError, match="unknown mitigations"):
        agentic.try_mitigations(["nope"])


def _reachable_host(**fields: Any) -> Environment:
    rules = [FirewallRule(name="r", from_zone=["internet"], to_zone=["servers"])]
    return network(host(**fields), rules=rules)


def test_a_host_the_rules_reach_is_exposed_and_one_they_dont_is_not() -> None:
    assert tag(_reachable_host(findings=[rce()])).exposed
    assert tag(network(host(findings=[rce()]), rules=[])).tag == "not_reachable"


@pytest.mark.parametrize(
    ("fields", "expected", "basis"),
    [
        pytest.param({"access_vector": "local"}, "local_only", "local_vector", id="local"),
        pytest.param({"vulnerability_class": "client"}, "not_reachable", "client_side", id="client"),
        pytest.param({"access_vector": "unknown"}, "unknown", "unknown_vector", id="unknown-vector"),
        pytest.param({"remote_check": True}, "reachable", "scanner_tested", id="scanner-reached-it"),
        pytest.param({"remote_check": False}, "host_reachable", "host_open", id="checked-from-inside"),
        pytest.param({"remote_check": False, "family": "Web Servers"}, "host_reachable", "host_open",
                     id="a-network-sounding-family-earns-nothing"),
    ],
)
def test_each_kind_of_finding_gets_its_verdict(fields: dict[str, Any], expected: str, basis: str) -> None:
    result = tag(_reachable_host(findings=[rce(**fields)]))
    assert (result.tag, result.basis) == (expected, basis)


def test_a_host_off_the_map_is_unknown_never_safe() -> None:
    result = tag(network(host(zone=None, findings=[rce()])))
    assert (result.tag, result.basis, result.exposed) == ("unknown", "not_placed", False)


@pytest.mark.parametrize(
    ("named", "running"),
    [("java", "java.exe"), ("tomcat", "tomcat9.exe"), ("sshd", "/usr/sbin/sshd -D"), ("nginx", "NGINX.EXE")],
)
def test_the_named_software_is_found_however_its_process_is_written(named: str, running: str) -> None:
    environment = _reachable_host(findings=[rce(**PATCH_CHECK)], processes=[running])
    environment.vulnerabilities["CVE-2020-1350"] = VulnerabilityProfile(cve="CVE-2020-1350", processes=[named])
    assert (tag(environment).tag, tag(environment).basis) == ("reachable", "software_running")


@pytest.mark.parametrize(
    ("processes", "services", "expected"),
    [
        pytest.param(["sshd"], {}, "not_seen_running", id="not-in-the-processes"),
        pytest.param(["sshd"], {"tomcat": "stopped"}, "not_seen_running", id="service-stopped"),
        pytest.param(["sshd"], {"other": "running"}, "host_reachable", id="service-list-doesnt-name-it"),
        pytest.param([], {}, "host_reachable", id="nothing-is-known"),
        pytest.param(["tomcat"], {}, "reachable", id="running"),
        pytest.param(["sshd"], {"tomcat": "running"}, "reachable", id="service-running"),
    ],
)
def test_software_not_seen_running_stays_exposed(
    processes: list[str], services: dict[str, str], expected: str
) -> None:
    environment = _reachable_host(findings=[rce(**PATCH_CHECK)], processes=processes, services=services)
    environment.vulnerabilities["CVE-2020-1350"] = VulnerabilityProfile(cve="CVE-2020-1350", processes=["tomcat"])
    result = tag(environment)
    assert result.tag == expected and result.exposed


def _signed_network(findings: list[Finding], *, processes: list[str] | None = None) -> Environment:
    rule = FirewallRule(name="r", from_zone=["internet"], to_zone=["servers"], vulnerability_profile="strict")
    environment = network(host(findings=findings, processes=processes or []), rules=[rule])
    environment.devices[0].vulnerability_profiles = {"strict": ["58691"]}
    return environment


def test_a_signature_counts_where_the_scanner_reached_the_service() -> None:
    assert tag(_signed_network([rce()]), mitigations=(IPS,)).protected_by == ["ips"]
    assert not tag(_signed_network([rce()]), mitigations=(IPS,)).exposed


def test_a_signature_counts_on_a_finding_tenable_only_read_the_patch_level_of() -> None:
    result = tag(_signed_network([rce(**PATCH_CHECK)]), mitigations=(IPS,))
    assert result.tag == "host_reachable" and result.protected_by == ["ips"] and not result.exposed


def test_a_plan_puts_a_signature_on_the_rules_to_a_patch_level_finding() -> None:
    candidate = match_mitigations(_reachable_host(findings=[rce(**PATCH_CHECK)]), [IPS])[0]
    assert candidate.status == "proceed" and candidate.protects == ["CVE-2020-1350 on dc"]
    assert candidate.changes[0].kind == "block_threats" and candidate.changes[0].rules


@pytest.mark.parametrize(
    ("running", "named", "expected"),
    [("dns.exe", "dns.exe", "reachable"), ("x.exe", "dns.exe", "not_seen_running")],
)
def test_a_signature_counts_whichever_way_the_finding_is_exposed(running: str, named: str, expected: str) -> None:
    environment = _signed_network([rce(**PATCH_CHECK)], processes=[running])
    environment.vulnerabilities["CVE-2020-1350"] = VulnerabilityProfile(cve="CVE-2020-1350", processes=[named])
    result = tag(environment, mitigations=(IPS,))
    assert result.tag == expected and result.protected_by == ["ips"] and not result.exposed


def test_a_medium_known_exploited_finding_isnt_on_the_known_exploited_step() -> None:
    local = rce("LOCAL", severity="high", vulnerability_class="local")
    environment = network(host(findings=[rce("MEDIUM", severity="medium"), rce("HIGH", severity="high"), local]))
    assert funnel(tag_cves(environment)).known_exposed == 1
    assert recommend(environment, []).left_exposed == ["HIGH on dc"]


@pytest.mark.usefixtures("flow_dir")
def test_an_applied_plan_counts_a_high_known_exploited_finding_it_left_open(tmp_path: Path) -> None:
    environment = network(host(findings=[rce(severity="high"), rce("CVE-2", severity="high")]))
    (tmp_path / "environment.json").write_text(environment.model_dump_json(), encoding="utf-8")
    (tmp_path / "mitigations.json").write_text(json.dumps([IPS.model_dump(mode="json")]), encoding="utf-8")
    runs.load_files(str(tmp_path / "environment.json"), str(tmp_path / "mitigations.json"))
    runs.apply_approved(runs.make_plan(["ips"])["plan"]["plan_hash"])
    assert runs.dashboard_data()["unmitigated"] == 1


@pytest.mark.usefixtures("flow_dir")
def test_trying_part_of_the_plan_stops_less_when_only_high_findings_differ(tmp_path: Path) -> None:
    environment = network(host(findings=[rce(), rce("CVE-2", severity="high")]))
    other = IPS.model_copy(update={"id": "other", "cve_ids": ["CVE-2"], "threat_ids": ["2"]})
    (tmp_path / "environment.json").write_text(environment.model_dump_json(), encoding="utf-8")
    mitigations = [IPS.model_dump(mode="json"), other.model_dump(mode="json")]
    (tmp_path / "mitigations.json").write_text(json.dumps(mitigations), encoding="utf-8")
    runs.load_files(str(tmp_path / "environment.json"), str(tmp_path / "mitigations.json"))
    tried = agentic.try_mitigations(["ips"])
    assert tried["verdict"] == "stops less than the recommendation" and tried["known_exploited_left"] == 1


@pytest.mark.usefixtures("flow_dir")
def test_trying_a_set_that_leaves_other_findings_open_stops_less(tmp_path: Path) -> None:
    environment = network(host(findings=[rce(), rce("CVE-2", kev=False), rce("CVE-3", kev=False)]))
    close = FlowMitigation(id="close", title="close", kind="acl_block", cve_ids=["CVE-2020-1350"])
    (tmp_path / "environment.json").write_text(environment.model_dump_json(), encoding="utf-8")
    mitigations = [IPS.model_dump(mode="json"), close.model_dump(mode="json")]
    (tmp_path / "mitigations.json").write_text(json.dumps(mitigations), encoding="utf-8")
    runs.load_files(str(tmp_path / "environment.json"), str(tmp_path / "mitigations.json"))
    assert agentic.try_mitigations(["close"])["verdict"] == "stops the same as the recommendation"
    assert agentic.try_mitigations(["ips"])["verdict"] == "stops less than the recommendation"


def test_a_patch_check_beside_a_tested_finding_doesnt_undo_the_signature() -> None:
    assert not tag(_signed_network([rce(), rce(**PATCH_CHECK)]), mitigations=(IPS,)).exposed


def test_a_signature_on_only_one_of_two_paths_doesnt_count() -> None:
    signed = FirewallRule(name="signed", from_zone=["internet"], to_zone=["servers"], vulnerability_profile="strict")
    environment = network(host(findings=[rce()]), rules=[signed])
    environment.devices[0].vulnerability_profiles = {"strict": ["58691"]}
    other = Device(id="fw2", zones=["internet", "servers"], rules=[FirewallRule(name="open")])
    environment.devices.append(other)
    assert tag(environment, mitigations=(IPS,)).exposed


def test_a_host_control_counts_wherever_it_applies() -> None:
    environment = _reachable_host(findings=[rce()], host_controls={"setting": ["CVE-2020-1350"]})
    assert tag(environment).protected_by == ["host_control"]


def test_funnel_counts_pairs_at_each_stage() -> None:
    findings = [
        rce("CVE-1"),
        rce("CVE-2"),
        rce("CVE-3", access_vector="local"),
        rce("CVE-4", kev=False),
        rce("CVE-5", severity="high"),
    ]
    result = funnel(tag_cves(_reachable_host(findings=findings)))
    assert (result.findings, result.remote, result.remote_critical, result.remote_critical_kev) == (5, 4, 3, 2)
    assert (result.kev_reachable, result.kev_exposed) == (2, 2)


def test_an_acl_closes_the_host_and_breaks_allowed_traffic_from_that_zone() -> None:
    flow = AllowedFlow(name="public", source_zone="internet", host="dc")
    environment = _reachable_host(findings=[rce()])
    close = FlowMitigation(id="close", title="Close", kind="acl_block", cve_ids=["CVE-2020-1350"])
    quiet = match_mitigations(environment, [close])[0]
    assert quiet.status == "proceed" and quiet.protects == ["CVE-2020-1350 on dc"]
    environment.allowed_flows.append(flow)
    held = match_mitigations(environment, [close])[0]
    assert held.status == "hold" and held.breaks_flows == ["public"]


def test_a_signature_that_leaves_a_host_it_cant_reach_open_is_held() -> None:
    environment = network(host(), host("other", zone="corp"))
    rule = FirewallRule(name="open", from_zone=["internet"], to_zone=["corp"])
    environment.devices.append(Device(id="fw2", zones=["internet", "corp"], threat_prevention=False, rules=[rule]))
    held = match_mitigations(environment, [IPS])[0]
    assert held.status == "hold" and "leaves 1 of 2" in " ".join(held.hold_reasons)


def test_a_signature_with_no_capable_device_on_the_path_is_held() -> None:
    environment = _reachable_host(findings=[rce(**PATCH_CHECK)])
    environment.devices[0].threat_prevention = False
    held = match_mitigations(environment, [IPS])[0]
    assert held.status == "hold" and not held.protects and "device is on the path" in held.hold_reasons[0]


def test_a_deny_limited_to_some_services_doesnt_close_a_host() -> None:
    export = {
        "hostname": "fw",
        "type": "PaloAltoNGFW",
        "zones": [],
        "virtual_router": {"routes": []},
        "security_rules": [
            {"name": "no-smb", "action": "deny", "service": ["svc-445"]},
            {"name": "no-app", "action": "deny", "application": ["ms-rdp"]},
            {"name": "shut", "action": "deny"},
            {"name": "web", "action": "allow", "service": ["svc-443"]},
        ],
    }
    assert [rule.name for rule in source_files._device_from_firewall(export).rules] == ["shut", "web"]


@pytest.mark.parametrize("address", [{"ip_range": "10.0.0.1-10.0.0.9"}, {"fqdn": "web.example.com"}])
def test_a_rule_on_an_address_the_model_cant_match_stops_the_run(address: dict[str, str]) -> None:
    export = {
        "hostname": "fw",
        "type": "PaloAltoNGFW",
        "zones": [],
        "virtual_router": {"routes": []},
        "address_objects": {"web": address},
        "security_rules": [{"name": "open", "destination": ["web"]}],
    }
    with pytest.raises(source_files.SourceError, match="address object web"):
        source_files._device_from_firewall(export)


@pytest.mark.usefixtures("flow_dir")
def test_the_scan_lists_reachable_hosts_and_says_when_a_missing_row_means_closed() -> None:
    _start_demo()
    result = runs.reachability()
    reachable = {item["host"] for item in result["open"]}
    assert "web-01" in reachable and result["complete"] is True and result["hosts_checked"] == 7
    assert result["hosts_reachable"] == len(reachable)
    assert all("port" not in item for item in result["open"])


def test_a_cut_scan_doesnt_let_a_missing_row_read_as_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PORYGON_FLOW_DIR", str(tmp_path))
    hosts = [host(f"h{index:03}", ips=[f"10.0.{index // 250}.{index % 250 + 1}"]) for index in range(300)]
    rules = [FirewallRule(name="r", from_zone=["internet"])]
    path = tmp_path / "environment.json"
    path.write_text(network(*hosts, rules=rules).model_dump_json(), encoding="utf-8")
    result = runs.reachability(runs.load_files(str(path), None))
    assert result["complete"] is False and result["open_listed"] < result["hosts_reachable"]
    assert len(json.dumps(result, separators=(",", ":"))) <= 45_000


def test_tenable_process_names_become_what_the_host_runs_with_no_port_kept() -> None:
    hosts = environment_from_tenable(
        [{"id": "a1", "network": {"hostnames": ["web"], "ipv4s": ["10.0.0.5"]}}],
        [
            {
                "asset": {"uuid": "a1", "hostname": "web"},
                "plugin": {"id": 34252},
                "output": json.dumps({"listening": [{"port": 53, "plugin_output": "process 'dns.exe'"}]}),
            },
            {
                "asset": {"uuid": "a1", "hostname": "web"},
                "plugin": {"id": 1000, "cve": ["CVE-2020-1350"], "family": "DNS", "name": "SIGRed"},
                "port": {"port": 53, "protocol": "TCP"},
                "severity": "critical",
                "state": "OPEN",
            },
        ],
        {},
        Environment(zones=[Zone(id="internet", kind="internet")]),
    ).hosts
    dumped = hosts[0].model_dump()
    assert dumped["processes"] == ["dns.exe"] and "port" not in dumped["findings"][0] and "listeners" not in dumped


def test_a_signature_has_to_be_on_every_rule_letting_traffic_through() -> None:
    rules = [
        FirewallRule(name="one", from_zone=["internet"], vulnerability_profile="signed"),
        FirewallRule(name="two", from_zone=["internet"]),
    ]
    environment = network(host(), rules=rules)
    environment.devices[0].threat_prevention = True
    environment.devices[0].vulnerability_profiles = {"signed": list(IPS.threat_ids)}
    assert tag(environment, mitigations=(IPS,)).exposed
    environment.devices[0].rules[1].vulnerability_profile = "signed"
    assert not tag(environment, mitigations=(IPS,)).exposed


def test_a_deny_above_the_second_rule_ends_what_a_signature_has_to_cover() -> None:
    rules = [
        FirewallRule(name="one", from_zone=["internet"], vulnerability_profile="signed"),
        FirewallRule(name="closed", from_zone=["internet"], action="deny"),
        FirewallRule(name="never-used", from_zone=["internet"]),
    ]
    environment = network(host(), rules=rules)
    environment.devices[0].threat_prevention = True
    environment.devices[0].vulnerability_profiles = {"signed": list(IPS.threat_ids)}
    assert not tag(environment, mitigations=(IPS,)).exposed


def test_a_plan_puts_the_signature_on_every_rule_letting_traffic_through() -> None:
    environment, mitigations = demo()
    plan = plan_change(environment, mitigations, ["sigred-ips"])
    rules = plan.impact[0].rules
    assert len(rules) > 1, "dc-01 is reached through more than one rule, so one signature wouldn't be enough"


def test_in_a_model_converted_run_no_path_is_unknown_never_closed() -> None:
    environment = network(host(), rules=[])
    assert tag(environment).tag == "not_reachable"
    environment.model_converted = ["firewall: edge"]
    result = tag(environment)
    assert (result.tag, result.basis) == ("unknown", "model_converted")
    assert not compute_reachability(environment)[0].settled


def test_a_converted_rule_that_flips_allow_to_deny_cant_clear_a_host() -> None:
    rules = [FirewallRule(name="flipped", from_zone=["internet"], action="deny")]
    environment = network(host(), rules=rules)
    environment.model_converted = ["firewall: edge"]
    assert tag(environment).tag == "unknown"


@pytest.mark.parametrize("field", ["source-user", "category", "schedule", "source-hip", "an-unknown-field"])
def test_a_deny_limited_by_anything_else_doesnt_close_a_host(field: str) -> None:
    assert source_files._closes_only_some_traffic({"name": "r", "action": "deny", field: ["bob"]})


def test_a_plain_deny_closes_the_host() -> None:
    plain = {"name": "r", "action": "deny", "from": ["any"], "to": ["any"], "destination": ["any"], "service": ["any"]}
    assert not source_files._closes_only_some_traffic(plain)


def test_a_mitigation_on_a_host_a_model_placed_is_held() -> None:
    placed = host(placed_by="model", findings=[rce()])
    block = FlowMitigation(id="block", title="Block", kind="acl_block", cve_ids=["CVE-2020-1350"])
    held = match_mitigations(network(placed), [block])[0]
    assert held.status == "hold" and any("guessed" in reason for reason in held.hold_reasons)


def test_checking_a_path_to_a_host_with_no_address_says_it_cant_tell(flow_dir: Path) -> None:
    path = flow_dir / "no-address.json"
    rules = [FirewallRule(name="r", from_zone=["internet"], to_zone=["servers"], destination=["10.0.0.0/8"])]
    path.write_text(network(host(ips=[], findings=[rce()]), rules=rules).model_dump_json(), encoding="utf-8")
    runs.load_files(str(path), None)
    result = agentic.check_path("internet", "dc")
    assert result["open"] is None and "no_address" in result["why"]


@pytest.mark.usefixtures("flow_dir")
def test_a_source_outside_an_allowed_folder_is_refused(tmp_path: Path) -> None:
    source = tmp_path / "export.csv"
    source.write_text(CSV_FIREWALL, encoding="utf-8")
    with pytest.raises(runs.FlowError, match="a person allowed"):
        agentic.read_source(str(source))
    agentic.allow_source_folder(str(tmp_path))
    assert "web-in" in agentic.read_source(str(source))["text"]


@pytest.mark.usefixtures("flow_dir")
def test_a_new_scan_starts_a_new_network(tmp_path: Path) -> None:
    with pytest.raises(runs.FlowError, match="save the scan first"):
        agentic.save_source("firewall", "edge-1", _firewall_from_csv())
    _start_a_network(tmp_path)
    source = tmp_path / "export.csv"
    source.write_text(CSV_FIREWALL, encoding="utf-8")
    agentic.read_source(str(source))
    saved = agentic.save_source("firewall", "edge-1", _firewall_from_csv())
    _start_a_network(tmp_path)
    assert not list(Path(saved["sources_dir"]).rglob("edge-1*"))
    with pytest.raises(runs.FlowError, match="read it again"):
        agentic.save_source("firewall", "edge-1", _firewall_from_csv())


@pytest.mark.parametrize(
    ("name", "threats", "expected"),
    [
        pytest.param("payroll", [], "needed", id="the-flow-itself"),
        pytest.param("payroll", ["1"], "needed", id="a-false-alarm-on-the-flow"),
        pytest.param("other", ["1"], "unknown", id="another-name-on-a-needed-path"),
        pytest.param("other", [], "unknown", id="another-name-no-signature"),
    ],
)
def test_traffic_on_a_needed_path_needs_the_name_to_count(name: str, threats: list[str], expected: str) -> None:
    flow = AllowedFlow(name="payroll", source_zone="internet", host="dc")
    item = ObservedTraffic(name=name, source_zone="internet", host="dc", threat_ids=threats)
    assert engine.traffic_kind(network(host(), flows=[flow]), item) == expected


def test_traffic_tripping_a_signature_with_no_flow_on_that_path_is_an_attack() -> None:
    item = ObservedTraffic(name="x", source_zone="internet", host="dc", threat_ids=["1"])
    assert engine.traffic_kind(network(host()), item) == "attack"


def test_the_log_shows_after_change_sessions_when_any_firewall_changed(tmp_path: Path) -> None:
    environment, _ = demo()
    environment.observed_traffic = [
        ObservedTraffic(name="later", source_zone="internet", host="web-01", only_after_change=True)
    ]
    mock.start_firewalls(tmp_path, environment)
    assert mock.read_traffic(tmp_path) == []
    state = json.loads((tmp_path / "pa-edge.json").read_text(encoding="utf-8"))
    state["versions"].append(state["versions"][-1])
    (tmp_path / "pa-edge.json").write_text(json.dumps(state), encoding="utf-8")
    assert [item.name for item, _ in mock.read_traffic(tmp_path)] == ["later"]


def test_with_no_firewall_to_read_the_traffic_comes_from_the_model_and_says_so(flow_dir: Path) -> None:
    raw = json.loads((EXAMPLES / "environment.json").read_text(encoding="utf-8"))
    raw["observed_traffic"] = [{**NIGHTLY}]
    raw["allowed_flows"] += [NIGHTLY_FLOW]
    for device in raw["devices"]:
        device["fw_type"] = "other"
    path = flow_dir / "no-pan-os.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    runs.load_files(str(path), str(EXAMPLES / "mitigations.json"))
    watched = runs.watch_traffic()
    assert "no PAN-OS firewall" in watched["read_from"] and watched["sessions_read"] == NIGHTLY["sessions"]


def test_a_person_allows_a_source_folder_from_the_command_line(flow_dir: Path, tmp_path: Path) -> None:
    source = tmp_path / "export.csv"
    source.write_text(CSV_FIREWALL, encoding="utf-8")
    assert main(["flow", "allow-source", str(tmp_path)]) == 0
    assert "web-in" in agentic.read_source(str(source))["text"]
    assert not any("allow" in name for name in _flow_tool_names())


def _flow_tool_names() -> list[str]:
    return [tool.name for tool in asyncio.run(mcp_server.server.list_tools())]


def test_a_signature_in_a_model_converted_run_earns_nothing() -> None:
    environment = _signed_network([rce()])
    assert not tag(environment, mitigations=(IPS,)).exposed
    environment.model_converted = ["firewall: edge"]
    result = tag(environment, mitigations=(IPS,))
    assert result.exposed and result.protected_by == []
    held = match_mitigations(environment, [IPS])[0]
    assert held.status == "hold" and any("A model converted" in reason for reason in held.hold_reasons)


def test_needed_traffic_is_at_risk_when_any_rule_it_may_use_gets_the_signature() -> None:
    rules = [
        FirewallRule(name="signed", from_zone=["internet"], vulnerability_profile="strict"),
        FirewallRule(name="plain", from_zone=["internet"]),
    ]
    flow = AllowedFlow(name="payroll", source_zone="internet", host="dc")
    environment = network(host(), rules=rules, flows=[flow])
    environment.devices[0].vulnerability_profiles = {"strict": ["9"]}
    needed = ObservedTraffic(name="payroll", source_zone="internet", host="dc", threat_ids=["9"])
    assert engine.traffic_action(environment, needed) == "reset-both"


def test_an_attack_only_counts_as_stopped_when_every_rule_would_stop_it() -> None:
    rules = [
        FirewallRule(name="signed", from_zone=["internet"], vulnerability_profile="strict"),
        FirewallRule(name="plain", from_zone=["internet"]),
    ]
    environment = network(host(), rules=rules)
    environment.devices[0].vulnerability_profiles = {"strict": ["9"]}
    attack = ObservedTraffic(name="exploit", source_zone="internet", host="dc", threat_ids=["9"])
    assert engine.traffic_action(environment, attack) == "allow"
    environment.devices[0].rules[1].vulnerability_profile = "strict"
    assert engine.traffic_action(environment, attack) == "reset-both"


def test_after_change_sessions_show_when_only_a_device_the_mock_cant_speak_to_changed(tmp_path: Path) -> None:
    before, _ = demo()
    before.devices[-1].fw_type = "CiscoASA"
    before.observed_traffic = [
        ObservedTraffic(name="later", source_zone="internet", host="web-01", only_after_change=True)
    ]
    after = before.model_copy(deep=True)
    after.devices[-1].rules = after.devices[-1].rules[:-1]
    receipt = mock.push_plan(tmp_path, before, after)
    assert receipt["devices"] == [] and receipt["not_sent"]
    assert [item.name for item, _ in mock.read_traffic(tmp_path)] == ["later"]
    mock.undo_plan(tmp_path, receipt)
    assert mock.read_traffic(tmp_path) == []


def test_checking_a_path_from_a_zone_no_device_joins_doesnt_read_as_closed(flow_dir: Path) -> None:
    environment = network(host(), rules=[])
    environment.devices[0].zones = ["internet", "servers"]
    path = flow_dir / "unjoined.json"
    path.write_text(environment.model_dump_json(), encoding="utf-8")
    runs.load_files(str(path), None)
    assert agentic.check_path("corp", "dc")["open"] is None
    assert agentic.check_path("internet", "dc")["open"] is False


def test_a_verify_with_no_firewall_log_doesnt_claim_one(flow_dir: Path) -> None:
    raw = json.loads((EXAMPLES / "environment.json").read_text(encoding="utf-8"))
    raw["observed_traffic"] = [{"name": "benign", "source_zone": "dmz", "host": "dc-01", "sessions": 3}]
    for device in raw["devices"]:
        device["fw_type"] = "CiscoASA"
    path = flow_dir / "asa.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    runs.load_files(str(path), str(EXAMPLES / "mitigations.json"))
    runs.apply_approved(runs.make_plan(["winverifytrust-registry"])["plan"]["plan_hash"])
    check = next(item for item in runs.verify_applied().checks if "firewall" in item.name)
    assert "With no firewall log" in check.detail


def _payroll_network(*rules: FirewallRule) -> Environment:
    flow = AllowedFlow(name="payroll", source_zone="internet", host="dc")
    environment = network(host(), rules=list(rules), flows=[flow])
    environment.devices[0].vulnerability_profiles = {"strict": ["58691"]}
    environment.observed_traffic = [
        ObservedTraffic(name="payroll", source_zone="internet", host="dc", threat_ids=["58691"])
    ]
    return environment


SIGNED = FirewallRule(name="signed", from_zone=["internet"], vulnerability_profile="strict")
PLAIN = FirewallRule(name="plain", from_zone=["internet"])


def test_a_signature_reaching_another_rule_is_new_risk_for_needed_traffic() -> None:
    before = _payroll_network(SIGNED, PLAIN)
    after = _payroll_network(SIGNED, PLAIN.model_copy(update={"vulnerability_profile": "strict"}))
    dropped = engine.traffic_dropped(before, after, before.observed_traffic)["needed"]
    assert [item.name for item in dropped] == ["payroll"]
    assert engine.traffic_dropped(before, before, before.observed_traffic)["needed"] == []


def test_a_mitigation_adding_a_signature_to_a_rule_needed_traffic_may_use_is_held() -> None:
    held = match_mitigations(_payroll_network(SIGNED, PLAIN), [IPS])[0]
    assert held.status == "hold" and any("payroll" in reason for reason in held.hold_reasons)


def test_a_new_deny_over_traffic_already_at_risk_is_reported() -> None:
    before = _payroll_network(SIGNED, PLAIN)
    after = _payroll_network(FirewallRule(name="closed", from_zone=["internet"], action="deny"), SIGNED, PLAIN)
    assert engine.traffic_action(before, before.observed_traffic[0]) == "reset-both"
    dropped = engine.traffic_dropped(before, after, before.observed_traffic)["needed"]
    assert [item.name for item in dropped] == ["payroll"]


def test_verify_catches_needed_traffic_at_more_risk_than_before(flow_dir: Path) -> None:
    environment = _payroll_network(SIGNED, PLAIN)
    path, mitigations = flow_dir / "payroll.json", flow_dir / "payroll-mitigations.json"
    path.write_text(environment.model_dump_json(), encoding="utf-8")
    mitigations.write_text(json.dumps([IPS.model_dump(mode="json")]), encoding="utf-8")
    runs.load_files(str(path), str(mitigations))
    assert [item["would_drop_needed"] for item in runs.watch_traffic()["mitigations"]] == [["payroll"]]
    runs.apply_approved(runs.make_plan(["ips"], accept_holds=True)["plan"]["plan_hash"])
    assert runs.verify_applied().needed_dropped == ["payroll"]


def test_a_converted_run_doesnt_claim_attacks_a_signature_would_stop(flow_dir: Path) -> None:
    environment = _signed_network([rce()])
    environment.devices[0].rules[0].vulnerability_profile = None
    environment.model_converted = ["firewall: edge"]
    environment.observed_traffic = [
        ObservedTraffic(name="exploit", source_zone="internet", host="dc", threat_ids=["58691"], sessions=7)
    ]
    path, mitigations = flow_dir / "converted.json", flow_dir / "converted-mitigations.json"
    path.write_text(environment.model_dump_json(), encoding="utf-8")
    mitigations.write_text(json.dumps([IPS.model_dump(mode="json")]), encoding="utf-8")
    runs.load_files(str(path), str(mitigations))
    assert runs.watch_traffic()["mitigations"][0]["would_stop_attacks"] == 0


def test_an_attack_already_stopped_doesnt_count_as_newly_stopped() -> None:
    rule = FirewallRule(name="signed", from_zone=["internet"], vulnerability_profile="strict")
    before = network(host(), rules=[rule])
    before.devices[0].vulnerability_profiles = {"strict": ["58691"]}
    attack = ObservedTraffic(name="exploit", source_zone="internet", host="dc", threat_ids=["58691"], sessions=7)
    after = network(host(), rules=[FirewallRule(name="closed", from_zone=["internet"], action="deny"), rule])
    after.devices[0].vulnerability_profiles = {"strict": ["58691"]}
    assert engine.traffic_action(before, attack) == "reset-both"
    assert engine.traffic_dropped(before, after, [attack])["attack"] == []


def test_the_funnel_narrows_step_by_step_and_each_step_means_what_it_says() -> None:
    environment = network(
        host(
            findings=[
                rce("CVE-2099-0001"),
                rce("CVE-2099-0002", remote_check=False, title="KB1"),
                rce("CVE-2099-0003", vulnerability_class="client"),
                rce("CVE-2099-0004", access_vector="local"),
                rce("CVE-2099-0005", severity="medium"),
            ]
        ),
    )
    result = funnel(tag_cves(environment))
    assert (result.findings, result.high_critical, result.remotely_exploitable) == (5, 4, 2)
    assert (result.exposed, result.reachable, result.cant_judge) == (2, 1, 0)


def test_findings_the_data_cant_judge_are_named_not_counted_as_exposed() -> None:
    result = funnel(tag_cves(network(host(zone=None, findings=[rce()]))))
    assert (result.remotely_exploitable, result.exposed, result.cant_judge) == (1, 0, 1)


def test_the_summary_names_what_stays_exposed_and_says_when_a_plan_is_applied(flow_dir: Path) -> None:
    _start_demo()
    runs.apply_approved(runs.make_plan(["sigred-ips"])["plan"]["plan_hash"])
    summary = render_summary(runs.dashboard_data())
    assert "with the plan in place" in summary
    assert "Critical known-exploited still exposed: " in summary and "CVE-2019-0708 on dc-01" in summary
    assert "CVE-2020-1350 on dc-01" not in summary.split("still exposed: ")[1].split("\n")[0]


def test_exposed_and_known_exploited_is_one_step_of_the_funnel() -> None:
    critical = rce("CVE-2099-0001")
    high = rce("CVE-2099-0002", severity="high")
    plain = rce("CVE-2099-0003", kev=False)
    unconfirmed = rce("CVE-2099-0004", remote_check=False, title="KB1")
    result = funnel(tag_cves(network(host(findings=[critical, high, plain, unconfirmed]))))
    assert (result.remotely_exploitable, result.known_exposed, result.exposed) == (4, 3, 4)


def test_the_funnel_page_and_summary_show_the_combined_step(flow_dir: Path) -> None:
    _start_demo()
    data = runs.dashboard_data()
    now = data["funnel"]
    expected = f"Exposed and known exploited: {now['known_exposed']}  Unmitigated: {data['unmitigated']}"
    assert expected in render_summary(data)
    page = render_dashboard(data)
    assert '"Exposed and known exploited", now.known_exposed' in page
    assert '["Reachable"' not in page.split("function renderFunnel")[1].split("];")[0]


def test_the_recommendation_leaves_out_what_stops_no_known_exploited_finding() -> None:
    other = rce("CVE-2099-0002", kev=False)
    environment = network(host(findings=[rce(), other]))
    known = FlowMitigation(id="known", title="K", kind="host_setting", setting="k", cve_ids=["CVE-2020-1350"])
    plain = FlowMitigation(id="plain", title="P", kind="host_setting", setting="p", cve_ids=["CVE-2099-0002"])
    advice = recommend(environment, [known, plain])
    assert [item.mitigation_id for item in advice.selected] == ["known"]
    assert "no known-exploited finding" in advice.not_selected["plain"]
