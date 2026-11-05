"""Map and scan edge cases no other test reached: a run id with no run behind it, a route or address that doesn't parse,
and a routing plugin with a gateway that isn't an address. Each must give a reason or an unknown, never a guess."""

from __future__ import annotations

from pathlib import Path

from porygon_mitigator.flow.engine import compute_reachability
from porygon_mitigator.flow.models import Environment, FirewallRule, Route
from porygon_mitigator.flow.tenable import environment_from_tenable
from porygon_mitigator.flow.topology import place_hosts

from .test_flow import _start_demo, _tool, flow_dir, host, network

__all__ = ["flow_dir"]  # the fixture, shared with test_flow


def test_a_scan_of_a_run_that_isnt_there_says_so(flow_dir: Path) -> None:
    """An agent can pass a stale or mistyped run id: that's an error to report, never another run's scan."""
    _start_demo()
    assert "no such run" in _tool("flow_reachability", {"run_id": "0123456789abcdef"})["error"]
    assert "not a run id" in _tool("flow_reachability", {"run_id": "latest-run"})["error"]
    assert _tool("flow_reachability", {})["hosts_reachable"] > 0


def test_a_route_that_isnt_a_cidr_is_refused_not_guessed(flow_dir: Path, tmp_path: Path) -> None:
    environment = network(host(zone=None))
    environment.devices[0].routes = [Route(destination="corp-net", zone="servers")]
    assert place_hosts(environment).hosts[0].zone is None  # placing skips it rather than failing
    file = tmp_path / "environment.json"
    file.write_text(environment.model_dump_json(), encoding="utf-8")
    error = _tool("flow_load_environment", {"environment_file": str(file)})["error"]
    assert "route destination 'corp-net' isn't a CIDR" in error


def test_a_host_whose_address_doesnt_parse_is_never_settled() -> None:
    """A typo in an address can't be placed by range or matched by a CIDR rule, so the scan can't call it safe."""
    rules = [FirewallRule(name="lan", from_zone=["internet"], destination=["10.0.0.0/24"])]
    for zone in (None, "servers"):
        environment = network(host(zone=zone, ips=["10.0.0.300"]), rules=rules)
        environment.zones[1].cidrs = ["10.0.0.0/24"]
        placed = place_hosts(environment)
        assert placed.hosts[0].zone == zone
        assert [(item.reachable, item.settled) for item in compute_reachability(placed)] == [(False, False)]


def test_tenable_routes_skip_a_gateway_that_isnt_an_address() -> None:
    asset = {"id": "uuid-9", "network": {"hostnames": ["gw"], "ipv4s": ["10.0.0.9"]}}

    def gateway(output: str) -> str | None:
        row = {"asset": {"uuid": "uuid-9"}, "plugin": {"id": 179200}, "output": output}
        return environment_from_tenable([asset], [row], {}, Environment()).hosts[0].gateway

    assert gateway("Gateway Routes:\n  eth0:\n    ipv4_gateways:\n      999.1.1.1:\n      10.0.0.1:\n") == "10.0.0.1"
    assert gateway("Gateway Routes:\n  eth0:\n    ipv4_gateways:\n      300.0.0.1:\n") is None
