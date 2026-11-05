"""What a real deployment has to collect before it can reason about a network, and turning it into one model.

Firewall exports, router tables and asset network data all name things differently: rules point at
address groups and `application-default`, routes point at interfaces, and which firewall rule really decides a path only
shows once routes and rules are joined. These readers do that work on files shaped like those exports. **In this project
the files are prepared in advance, so no device is ever contacted**, and every result says so.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from porygon_mitigator.flow.engine import compute_reachability, decide, zone_paths
from porygon_mitigator.flow.models import (
    ANY,
    ROUTER_TYPE,
    AllowedFlow,
    Device,
    Environment,
    FirewallRule,
    Route,
    Zone,
)
from porygon_mitigator.flow.topology import _zones_of_addresses, best_route, place_hosts

SIMULATED_SOURCE = "SIMULATED SOURCE: read from a prepared file. No firewall, router or scanner was contacted."
FORWARDING_RULE = "routes-everything"
APPLICATION_DEFAULT = "application-default"
TOP_MAPPED_PATHS = 200


class SourceError(ValueError):
    """A source file is missing or isn't what it should be."""


class RuleMapping(BaseModel):
    """One path from an attacker zone to a host, down to the single rule that decides it on each device."""

    model_config = ConfigDict(extra="forbid")

    vantage: str
    host: str
    open: bool
    routes: list[str] = Field(default_factory=list, description="The route each device on the path has for this host.")
    rules: list[str] = Field(default_factory=list, description="`device: rule (action)`, one per route, in path order.")


def _load(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError as error:
        raise SourceError(f"can't read {path.name}: {type(error).__name__}") from error
    except ValueError as error:
        raise SourceError(f"{path.name} isn't valid JSON") from error


def read_firewalls(sources: Path) -> list[dict[str, Any]]:
    return [_load(path) for path in sorted((sources / "firewalls").glob("*.json"))]


def read_routers(sources: Path) -> list[dict[str, Any]]:
    return [_load(path) for path in sorted((sources / "routers").glob("*.json"))]


_JSON_TYPES = {list: "array", str: "string", int: "number", float: "number", bool: "boolean", type(None): "null"}


def _load_object(path: Path) -> dict[str, Any]:
    """A source that has to be one JSON object. `dict()` would turn a list of pairs into keys, or fail with an error the
    collection step doesn't report, so a Tenable export in the wrong place is refused with a reason instead."""
    loaded = _load(path)
    if not isinstance(loaded, dict):
        kind = _JSON_TYPES.get(type(loaded), type(loaded).__name__)
        raise SourceError(f"{path.name} holds a JSON {kind}, not the object this step reads")
    return loaded


def read_assets(sources: Path) -> dict[str, Any]:
    return _load_object(sources / "assets.json")


def summarize_firewall(export: dict[str, Any]) -> dict[str, Any]:
    return {
        "device": export["hostname"],
        "type": export["type"],
        "version": export.get("sw_version"),
        "zones": len(export["zones"]),
        "routes": len(export["virtual_router"]["routes"]),
        "security_rules": len(export["security_rules"]),
        "address_objects": len(export.get("address_objects", {})) + len(export.get("address_groups", {})),
        "service_objects": len(export.get("service_objects", {})) + len(export.get("service_groups", {})),
        "rules_using_application_default": sum(
            APPLICATION_DEFAULT in rule.get("service", []) for rule in export["security_rules"]
        ),
    }


def _addresses(name: str, export: dict[str, Any], seen: frozenset[str] = frozenset()) -> list[str]:
    """Follow address groups down to CIDRs. A name nobody defines stays as it is, and validation stops the run over it:
    a rule read wrongly here would read as safe later."""
    objects, groups = export.get("address_objects", {}), export.get("address_groups", {})
    if name in groups and name not in seen:
        return [item for member in groups[name] for item in _addresses(member, export, seen | {name})]
    if name in objects:
        found = objects[name]
        # A rule matches hosts by address, so a name or a range it can't compare would read as covering nobody.
        if not found.get("ip_netmask"):
            raise SourceError(f"address object {name} isn't an IP or subnet, which the model can't match to a host")
        return [str(found["ip_netmask"])]
    return [name]


_RULE_FIELDS_THAT_DONT_LIMIT = frozenset(
    {"name", "rulebase", "from", "to", "source", "destination", "application", "service", "action", "profile_setting"}
)


def _unmodeled(rule: dict[str, Any]) -> str | None:
    """What a rule depends on that the model has no place for. Dropping it would widen the rule: a deny limited to one
    source would read as a deny for everyone, and hide every allow below it."""
    if any(item != ANY for item in rule.get("source", [ANY])):
        return "a source other than any"
    if rule.get("negate_source") or rule.get("negate_destination"):
        return "a negated address"
    return None


def _closes_only_some_traffic(rule: dict[str, Any]) -> bool:
    """A deny limited to some services, applications, users, schedules or anything else this doesn't know can't be said
    to close the host, so it doesn't count: reading it as closing everything would hide what the host still answers."""
    if rule.get("action", "allow") == "allow":
        return False
    if {key for key, value in rule.items() if value} - _RULE_FIELDS_THAT_DONT_LIMIT:
        return True
    return any(
        rule.get(field, [ANY]) not in ([ANY], [ANY.upper()], ANY, [], None) for field in ("service", "application")
    )


def _device_from_firewall(export: dict[str, Any]) -> Device:
    active = [rule for rule in export["security_rules"] if not rule.get("disabled")]
    problems = [
        f"device {export['hostname']} rule {rule['name']} uses {reason}, which the model can't represent"
        for rule in active
        if (reason := _unmodeled(rule))
    ]
    if problems:
        raise SourceError("; ".join(problems))
    rules = [
        FirewallRule(
            name=rule["name"],
            from_zone=rule.get("from", [ANY]),
            to_zone=rule.get("to", [ANY]),
            destination=[item for name in rule.get("destination", [ANY]) for item in _addresses(name, export)],
            action=rule.get("action", "allow"),
            vulnerability_profile=rule.get("profile_setting", {}).get("vulnerability"),
        )
        for rule in active
        if not _closes_only_some_traffic(rule)
    ]
    return Device(
        id=export["hostname"],
        name=export.get("display_name", ""),
        fw_type=export["type"],
        version=export.get("sw_version"),
        zones=[zone["name"] for zone in export["zones"]],
        routes=_routes(export["virtual_router"]["routes"]),
        threat_prevention=export.get("threat_prevention_license", False),
        rules=rules,
        vulnerability_profiles={
            # What the profile blocks, as `porygon panos collect` resolves it. Never `threat_exceptions`: those are
            # per-signature overrides, often allow or alert, and reading them as blocks would credit missing protection.
            name: list(profile.get("blocked_threat_ids", []))
            for name, profile in export.get("vulnerability_profiles", {}).items()
        },
    )


def _routes(rows: list[dict[str, Any]]) -> list[Route]:
    return [
        Route(destination=row["destination"], zone=row.get("zone"), next_hop_device=row.get("nexthop_device"))
        for row in rows
    ]


def _device_from_router(export: dict[str, Any]) -> Device:
    """A router has no rule base: it forwards what its table covers, and that's the only 'rule' a path meets there."""
    return Device(
        id=export["hostname"],
        name=export.get("display_name", ""),
        fw_type=ROUTER_TYPE,
        threat_prevention=False,
        zones=[zone["name"] for zone in export["zones"]],
        routes=_routes(export["routes"]),
        rules=[FirewallRule(name=FORWARDING_RULE)],
    )


def _zones(exports: list[dict[str, Any]]) -> list[Zone]:
    zones: dict[str, Zone] = {}
    for export in exports:
        for row in export["zones"]:
            zone = Zone(
                id=row["name"],
                name=row.get("display_name", ""),
                kind=row.get("kind", "unknown"),
                cidrs=row.get("cidrs", []),
                attacker_vantage=row.get("attacker_vantage"),
            )
            known = zones.setdefault(zone.id, zone)
            if known.is_vantage != zone.is_vantage or sorted(known.cidrs) != sorted(zone.cidrs):
                raise SourceError(f"exports disagree about zone {zone.id}: whether it's an attacker's, or its ranges")
    return list(zones.values())


def normalize(sources: Path, scanned: Environment) -> Environment:
    """One environment from the collected sources: its topology from them, hosts and findings from the scan."""
    firewalls, routers = read_firewalls(sources), read_routers(sources)
    assets = read_assets(sources)
    if not firewalls and not routers:
        raise SourceError("no firewall or router export found")
    if "network_events" not in assets:
        raise SourceError("assets.json has no network_events, so what traffic must keep working is unknown")
    by_id = {host["host"]: host for host in assets.get("hosts", [])}
    hosts = []
    for host in scanned.hosts:
        network = by_id.get(host.id, {})
        hosts.append(
            host.model_copy(
                update={
                    "zone": network.get("zone", host.zone),
                    "ips": network.get("ips") or host.ips,
                    "gateway": network.get("gateway", host.gateway),
                }
            )
        )
    environment = Environment(
        label=scanned.label,
        zones=_zones([*firewalls, *routers]),
        devices=[
            *(_device_from_firewall(export) for export in firewalls),
            *(_device_from_router(export) for export in routers),
        ],
        hosts=hosts,
        allowed_flows=[
            AllowedFlow(
                name=event["application"],
                source_zone=event["source_zone"],
                host=event["host"],
                service=event.get("service"),
            )
            for event in assets.get("network_events", [])
        ],
        observed_traffic=_load(sources / "traffic.json") if (sources / "traffic.json").exists() else [],
        vulnerabilities=scanned.vulnerabilities,
    )
    conflicts = []
    for host in environment.hosts:
        routed = _zones_of_addresses(environment, host.ips)
        if host.zone is not None and routed and host.zone not in routed:
            conflicts.append(f"host {host.id}: assets say zone {host.zone}, routes say {', '.join(sorted(routed))}")
    if conflicts:
        raise SourceError("; ".join(conflicts))
    return place_hosts(environment)


def map_routes_to_rules(environment: Environment) -> dict[str, Any]:
    """Join routes and rules: for every path from an attacker zone to a host, the route each device picks and
    the one rule that decides it. Also which rules no such path ever reaches."""
    by_host = {host.id: host for host in environment.hosts}
    devices = {device.id: device for device in environment.devices}
    used: set[tuple[str, str]] = set()
    mapped: list[RuleMapping] = []
    for result in compute_reachability(environment):
        host = by_host[result.host]
        if host.zone is None:
            continue
        ip = host.ips[0] if host.ips else ""
        for path in zone_paths(environment, result.vantage, host.zone):
            hops = [
                decide(device, source, target, host) for device, source, target in path
            ]
            routes, rules = [], []
            arrives = True  # traffic stopped at one hop never meets the rules after it
            for hop in hops:
                if arrives and hop.rule:
                    used.add((hop.device, hop.rule))
                arrives = arrives and hop.action == "allow"
                route = best_route(devices[hop.device].routes, ip) if ip else None
                via = (route.next_hop_device or route.zone) if route else None
                routes.append(
                    f"{hop.device}: {route.destination} via {via}" if route else f"{hop.device}: no route known"
                )
                rules.append(f"{hop.device}: {hop.rule or 'default deny'} ({hop.action})")
            mapped.append(
                RuleMapping(
                    vantage=result.vantage,
                    host=result.host,
                    open=all(hop.action == "allow" for hop in hops),
                    routes=routes,
                    rules=rules,
                )
            )
    mapped.sort(key=lambda item: (not item.open, item.host, item.vantage))
    unreached = sorted(
        f"{device.id}: {rule.name}"
        for device in environment.devices
        for rule in device.rules
        if (device.id, rule.name) not in used and rule.name != FORWARDING_RULE
    )
    return {
        "paths_mapped": len(mapped),
        "paths_open": sum(item.open for item in mapped),
        "devices": len(environment.devices),
        "rules": sum(len(device.rules) for device in environment.devices),
        "rules_no_attacker_path_reaches": unreached,
        "open_paths": [item.model_dump() for item in mapped if item.open][:TOP_MAPPED_PATHS],
    }
