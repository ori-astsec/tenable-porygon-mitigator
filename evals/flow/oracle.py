"""An independent reading of the flow's rules, written from docs/flow.md and not from the engine.

Nothing here imports `porygon_mitigator`, and it works on the plain JSON of an environment. Addresses are parsed by hand
and paths are enumerated with no depth limit, so a shortcut in the engine can't also be a shortcut here. The benchmark's
expected answers come from it.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

Env = dict[str, Any]
FULL_V4 = 32
FULL_V6 = 128
V6_GROUPS = 8


def parse_address(text: str) -> tuple[int, int] | None:
    """(IP version, value), or None for something that isn't an address."""
    if ":" in text:
        head, gap, tail = text.partition("::")
        left = [part for part in head.split(":") if part]
        right = [part for part in tail.split(":") if part]
        if not gap and len(left) != V6_GROUPS:
            return None
        try:
            groups = [int(part, 16) for part in left] + [0] * (V6_GROUPS - len(left) - len(right))
            groups += [int(part, 16) for part in right]
        except ValueError:
            return None
        value = 0
        for group in groups:
            value = (value << 16) | group
        return 6, value
    parts = text.split(".")
    if len(parts) != 4 or not all(part.isdigit() and int(part) < 256 for part in parts):
        return None
    value = 0
    for part in parts:
        value = (value << 8) | int(part)
    return 4, value


def in_cidr(ip: str, cidr: str) -> bool:
    address = parse_address(ip)
    base, _, bits_text = cidr.partition("/")
    network = parse_address(base)
    if address is None or network is None or address[0] != network[0]:
        return False
    full = FULL_V4 if network[0] == 4 else FULL_V6
    bits = int(bits_text) if bits_text else full
    mask = ((1 << bits) - 1) << (full - bits)
    return address[1] & mask == network[1] & mask


def _names_match(names: list[str], name: str) -> bool:
    return any(item.lower() == "any" or item == name for item in names)


def _destination_covers(destinations: list[str], host: Env) -> bool:
    for destination in destinations:
        if destination.lower() == "any" or destination == host["id"]:
            return True
        if any(in_cidr(ip, destination) for ip in host.get("ips", [])):
            return True
    return False


def first_match(device: Env, from_zone: str, to_zone: str, host: Env) -> Env | None:
    for rule in device.get("rules", []):
        if (
            _names_match(rule.get("from_zone", ["any"]), from_zone)
            and _names_match(rule.get("to_zone", ["any"]), to_zone)
            and _destination_covers(rule.get("destination", ["any"]), host)
        ):
            return rule
    return None


@dataclass(frozen=True)
class Hop:
    device: str
    from_zone: str
    to_zone: str


def zone_walks(environment: Env, source: str, target: str) -> Iterator[list[Hop]]:
    """Every way across the map with no zone twice. A device is crossed once per pass, so traffic going through one
    firewall from A to C is the A to C hop, never A to B then B to C on that same firewall."""
    if source == target:
        yield []
        return
    devices = environment.get("devices", [])

    def walk(zone: str, seen: frozenset[str], path: list[Hop]) -> Iterator[list[Hop]]:
        for device in devices:
            if zone not in device.get("zones", []) or (path and path[-1].device == device["id"]):
                continue
            for next_zone in device["zones"]:
                if next_zone in seen:
                    continue
                hop = Hop(device["id"], zone, next_zone)
                if next_zone == target:
                    yield [*path, hop]
                else:
                    yield from walk(next_zone, seen | {next_zone}, [*path, hop])

    yield from walk(source, frozenset({source}), [])


def vantages(environment: Env) -> list[str]:
    result = []
    for zone in environment.get("zones", []):
        declared = zone.get("attacker_vantage")
        internet_like = zone.get("kind") in ("internet", "partner", "vpn", "guest")
        if internet_like if declared is None else declared:
            result.append(zone["id"])
    return result


def open_walks(environment: Env, source: str, host: Env) -> list[list[tuple[Hop, Env]]]:
    """Each path that reaches this host, with the rule that let it through on each hop."""
    if host.get("zone") is None:
        return []
    by_id = {device["id"]: device for device in environment.get("devices", [])}
    found = []
    for walk in zone_walks(environment, source, host["zone"]):
        hops = []
        for hop in walk:
            rule = first_match(by_id[hop.device], hop.from_zone, hop.to_zone, host)
            if rule is None or rule.get("action", "allow") != "allow":
                break
            hops.append((hop, rule))
        else:
            found.append(hops)
    return found


def scan(environment: Env) -> dict[tuple[str, str], bool]:
    """(vantage, host) -> does a path reach it."""
    return {
        (vantage, host["id"]): bool(open_walks(environment, vantage, host))
        for host in environment.get("hosts", [])
        for vantage in vantages(environment)
    }


def connected(environment: Env, zone: str) -> bool:
    return any(next(zone_walks(environment, vantage, zone), None) is not None for vantage in vantages(environment))


def _has_usable_address(environment: Env, host: Env) -> bool:
    """Rules on addresses say nothing about a host with no address of that IP version."""
    rule_versions = {
        parsed[0]
        for device in environment.get("devices", [])
        for rule in device.get("rules", [])
        for value in rule.get("destination", [])
        if (parsed := parse_address(value.partition("/")[0]))
    }
    host_versions = {parsed[0] for ip in host.get("ips", []) if (parsed := parse_address(ip))}
    return not rule_versions or bool(rule_versions & host_versions)


def undetermined(environment: Env) -> int:
    """Scan checks that find nothing only because the map can't say: off the map, unconnected, or no usable address."""
    count = 0
    for (_, host_id), reachable in scan(environment).items():
        host = next(item for item in environment["hosts"] if item["id"] == host_id)
        if not reachable and (
            host.get("zone") is None
            or not connected(environment, host["zone"])
            or not _has_usable_address(environment, host)
        ):
            count += 1
    return count


