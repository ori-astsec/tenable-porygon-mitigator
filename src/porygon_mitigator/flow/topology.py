"""Map firewall routes to what sits in front of and behind each device.

Firewall routes say which zone or next device an address leaves through. Longest-prefix match places a host in a zone,
and following next-hop devices gives the chain of devices traffic crosses on its way to that host.
"""

from __future__ import annotations

import ipaddress
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from porygon_mitigator.flow.models import Device, Environment, Route, Zone

MAX_CHAIN_HOPS = 16


class HostPlacement(BaseModel):
    model_config = ConfigDict(extra="forbid")

    host: str
    zone: str | None
    method: Literal["declared", "route", "zone_cidr", "model", "not_placed"]
    devices_in_front: list[str] = Field(default_factory=list, description="Nearest to the entry device first.")


def _network(value: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    try:
        return ipaddress.ip_network(value, strict=False)
    except ValueError:
        return None


def _address(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def best_route(routes: list[Route], ip: str) -> Route | None:
    """The most specific route for an address, as a router picks it. The first listed wins a tie."""
    address = _address(ip)
    if address is None:
        return None
    best: tuple[int, Route] | None = None
    for route in routes:
        network = _network(route.destination)
        if network is None or network.version != address.version or address not in network:
            continue
        if best is None or network.prefixlen > best[0]:
            best = (network.prefixlen, route)
    return best[1] if best else None


def route_chain(devices: list[Device], entry_device: str, ip: str) -> tuple[list[str], str | None]:
    """Follow routes from one device towards an address: the devices crossed, and the zone it ends in."""
    by_id = {device.id: device for device in devices}
    chain: list[str] = []
    current: str | None = entry_device
    while current in by_id and current not in chain and len(chain) < MAX_CHAIN_HOPS:
        chain.append(current)
        route = best_route(by_id[current].routes, ip)
        if route is None:
            return chain, None
        if route.next_hop_device is None:
            return chain, route.zone
        current = route.next_hop_device
    return chain, None


def _entry_devices(environment: Environment) -> list[Device]:
    vantages = {zone.id for zone in environment.zones if zone.is_vantage}
    return [device for device in environment.devices if vantages & set(device.zones)] or environment.devices


def _zones_by_cidr(zones: list[Zone], ip: str) -> set[str]:
    """The zones with the most specific range for an address: more than one if two zones claim the same range."""
    address = _address(ip)
    if address is None:
        return set()
    best = 0
    found: set[str] = set()
    for zone in zones:
        for cidr in zone.cidrs:
            network = _network(cidr)
            if network is None or network.version != address.version or address not in network:
                continue
            if network.prefixlen > best or not found:
                best, found = network.prefixlen, {zone.id}
            elif network.prefixlen == best:
                found.add(zone.id)
    return found


def _route_prefix(device: Device, ip: str) -> int:
    route = best_route(device.routes, ip)
    network = _network(route.destination) if route else None
    return network.prefixlen if network else 0


def _route_placement(environment: Environment, ip: str) -> dict[str, list[str]]:
    """Zone -> chain from the most specific route that ends at a zone, across the entry devices. More than one zone
    means the devices disagree. A default route says where everything else goes, not where a host is, so it never places
    one."""
    by_id = {device.id: device for device in environment.devices}
    best = 0
    found: dict[str, list[str]] = {}
    for device in _entry_devices(environment):
        chain, zone = route_chain(environment.devices, device.id, ip)
        prefix = _route_prefix(by_id[chain[-1]], ip) if chain else 0
        if zone is None or not prefix or prefix < best:
            continue
        if prefix > best:
            best, found = prefix, {}
        found.setdefault(zone, chain)
    return found


def _zones_of_addresses(environment: Environment, ips: list[str]) -> dict[str, list[str]]:
    """Zone -> chain across every address of a host, by route and otherwise by zone range, which has no chain. A host
    has one zone here, so more than one means it can't be placed."""
    found: dict[str, list[str]] = {}
    for ip in ips:
        routed = _route_placement(environment, ip)
        zones = routed or {zone: [] for zone in _zones_by_cidr(environment.zones, ip)}
        for zone, chain in zones.items():
            if chain or zone not in found:
                found[zone] = chain
    return found


def place_host(environment: Environment, host_id: str) -> HostPlacement:
    host = next(item for item in environment.hosts if item.id == host_id)
    found = _zones_of_addresses(environment, host.ips)
    if host.zone is not None:
        method = host.placed_by or "declared"
        return HostPlacement(host=host_id, zone=host.zone, method=method, devices_in_front=found.get(host.zone, []))
    if len(found) != 1:
        return HostPlacement(host=host_id, zone=None, method="not_placed")
    zone, chain = next(iter(found.items()))
    return HostPlacement(host=host_id, zone=zone, method="route" if chain else "zone_cidr", devices_in_front=chain)


def place_hosts(environment: Environment) -> Environment:
    """A copy with every host that can be placed given its zone: declared first, then routes, then zone CIDRs."""
    placed = environment.model_copy(deep=True)
    for host in placed.hosts:
        placement = place_host(environment, host.id)
        host.zone = placement.zone
        if placement.method == "route" or placement.method == "zone_cidr":
            host.placed_by = placement.method
    return placed


def network_map(environment: Environment) -> dict[str, object]:
    """Zones, devices and hosts as a graph, for the report and for an agent to read."""
    placements = [place_host(environment, host.id) for host in environment.hosts]
    return {
        "zones": [
            {"id": zone.id, "name": zone.name, "kind": zone.kind, "vantage": zone.is_vantage}
            for zone in environment.zones
        ],
        "devices": [
            {
                "id": device.id,
                "type": device.fw_type,
                "zones": device.zones,
                "rules": len(device.rules),
                "ips": device.threat_prevention,
            }
            for device in environment.devices
        ],
        "hosts": [item.model_dump() for item in placements],
        "totals": {
            "zones": len(environment.zones),
            "devices": len(environment.devices),
            "hosts": len(placements),
            "hosts_placed": sum(item.method != "not_placed" for item in placements),
        },
    }
