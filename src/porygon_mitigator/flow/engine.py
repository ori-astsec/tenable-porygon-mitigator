"""Reachability, CVE tags, what-if and verification over the simulated environment. Deterministic: no model calls.

The order follows how accessibility analysis has to work: can a host be reached from somewhere an attacker can stand,
is the vulnerable software running on it, and does anything on the way stop the exploit. There's no port data.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from functools import lru_cache, partial

from porygon_mitigator.flow.models import (
    ANY,
    ROUTER_TYPE,
    AllowedFlow,
    Candidate,
    Change,
    ChangeImpact,
    CveTag,
    Device,
    Environment,
    Finding,
    FirewallRule,
    FlowCheck,
    FlowMitigation,
    Funnel,
    HeldOption,
    Host,
    HostReach,
    ImageTest,
    ObservedTraffic,
    PathHop,
    Plan,
    Protection,
    Recommendation,
    RecommendedMitigation,
    TagBasis,
    TaggedFinding,
    Verification,
    VulnerabilityProfile,
)

DEFAULT_PROFILE = "porygon-strict"
MAX_PATH_ZONES = 8
# Past these a map can't be settled, and reads as unknown. Few real maps get near them, but two firewalls that share
# many zones can, so list an HA pair as one device.
MAX_PATHS = 1000
MAX_SEARCH_STEPS = 100_000
_PROCESS_ARGUMENTS = re.compile(r"\s+-")
_PROCESS_VERSION = re.compile(r"[-_.]?[\d.]+$")
_SHARED_HOST_PROGRAMS = frozenset({"svchost", "system", "services", "wininit", "dllhost"})
_MAX_NAMED_PROGRAMS = 4
_TAG_RANK = {
    "reachable": 0,
    "host_reachable": 1,
    "not_seen_running": 2,
    "unknown": 3,
    "not_reachable": 4,
    "local_only": 5,
}
_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_VECTOR_RANK = {"network": 0, "adjacent": 1, "unknown": 2, "local": 3, "physical": 4}
_EXPOSING_TAGS = ("reachable", "host_reachable", "not_seen_running")
MAX_REPORTED_PROBLEMS = 10
_PARSED_VALUES = 65536


def canonical_hash(*parts: object) -> str:
    text = json.dumps(parts, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def environment_hash(environment: Environment) -> str:
    return canonical_hash(environment.model_dump(mode="json"))


def mitigations_hash(mitigations: Iterable[FlowMitigation]) -> str:
    return canonical_hash([item.model_dump(mode="json") for item in mitigations])


def _duplicates(names: Iterable[str]) -> list[str]:
    return sorted(name for name, count in Counter(names).items() if count > 1)


@lru_cache(maxsize=_PARSED_VALUES)
def _network_of(value: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    try:
        return ipaddress.ip_network(value, strict=False)
    except ValueError:
        return None


@lru_cache(maxsize=_PARSED_VALUES)
def _address_of(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def _is_network(value: str) -> bool:
    return _network_of(value) is not None


def _rule_problems(device: Device, rule: FirewallRule, zones: set[str], hosts: set[str]) -> list[str]:
    where = f"device {device.id} rule {rule.name}"
    lists = {
        "from_zone": rule.from_zone,
        "to_zone": rule.to_zone,
        "destination": rule.destination,
    }
    problems = [f"{where}: {name} is empty, so it can never match" for name, values in lists.items() if not values]
    problems += [
        f"{where}: no zone {zone!r}"
        for zone in [*rule.from_zone, *rule.to_zone]
        if zone.lower() != ANY and zone not in zones
    ]
    problems += [
        f"{where}: destination {value!r} isn't `any`, a host id or a CIDR, so it can't be evaluated"
        for value in rule.destination
        if value.lower() != ANY and value not in hosts and not _is_network(value)
    ]
    return problems


def validate_inputs(environment: Environment, mitigations: Iterable[FlowMitigation]) -> list[str]:
    """What would make the simulation wrong without any error. A rule nobody can read would otherwise fall through to
    the default deny and read as safe, so these stop the run."""
    zones = {zone.id for zone in environment.zones}
    devices = {device.id for device in environment.devices}
    hosts = {host.id for host in environment.hosts}
    problems = [f"duplicate zone id {name!r}" for name in _duplicates(zone.id for zone in environment.zones)]
    problems += [f"duplicate device id {name!r}" for name in _duplicates(device.id for device in environment.devices)]
    problems += [f"duplicate host id {name!r}" for name in _duplicates(host.id for host in environment.hosts)]
    if environment.hosts and not _vantages(environment):
        problems.append("no zone is an attacker vantage, so nothing can be judged reachable")
    for device in environment.devices:
        problems += [f"device {device.id}: no zone {zone!r}" for zone in device.zones if zone not in zones]
        for route in device.routes:
            if not _is_network(route.destination):
                problems.append(f"device {device.id}: route destination {route.destination!r} isn't a CIDR")
            if route.zone is not None and route.zone not in zones:
                problems.append(f"device {device.id}: route to unknown zone {route.zone!r}")
            if route.next_hop_device is not None and route.next_hop_device not in devices:
                problems.append(f"device {device.id}: route to unknown device {route.next_hop_device!r}")
        for rule in device.rules:
            problems += _rule_problems(device, rule, zones, hosts)
    problems += [
        f"host {host.id}: no zone {host.zone!r}"
        for host in environment.hosts
        if host.zone is not None and host.zone not in zones
    ]
    for flow in environment.allowed_flows:
        if flow.source_zone not in zones:
            problems.append(f"allowed flow {flow.name}: no zone {flow.source_zone!r}")
        if flow.host not in hosts:
            problems.append(f"allowed flow {flow.name}: no host {flow.host!r}")
    mitigation_list = list(mitigations)
    problems += [f"duplicate mitigation id {name!r}" for name in _duplicates(item.id for item in mitigation_list)]
    return problems


def _destination_matches(destinations: list[str], host: Host) -> bool:
    for destination in destinations:
        if destination.lower() == ANY or destination == host.id:
            return True
        network = _network_of(destination)
        if network is None:
            continue
        for ip in host.ips:
            address = _address_of(ip)
            if address is not None and address in network:
                return True
    return False


def _zone_matches(zones: list[str], zone: str) -> bool:
    return ANY in (item.lower() for item in zones) or zone in zones


def decide(device: Device, from_zone: str, to_zone: str, host: Host) -> PathHop:
    """First matching rule wins; no match is a deny."""
    for rule in device.rules:
        if (
            _zone_matches(rule.from_zone, from_zone)
            and _zone_matches(rule.to_zone, to_zone)
            and _destination_matches(rule.destination, host)
        ):
            return PathHop(
                device=device.id,
                from_zone=from_zone,
                to_zone=to_zone,
                rule=rule.name,
                action=rule.action,
                vulnerability_profile=rule.vulnerability_profile,
            )
    return PathHop(device=device.id, from_zone=from_zone, to_zone=to_zone)


ZoneWalks = tuple[tuple[tuple[str, str, str], ...], ...]


@lru_cache(maxsize=_PARSED_VALUES)
def _walk_zones(links: tuple[tuple[str, tuple[str, ...]], ...], source: str, target: str) -> tuple[ZoneWalks, bool]:
    """Every simple path of (device id, from zone, to zone) between two zones, and whether the search stopped early. It
    depends only on which device joins which zones, so it's remembered across every host that shares it."""
    adjacent: dict[str, list[tuple[str, str]]] = {}
    for device, zones in links:
        for zone in zones:
            adjacent.setdefault(zone, []).extend((device, other) for other in zones if other != zone)
    paths: list[tuple[tuple[str, str, str], ...]] = []
    truncated = False
    steps = 0

    def connects(zone: str, seen: set[str]) -> bool:
        frontier, visited = [zone], set(seen)
        while frontier:
            current = frontier.pop()
            if current == target:
                return True
            if current not in visited:
                visited.add(current)
                frontier.extend(other for _, other in adjacent.get(current, []))
        return False

    def walk(zone: str, seen: set[str], path: tuple[tuple[str, str, str], ...]) -> None:
        nonlocal truncated, steps
        for device, next_zone in adjacent.get(zone, []):
            # Going in and out of one device again is its direct hop, which is already there.
            if next_zone in seen or (path and path[-1][0] == device):
                continue
            steps += 1
            if len(paths) >= MAX_PATHS or steps >= MAX_SEARCH_STEPS:
                truncated = True
                return
            hop = (device, zone, next_zone)
            if next_zone == target:
                paths.append((*path, hop))
            elif len(seen) >= MAX_PATH_ZONES:
                truncated = truncated or connects(next_zone, seen)
            else:
                walk(next_zone, seen | {next_zone}, (*path, hop))

    walk(source, {source}, ())
    return tuple(paths), truncated


def _search_zone_paths(
    environment: Environment, source: str, target: str
) -> tuple[list[list[tuple[Device, str, str]]], bool]:
    """Every simple path between two zones on this environment's devices. An empty path means the same zone."""
    if source == target:
        return [[]], False
    links = tuple((device.id, tuple(device.zones)) for device in environment.devices)
    walks, truncated = _walk_zones(links, source, target)
    devices = {device.id: device for device in environment.devices}
    return [[(devices[device], left, right) for device, left, right in walk] for walk in walks], truncated


def zone_paths(environment: Environment, source: str, target: str) -> list[list[tuple[Device, str, str]]]:
    return _search_zone_paths(environment, source, target)[0]


def _map_cant_settle(environment: Environment, zone: str, vantages: list[str]) -> bool:
    """No vantage connects to this zone at all, or the search gave up: "no open path" would prove nothing here."""
    connected = False
    for vantage in vantages:
        paths, truncated = _search_zone_paths(environment, vantage, zone)
        if truncated:
            return True
        connected = connected or bool(paths)
    return not connected


def _vantages(environment: Environment) -> list[str]:
    return [zone.id for zone in environment.zones if zone.is_vantage]


def reach(environment: Environment, source: str, host: Host) -> tuple[list[list[PathHop]], list[PathHop]]:
    """Open paths from a zone to a host, and the closest blocked path when there are none."""
    if host.zone is None:
        return [], []
    open_paths: list[list[PathHop]] = []
    blocked: list[PathHop] = []
    for path in zone_paths(environment, source, host.zone):
        hops = [decide(device, from_zone, to_zone, host) for device, from_zone, to_zone in path]
        if all(hop.action == "allow" for hop in hops):
            open_paths.append(hops)
        elif not blocked or len(hops) < len(blocked):
            blocked = hops
    return open_paths, blocked


def _why_unsettled(host: Host, context: _TagContext) -> str | None:
    """Why finding no path to this host doesn't make it closed, or None when it does."""
    if host.zone is None:
        return "not_placed"
    if context.converted:
        return "model_converted"
    if host.zone in context.unsettled_zones:
        return "not_connected"
    if not _has_address_rules_can_match(host, context.address_versions):
        return "no_address"
    return None


def compute_reachability(environment: Environment) -> list[HostReach]:
    """Whether each attacker vantage can reach each host: the simulated scan."""
    results: list[HostReach] = []
    context = _tag_context(environment, ())
    for host in environment.hosts:
        conclusive = _why_unsettled(host, context) is None
        for vantage in _vantages(environment):
            open_paths, blocked = reach(environment, vantage, host)
            results.append(
                HostReach(
                    vantage=vantage,
                    host=host.id,
                    reachable=bool(open_paths),
                    settled=bool(open_paths) or conclusive,
                    hops=open_paths[0] if open_paths else blocked,
                    open_paths=open_paths,
                )
            )
    return results


def _search_stopped(environment: Environment, zone: str, vantages: list[str]) -> bool:
    return any(_search_zone_paths(environment, vantage, zone)[1] for vantage in vantages)


def scan_gaps(environment: Environment, results: Iterable[HostReach]) -> dict[str, list[tuple[str, str]]]:
    """Hosts the scan can't judge: host id -> (reason, what it means). For a host that isn't here, no open path means
    not reachable."""
    context = _tag_context(environment, ())
    unsettled = {item.host for item in results if not item.settled}
    gaps: dict[str, list[tuple[str, str]]] = {}
    for host in environment.hosts:
        reasons: list[tuple[str, str]] = []
        if host.zone is None:
            reasons.append(("not_placed", "not placed on the map"))
        why = _why_unsettled(host, context) if host.id in unsettled else None
        if why == "not_connected" and host.zone is not None:
            if _search_stopped(environment, host.zone, context.vantages):
                reasons.append(("search_stopped", f"the path search to zone {host.zone} stopped at its limit"))
            else:
                reasons.append(("not_connected", f"zone {host.zone} isn't connected to any attacker zone"))
        elif why == "no_address":
            reasons.append(("no_address", "it has no address the rules can match"))
        elif why == "model_converted":
            reasons.append(("model_converted", "a model converted the rules, so a missing path proves nothing"))
        if reasons:
            gaps[host.id] = reasons
    return gaps


def _scanner_tested_service(finding: Finding) -> bool:
    """The scanner reached the service over the network, rather than reading a patch level from inside the machine."""
    return finding.remote_check


def _program_name(written: str) -> str:
    """One program however it's written: `/usr/sbin/sshd -D`, `SSHD`, `"sshd.exe"`, and `tomcat` with `tomcat9.exe`."""
    command = _PROCESS_ARGUMENTS.split(written.strip())[0].strip("\"'").replace("\\", "/")
    base = command.rsplit("/", 1)[-1].lower().removesuffix(".exe")
    return _PROCESS_VERSION.sub("", base)


def _named_programs(profile: VulnerabilityProfile) -> set[str]:
    """The programs a CVE's details really point at. A shared host like `svchost.exe` runs many unrelated services, so
    its running says nothing about this flaw, and a long list is the machine's own processes copied back."""
    if len(profile.processes) > _MAX_NAMED_PROGRAMS:
        return set()
    return {_program_name(name) for name in profile.processes} - _SHARED_HOST_PROGRAMS


def _threat_ids_by_cve(mitigations: Iterable[FlowMitigation]) -> dict[str, list[list[str]]]:
    catalogue: dict[str, list[list[str]]] = {}
    for mitigation in mitigations:
        if mitigation.kind == "ips_threat_ids" and mitigation.threat_ids:
            for cve in mitigation.cve_ids:
                catalogue.setdefault(cve, []).append(mitigation.threat_ids)
    return catalogue


def _rules_letting_through(device: Device, from_zone: str, to_zone: str, host: Host) -> list[FirewallRule]:
    """Every allow rule that matches, down to the first rule that closes the host. With no port data any of them may be
    what carries the traffic, so a signature has to be on all of them."""
    rules = []
    for rule in device.rules:
        if (
            _zone_matches(rule.from_zone, from_zone)
            and _zone_matches(rule.to_zone, to_zone)
            and _destination_matches(rule.destination, host)
        ):
            if rule.action != "allow":
                break
            rules.append(rule)
    return rules


def _path_blocks(environment: Environment, path: list[PathHop], threat_sets: list[list[str]], host: Host) -> bool:
    devices = {device.id: device for device in environment.devices}
    for hop in path:
        device = devices[hop.device]
        rules = _rules_letting_through(device, hop.from_zone, hop.to_zone, host)
        profiles = device.vulnerability_profiles
        if (
            device.threat_prevention
            and rules
            and any(
                all(set(profiles.get(rule.vulnerability_profile or "", [])).issuperset(ids) for rule in rules)
                for ids in threat_sets
            )
        ):
            return True
    return False


OpenCache = dict[tuple[object, ...], tuple[list[list[PathHop]], list[str]]]


def _open_over(
    environment: Environment, host: Host, sources: list[str], cache: OpenCache
) -> tuple[list[list[PathHop]], list[str]]:
    """Open paths to this host from these zones. Thousands of CVEs share a host, so it's memoized."""
    key = (host.id, tuple(sources))
    if key in cache:
        return cache[key]
    open_paths: list[list[PathHop]] = []
    vantages: list[str] = []
    for vantage in sources:
        paths, _ = reach(environment, vantage, host)
        if paths:
            open_paths.extend(paths)
            vantages.append(vantage)
    cache[key] = (open_paths, vantages)
    return cache[key]


@dataclass
class _TagContext:
    threats: dict[str, list[list[str]]]
    vantages: list[str]
    unsettled_zones: set[str]
    address_versions: set[int]
    tested_cves: dict[str, set[str]] = field(default_factory=dict)
    converted: bool = False
    open_paths: OpenCache = field(default_factory=dict)


def _has_address_rules_can_match(host: Host, versions: set[int]) -> bool:
    if not versions:
        return True
    return any(address.version in versions for ip in host.ips if (address := _address_of(ip)) is not None)


def _tag_context(environment: Environment, mitigations: Iterable[FlowMitigation]) -> _TagContext:
    vantages = _vantages(environment)
    zones = {host.zone for host in environment.hosts if host.zone is not None}
    versions: set[int] = {
        network.version
        for device in environment.devices
        for rule in device.rules
        for value in rule.destination
        if value.lower() != ANY and (network := _network_of(value)) is not None
    }
    return _TagContext(
        threats=_threat_ids_by_cve(mitigations),
        vantages=vantages,
        unsettled_zones={zone for zone in zones if _map_cant_settle(environment, zone, vantages)},
        address_versions=versions,
        converted=bool(environment.model_converted),
        tested_cves={
            host.id: {item.cve for item in host.findings if _scanner_tested_service(item)} for host in environment.hosts
        },
    )


def _protection(
    environment: Environment,
    host: Host,
    finding: Finding,
    paths: list[list[PathHop]],
    context: _TagContext,
) -> list[Protection]:
    protection: list[Protection] = (
        ["host_control"] if any(finding.cve in cves for cves in host.host_controls.values()) else []
    )
    # If the software runs and is reachable the exploit crosses these rules, and if it doesn't there's nothing to
    # attack, so a signature counts on a patch-level finding too. A model can write any profile into the rules it
    # converts, so those earn nothing.
    threat_sets = context.threats.get(finding.cve, []) if not context.converted else []
    # With the search cut short there may be open paths it never saw, and nothing says those are blocked.
    settled = host.zone not in context.unsettled_zones
    if threat_sets and settled and all(_path_blocks(environment, path, threat_sets, host) for path in paths):
        protection.append("ips")
    return protection


def _running_programs(host: Host) -> set[str]:
    running = {_program_name(name) for name in host.processes}
    return running | {_program_name(name) for name, state in host.services.items() if state == "running"}


def _is_running(host: Host, profile: VulnerabilityProfile | None) -> bool:
    return profile is not None and bool(_named_programs(profile) & _running_programs(host))


def _not_seen_running(host: Host, profile: VulnerabilityProfile) -> bool:
    """The details name a program, and nothing the machine reports says it's running. It isn't proof: the name came
    from a model, and what a scan lists isn't everything. A service list doesn't name processes (`spoolsv.exe` runs as
    `spooler`), so where there is one, only that service being stopped says so."""
    names = _named_programs(profile)
    # Naming a shared host says the flaw runs inside it, and nothing here can say that isn't running.
    if {_program_name(name) for name in profile.processes} & _SHARED_HOST_PROGRAMS:
        return False
    if not names or not host.processes or names & _running_programs(host):
        return False
    if not host.services:
        return True
    stopped = {_program_name(service) for service, state in host.services.items() if state in ("stopped", "disabled")}
    return names <= stopped


def _tag_finding(environment: Environment, host: Host, finding: Finding, context: _TagContext) -> TaggedFinding:
    """The runtime analysis: can the internet reach this machine, and is this flaw's software running on it? A name
    comes from a model reading scanner text, so it can only make a pair more exposed: a wrong one can't clear a CVE,
    which is why a pair not seen running stays exposed. A flaw class only sets local and client flaws apart."""

    def tagged(
        tag: CveTag,
        basis: TagBasis,
        vantages: list[str] | None = None,
        protected_by: list[Protection] | None = None,
    ) -> TaggedFinding:
        return TaggedFinding(
            cve=finding.cve,
            host=host.id,
            tag=tag,
            basis=basis,
            severity=finding.severity,
            kev=finding.kev,
            access_vector=finding.access_vector,
            vantages=vantages or [],
            protected_by=protected_by or [],
        )

    if finding.access_vector in ("local", "physical") or finding.vulnerability_class == "local":
        return tagged("local_only", "local_vector")
    if finding.vulnerability_class == "client":
        return tagged("not_reachable", "client_side")
    if finding.access_vector == "unknown":
        return tagged("unknown", "unknown_vector")
    if host.zone is None:
        return tagged("unknown", "not_placed")
    adjacent = finding.access_vector == "adjacent"
    sources = context.vantages
    if adjacent:
        sources = [host.zone] if host.zone in context.vantages else []
    open_paths, vantages = _open_over(environment, host, sources, context.open_paths)
    if not open_paths:
        # A model read these rules, and nothing checks it read every allow: no path can't count as closed.
        if context.converted:
            return tagged("unknown", "model_converted")
        if not adjacent and host.zone in context.unsettled_zones:
            return tagged("unknown", "not_connected")
        if not _has_address_rules_can_match(host, context.address_versions):
            return tagged("unknown", "no_address")
        return tagged("not_reachable", "no_path")
    profile = environment.vulnerabilities.get(finding.cve)
    protected_by = _protection(environment, host, finding, open_paths, context)
    if finding.cve in context.tested_cves.get(host.id, set()):
        return tagged("reachable", "scanner_tested", vantages, protected_by)
    if _is_running(host, profile):
        return tagged("reachable", "software_running", vantages, protected_by)
    if profile is not None and _not_seen_running(host, profile):
        return tagged("not_seen_running", "not_seen_running", vantages, protected_by)
    return tagged("host_reachable", "host_open", vantages, protected_by)


def _merge_pair(items: list[TaggedFinding]) -> TaggedFinding:
    """One verdict for a (CVE, host) from all its findings: the most exposed tag and the worst severity. Every finding
    on a pair shares the host's paths and the CVE's controls, so it's protected only if all that expose it are."""
    winner = min(items, key=lambda item: (_TAG_RANK[item.tag], item.basis == "client_side", item.basis))
    exposing = [item for item in items if item.tag in _EXPOSING_TAGS]
    protections: set[Protection] = set()
    if exposing:
        protections = set(exposing[0].protected_by).intersection(*(item.protected_by for item in exposing))
    return winner.model_copy(
        update={
            "severity": min((item.severity for item in items), key=lambda value: _SEVERITY_RANK.get(value, 9)),
            "kev": any(item.kev for item in items),
            "access_vector": min((item.access_vector for item in items), key=_VECTOR_RANK.__getitem__),
            "vantages": sorted({zone for item in exposing or [winner] for zone in item.vantages}),
            "protected_by": sorted(protections),
        }
    )


def tag_cves(
    environment: Environment, mitigations: Iterable[FlowMitigation] = (), hosts: set[str] | None = None
) -> list[TaggedFinding]:
    """One tag per (CVE, host), merged from every finding that names the pair."""
    context = _tag_context(environment, mitigations)
    pairs: dict[tuple[str, str], list[TaggedFinding]] = {}
    for host in environment.hosts:
        if hosts is not None and host.id not in hosts:
            continue
        for finding in host.findings:
            pairs.setdefault((finding.cve, host.id), []).append(_tag_finding(environment, host, finding, context))
    return sorted((_merge_pair(items) for items in pairs.values()), key=lambda item: (item.host, item.cve))


def _remotely_exploitable(item: TaggedFinding) -> bool:
    return item.access_vector in ("network", "unknown") and item.tag != "local_only" and item.basis != "client_side"


def counts_as_known_exploited(item: TaggedFinding) -> bool:
    """On the funnel's Exposed and known exploited step, once it's exposed."""
    return item.kev and item.severity in ("high", "critical") and _remotely_exploitable(item)


def reachable_left_open(tags: list[TaggedFinding]) -> int:
    """The funnel's last step: its Reachable pairs that nothing stops."""
    rated = [item for item in tags if item.severity in ("high", "critical") and _remotely_exploitable(item)]
    return sum(item.exposed and item.tag == "reachable" for item in rated)


def funnel(tags: list[TaggedFinding]) -> Funnel:
    """A finding with no stated vector stays in the remote rows: dropping it would hide it from every count below."""
    remote = [item for item in tags if item.access_vector in ("network", "unknown")]
    critical = [item for item in remote if item.severity == "critical"]
    kev = [item for item in critical if item.kev]
    rated = [item for item in tags if item.severity in ("high", "critical")]
    exploitable = [item for item in rated if _remotely_exploitable(item)]
    known = [item for item in tags if counts_as_known_exploited(item)]
    return Funnel(
        findings=len(tags),
        known_exposed=sum(item.tag in _EXPOSING_TAGS for item in known),
        high_critical=len(rated),
        remotely_exploitable=len(exploitable),
        exposed=sum(item.tag in _EXPOSING_TAGS for item in exploitable),
        reachable=sum(item.tag == "reachable" for item in exploitable),
        cant_judge=sum(item.tag == "unknown" for item in exploitable),
        remote=len(remote),
        remote_critical=len(critical),
        remote_critical_kev=len(kev),
        kev_reachable=sum(item.tag == "reachable" for item in kev),
        kev_host_reachable=sum(item.tag == "host_reachable" for item in kev),
        kev_not_seen_running=sum(item.tag == "not_seen_running" for item in kev),
        kev_not_reachable=sum(item.tag == "not_reachable" and item.basis != "client_side" for item in kev),
        kev_client_side=sum(item.basis == "client_side" for item in kev),
        kev_local_only=sum(item.tag == "local_only" for item in kev),
        kev_unknown=sum(item.tag == "unknown" for item in kev),
        kev_protected=sum(item.tag in _EXPOSING_TAGS and bool(item.protected_by) for item in kev),
        kev_exposed=sum(item.exposed for item in kev),
    )


def flow_passes(environment: Environment, flow: AllowedFlow) -> bool:
    host = next((item for item in environment.hosts if item.id == flow.host), None)
    if host is None or host.zone is None:
        return False
    if flow.service and host.services.get(flow.service.lower()) in ("stopped", "disabled"):
        return False
    return bool(reach(environment, flow.source_zone, host)[0])


def _rules_that_may_reset(
    environment: Environment, path: list[PathHop], trips: list[list[str]], host: Host
) -> set[tuple[str, str]]:
    """The rules on this path carrying the signature. With no port data any of them may carry these sessions."""
    devices = {device.id: device for device in environment.devices}
    rules: set[tuple[str, str]] = set()
    for hop in path:
        device = devices[hop.device]
        for rule in _rules_letting_through(device, hop.from_zone, hop.to_zone, host):
            blocked = set(device.vulnerability_profiles.get(rule.vulnerability_profile or "", []))
            if device.threat_prevention and any(blocked.issuperset(ids) for ids in trips):
                rules.add((device.id, rule.name))
    return rules


def traffic_action(environment: Environment, item: ObservedTraffic) -> str:
    """What the firewalls do to these sessions: pass them, drop them on a rule, or reset them on a signature. Each side
    is read the cautious way: an attack is only stopped if every rule stops it, and traffic that may be needed is at
    risk if any rule might reset it."""
    flow = AllowedFlow(name=item.name, source_zone=item.source_zone, host=item.host)
    if not flow_passes(environment, flow):
        return "drop"
    host = next(entry for entry in environment.hosts if entry.id == item.host)
    paths = reach(environment, item.source_zone, host)[0]
    trips = [[threat_id] for threat_id in item.threat_ids]
    if traffic_kind(environment, item) == "attack":
        reset = all(_path_blocks(environment, path, trips, host) for path in paths)
    else:
        reset = any(_rules_that_may_reset(environment, path, trips, host) for path in paths)
    return "reset-both" if trips and reset else "allow"


def traffic_kind(environment: Environment, item: ObservedTraffic) -> str:
    """`needed` if it's traffic that has to keep working, even when it trips a signature: that's a false alarm.
    Otherwise `attack` if it trips one, and `unknown` if nothing says either way."""
    path = (item.source_zone, item.host)
    on_path = [flow for flow in environment.allowed_flows if (flow.source_zone, flow.host) == path]
    if any(flow.name == item.name for flow in on_path):
        return "needed"
    # A session along a path needed traffic uses, under another name, could be either, so it's for a person to look at.
    return "attack" if item.threat_ids and not on_path else "unknown"


def newly_stopped(before: Environment, after: Environment, item: ObservedTraffic) -> bool:
    """Did the change add a way to stop these sessions? Traffic already at risk on one rule can still gain another."""
    now, was = traffic_action(after, item), traffic_action(before, item)
    if now == "allow":
        return False
    if traffic_kind(before, item) == "attack":
        return was == "allow"
    if now != was:
        return True
    if now == "drop":
        return False

    def resetting(environment: Environment) -> set[tuple[str, str]]:
        host = next(entry for entry in environment.hosts if entry.id == item.host)
        trips = [[threat_id] for threat_id in item.threat_ids]
        paths = reach(environment, item.source_zone, host)[0]
        return {rule for path in paths for rule in _rules_that_may_reset(environment, path, trips, host)}

    return bool(resetting(after) - resetting(before))


def traffic_dropped(
    before: Environment, after: Environment, traffic: list[ObservedTraffic]
) -> dict[str, list[ObservedTraffic]]:
    """What a change newly drops or resets, by kind."""
    dropped: dict[str, list[ObservedTraffic]] = {"needed": [], "attack": [], "unknown": []}
    for item in traffic:
        if newly_stopped(before, after, item):
            dropped[traffic_kind(before, item)].append(item)
    return dropped


def apply_change(environment: Environment, change: Change) -> None:
    """Edit the model. This is the only state change in the flow, and it only ever touches this simulation."""
    if change.kind in ("block_threats", "add_deny_rule"):
        device = next(item for item in environment.devices if item.id == change.target)
        if change.kind == "add_deny_rule" and change.deny_rule:
            device.rules.insert(0, change.deny_rule)
            return
        for rule in device.rules:
            if rule.name in change.rules:
                # A rule keeps the profile it has, so what that profile already blocks stays blocked.
                profile = rule.vulnerability_profile or change.profile or DEFAULT_PROFILE
                blocked = device.vulnerability_profiles.setdefault(profile, [])
                blocked.extend(item for item in change.threat_ids if item not in blocked)
                rule.vulnerability_profile = profile
        return
    host = next(item for item in environment.hosts if item.id == change.target)
    key = change.setting or change.mitigation_id
    if change.kind == "stop_service":
        service = (change.service or change.mitigation_id).lower()
        host.services[service] = "stopped"
        host.processes = [item for item in host.processes if _program_name(item) != _program_name(service)]
        key = f"service {service} stopped"
    if change.kind in ("stop_service", "set_host_control"):
        host.host_controls[key] = sorted({*host.host_controls.get(key, []), *change.cve_ids})


def _not_stopped(tags: list[TaggedFinding]) -> set[tuple[str, str]]:
    """A pair that went from exposed to unknown isn't protected: the change only took away what could be proven."""
    return {(item.cve, item.host) for item in tags if item.exposed or item.tag == "unknown"}


def _pair(item: TaggedFinding) -> str:
    return f"{item.cve} on {item.host}"


def _block_threat_changes(
    environment: Environment, mitigation: FlowMitigation, exposed: list[TaggedFinding]
) -> tuple[list[Change], list[str]]:
    """Attach a blocking profile to every Security rule on every open path, on one device per path."""
    by_host = {host.id: host for host in environment.hosts}
    devices = {device.id: device for device in environment.devices}
    rules_by_device: dict[str, set[str]] = {}
    uncovered: set[str] = set()
    for item in exposed:
        host = by_host[item.host]
        for vantage in _vantages(environment) if item.access_vector != "adjacent" else [host.zone or ""]:
            for path in reach(environment, vantage, host)[0]:
                usable = [
                    hop
                    for hop in path
                    if devices[hop.device].threat_prevention
                    and (mitigation.fw_type is None or devices[hop.device].fw_type == mitigation.fw_type)
                ]
                if not usable:
                    uncovered.add(item.host)
                    continue
                hop = usable[-1]  # the device nearest the host also covers east-west traffic through it
                through = _rules_letting_through(devices[hop.device], hop.from_zone, hop.to_zone, host)
                rules_by_device.setdefault(hop.device, set()).update(rule.name for rule in through)
    changes: list[Change] = []
    for device_id, rules in sorted(rules_by_device.items()):
        ordered = sorted(rules)
        current = {rule.name: rule.vulnerability_profile for rule in devices[device_id].rules}
        profiles = sorted({current.get(rule) or DEFAULT_PROFILE for rule in ordered})
        preview = [
            f"set profiles vulnerability {profile} threat-exception {threat} action reset-both"
            for profile in profiles
            for threat in mitigation.threat_ids
        ]
        preview += [
            f"set rulebase security rules {rule} profile-setting profiles vulnerability {DEFAULT_PROFILE}"
            for rule in ordered
            if not current.get(rule)
        ]
        changes.append(
            Change(
                kind="block_threats",
                target=device_id,
                mitigation_id=mitigation.id,
                threat_ids=mitigation.threat_ids,
                profile=DEFAULT_PROFILE,
                rules=ordered,
                cve_ids=mitigation.cve_ids,
                preview=preview,
            )
        )
    return changes, sorted(uncovered)


def _acl_changes(environment: Environment, mitigation: FlowMitigation, exposed: list[TaggedFinding]) -> list[Change]:
    """A deny rule on the device nearest the host, only for the zones that exposed it, so other zones still reach it."""
    by_host = {host.id: host for host in environment.hosts}
    devices = {device.id: device for device in environment.devices}
    hosts_by_device: dict[str, set[str]] = {}
    zones_by_device: dict[str, set[str]] = {}
    for item in exposed:
        host = by_host[item.host]
        for vantage in _vantages(environment):
            for path in reach(environment, vantage, host)[0]:
                usable = [
                    hop
                    for hop in path
                    if devices[hop.device].fw_type != ROUTER_TYPE
                    and (mitigation.fw_type is None or devices[hop.device].fw_type == mitigation.fw_type)
                ]
                if usable:
                    hosts_by_device.setdefault(usable[-1].device, set()).add(item.host)
                    zones_by_device.setdefault(usable[-1].device, set()).add(usable[-1].from_zone)
    changes: list[Change] = []
    for device_id, host_ids in sorted(hosts_by_device.items()):
        name = f"porygon-block-{mitigation.id}"
        zones = sorted(zones_by_device[device_id])
        rule = FirewallRule(name=name, from_zone=zones, destination=sorted(host_ids), action="deny")
        preview = [
            f"set rulebase security rules {name} from [ {' '.join(zones)} ] "
            f"destination [ {' '.join(sorted(host_ids))} ] action deny",
            f"move rulebase security rules {name} top",
        ]
        changes.append(
            Change(
                kind="add_deny_rule",
                target=device_id,
                mitigation_id=mitigation.id,
                deny_rule=rule,
                cve_ids=mitigation.cve_ids,
                preview=preview,
            )
        )
    return changes


def _host_changes(mitigation: FlowMitigation, exposed: list[TaggedFinding]) -> list[Change]:
    changes: list[Change] = []
    for host_id in sorted({item.host for item in exposed}):
        if mitigation.kind == "disable_service":
            changes.append(
                Change(
                    kind="stop_service",
                    target=host_id,
                    mitigation_id=mitigation.id,
                    service=mitigation.service,
                    cve_ids=mitigation.cve_ids,
                    preview=[f"stop and disable service {mitigation.service}"],
                )
            )
        else:
            changes.append(
                Change(
                    kind="set_host_control",
                    target=host_id,
                    mitigation_id=mitigation.id,
                    setting=mitigation.setting,
                    cve_ids=mitigation.cve_ids,
                    preview=[f"set {mitigation.setting}"],
                )
            )
    return changes


_LINUX_NAMES = ("linux", "ubuntu", "centos", "debian", "red hat", "rhel", "fedora", "suse", "alma", "rocky")


def _applies(mitigation: FlowMitigation, host: Host) -> bool:
    if not mitigation.os:
        return True
    wanted, name = mitigation.os.lower(), (host.os or "").lower()
    return any(item in name for item in _LINUX_NAMES) if wanted == "linux" else wanted in name


def _changes_for(
    environment: Environment, mitigation: FlowMitigation, exposed: list[TaggedFinding]
) -> tuple[list[Change], list[str]]:
    if mitigation.kind == "ips_threat_ids":
        return _block_threat_changes(environment, mitigation, exposed)
    if mitigation.kind == "acl_block":
        return _acl_changes(environment, mitigation, exposed), []
    return _host_changes(mitigation, exposed), []


def _editable_copy(environment: Environment, changes: list[Change]) -> Environment:
    """A copy to apply changes to. Findings aren't copied because apply_change never edits them, and thousands of
    them make a deep copy per candidate slow."""
    targets = {change.target for change in changes}
    hosts = [
        host.model_copy(update={"services": dict(host.services), "host_controls": dict(host.host_controls)})
        if host.id in targets
        else host
        for host in environment.hosts
    ]
    devices = [device.model_copy(deep=True) for device in environment.devices]
    return environment.model_copy(update={"hosts": hosts, "devices": devices})


def what_if(
    environment: Environment, mitigations: list[FlowMitigation], changes: list[Change], hosts: set[str] | None = None
) -> tuple[Environment, list[TaggedFinding], list[str]]:
    """Apply changes to a copy: the resulting environment, its tags, and the allowed flows it breaks."""
    copy = _editable_copy(environment, changes)
    for change in changes:
        apply_change(copy, change)
    broken = [
        flow.name
        for flow in environment.allowed_flows
        if flow_passes(environment, flow) and not flow_passes(copy, flow)
    ]
    return copy, tag_cves(copy, mitigations, hosts), broken


def match_mitigations(environment: Environment, mitigations: list[FlowMitigation]) -> list[Candidate]:
    """Each mitigation with the changes it needs here, what those would protect and what they would break.

    Effects come from simulating the change. A candidate is held when it would break allowed traffic, when nothing on
    the path can enforce it, or when it has nothing exposed to protect."""
    before = tag_cves(environment, mitigations)
    by_host = {host.id: host for host in environment.hosts}
    candidates: list[Candidate] = []
    for mitigation in mitigations:
        wanted = set(mitigation.cve_ids)
        exposed = [
            item for item in before if item.cve in wanted and item.exposed and _applies(mitigation, by_host[item.host])
        ]
        changes, uncovered = _changes_for(environment, mitigation, exposed)
        changed, after, broken = what_if(environment, mitigations, changes, {item.host for item in exposed})
        seen = [item for item in environment.observed_traffic if not item.only_after_change]
        dropped = traffic_dropped(environment, changed, seen)
        still_exposed = _not_stopped(after)
        protected = [item for item in exposed if (item.cve, item.host) not in still_exposed]
        # Closing a host stops every CVE on it, not only the ones the mitigation was written for.
        touched = {item.host for item in exposed}
        stopped = [
            item
            for item in before
            if item.exposed and item.host in touched and (item.cve, item.host) not in still_exposed
        ]
        left_open = [item for item in exposed if (item.cve, item.host) in still_exposed]
        reasons: list[str] = []
        if not exposed:
            reasons.append("Nothing it covers is exposed here.")
        elif mitigation.kind == "ips_threat_ids" and environment.model_converted:
            reasons.append("A model converted these rules, so a signature on them can't count as protection.")
        elif not changes:
            reasons.append(f"No {mitigation.fw_type or 'capable'} device is on the path to enforce it.")
        elif not protected:
            reasons.append(f"It wouldn't stop any of the {len(exposed)} exposed findings it covers here.")
        elif left_open:
            reasons.append(
                f"It leaves {len(left_open)} of {len(exposed)} exposed findings open, such as {_pair(left_open[0])}."
            )
        if uncovered:
            reasons.append(f"No capable device on some paths to: {', '.join(uncovered)}.")
        touched_hosts = {*touched, *(change.target for change in changes if change.target in by_host)}
        guessed = sorted(name for name in touched_hosts if by_host[name].placed_by == "model")
        if guessed:
            reasons.append(f"A model guessed where {', '.join(guessed)} sits, so a person has to confirm that first.")
        if broken:
            reasons.append(f"Would break allowed traffic: {', '.join(broken)}.")
        false_alarms = [item.name for item in dropped["needed"] if item.name not in broken]
        if false_alarms:
            reasons.append(f"Would drop needed traffic seen at the firewall: {', '.join(false_alarms)}.")
        candidates.append(
            Candidate(
                mitigation_id=mitigation.id,
                title=mitigation.title,
                kind=mitigation.kind,
                status="hold" if reasons else "proceed",
                hold_reasons=reasons,
                risk=mitigation.risk,
                changes=changes,
                protects=sorted(_pair(item) for item in stopped),
                protects_kev=sum(counts_as_known_exploited(item) for item in stopped),
                breaks_flows=broken,
                drops_traffic=sorted(item.name for item in [*dropped["needed"], *dropped["unknown"]]),
                side_effects=mitigation.side_effects,
                rollback=mitigation.rollback,
                source_url=mitigation.source_url,
            )
        )
    candidates.sort(
        key=lambda item: (
            item.status != "proceed",
            -item.protects_kev,
            -len(item.protects),
            item.risk,
            item.mitigation_id,
        )
    )
    return candidates


_NO_PUBLIC_IMAGE = "Out of support, so no public image: clone your own"
_IMAGES: tuple[tuple[str, str], ...] = (
    *(
        (name, _NO_PUBLIC_IMAGE)
        for name in (
            "windows server 2003",
            "windows server 2008",
            "windows server 2012",
            "windows 2008",
            "windows 2003",
            "windows xp",
            "windows vista",
            "windows 7",
            "windows 8",
            "centos linux",
        )
    ),
    ("windows server", "Windows Server evaluation image"),
    ("windows", "Windows client evaluation image"),
    ("ubuntu", "Ubuntu cloud image"),
    ("centos", "CentOS Stream cloud image"),
    ("red hat", "RHEL developer image"),
    ("rhel", "RHEL developer image"),
    ("debian", "Debian cloud image"),
)
_FIREWALL_IMAGES = {"PaloAltoNGFW": "Palo Alto VM-Series evaluation image"}


def _tests_first(environment: Environment, changes: list[Change], protected: set[str]) -> list[ImageTest]:
    """A clean image of what each change runs on, so it can be tried off production. See docs/testing-on-images.md."""
    by_os: dict[str, set[str]] = {}
    images: dict[str, str] = {}
    for host in environment.hosts:
        if host.id not in protected:
            continue
        name = host.os or "Unknown OS"
        by_os.setdefault(name, set()).add(host.id)
        images[name] = next((image for key, image in _IMAGES if key in name.lower()), "No public image known: clone it")
    changed = {change.target for change in changes}
    for device in environment.devices:
        if device.id in changed:
            name = f"{device.fw_type} {device.version or ''}".strip()
            by_os.setdefault(name, set()).add(device.id)
            images[name] = _FIREWALL_IMAGES.get(device.fw_type, "Ask the vendor for a lab image")
    return [ImageTest(runs_on=name, targets=sorted(by_os[name]), image=images[name]) for name in sorted(by_os)]


def _impact(environment: Environment, mitigation: FlowMitigation, candidate: Candidate) -> ChangeImpact:
    """Traffic crossing a changed rule isn't broken, but it's what a false positive there would hit, so a person should
    see it before approving."""
    device_ids = {device.id for device in environment.devices}
    devices = sorted({change.target for change in candidate.changes if change.target in device_ids})
    hosts_changed = sorted({change.target for change in candidate.changes if change.target not in device_ids})
    touched: set[tuple[str, str]] = set()
    denied: set[tuple[str, str]] = set()
    for change in candidate.changes:
        touched |= {(change.target, rule) for rule in change.rules}
        device = next((item for item in environment.devices if item.id == change.target), None)
        if device:
            # A signature added to a profile changes what every rule using that profile blocks.
            shared = {rule.vulnerability_profile for rule in device.rules if rule.name in change.rules} - {None}
            touched |= {(device.id, rule.name) for rule in device.rules if rule.vulnerability_profile in shared}
        if change.deny_rule:
            touched.add((change.target, change.deny_rule.name))
            denied |= {(change.target, host_id) for host_id in change.deny_rule.destination}
    by_id = {host.id: host for host in environment.hosts}
    crossing = []
    for flow in environment.allowed_flows:
        host = by_id.get(flow.host)
        if host is None:
            continue
        paths = reach(environment, flow.source_zone, host)[0]
        crosses = any(
            (hop.device, hop.rule or "") in touched or (hop.device, flow.host) in denied
            for path in paths
            for hop in path
        )
        if crosses or flow.host in hosts_changed:
            crossing.append(flow.name)
    return ChangeImpact(
        mitigation_id=mitigation.id,
        title=mitigation.title,
        kind=mitigation.kind,
        risk=mitigation.risk,
        devices=devices,
        hosts_changed=hosts_changed,
        rules=sorted(f"{device}: {rule}" for device, rule in touched),
        hosts_protected=sorted({pair.partition(" on ")[2] for pair in candidate.protects}),
        protects=len(candidate.protects),
        protects_kev=candidate.protects_kev,
        traffic_crossing=sorted(crossing),
        breaks=candidate.breaks_flows,
        side_effects=mitigation.side_effects,
        rollback=mitigation.rollback,
        source_url=mitigation.source_url,
    )


def _counts_in_funnel(item: TaggedFinding) -> bool:
    """The pairs the funnel's KEV rows count, so a recommendation and the funnel always talk about the same thing."""
    return item.kev and item.severity == "critical" and item.access_vector in ("network", "unknown")


def _gain(covered: set[str], kev: set[str], item: Candidate) -> tuple[int, int, int, bool, str]:
    new = set(item.protects) - covered
    return (-len(new & kev), -len(new), item.risk, item.kind == "host_setting", item.mitigation_id)


def _without_redundant(picked: list[Candidate]) -> list[Candidate]:
    """A later pick can make an earlier one unnecessary. Greedy picks aren't always the smallest set, but this helps."""
    kept = list(picked)
    for item in picked:
        others = [other for other in kept if other is not item]
        if set(item.protects) <= {pair for other in others for pair in other.protects}:
            kept = others
    return kept


def recommend(
    environment: Environment, mitigations: list[FlowMitigation], candidates: list[Candidate] | None = None
) -> Recommendation:
    """Which mitigations to propose: as few as it can find that stop known-exploited findings without breaking
    anything. One that stops none of them is left out. Each pick is the one adding the most critical KEV pairs, then the
    most pairs, then the least risk, with firewall changes before host changes since they change nothing on it."""
    tags = tag_cves(environment, mitigations)
    kev = {_pair(item) for item in tags if item.exposed and _counts_in_funnel(item)}
    known = {_pair(item) for item in tags if item.exposed and counts_as_known_exploited(item)}
    found = match_mitigations(environment, mitigations) if candidates is None else candidates
    not_selected = {item.mitigation_id: " ".join(item.hold_reasons) for item in found if item.status != "proceed"}
    ready = [item for item in found if item.status == "proceed"]
    remaining = [item for item in ready if set(item.protects) & known]
    for item in ready:
        if item not in remaining:
            not_selected[item.mitigation_id] = "It stops no known-exploited finding, so the plan leaves it out."
    covered: set[str] = set()
    picked: list[Candidate] = []
    while remaining:
        best = min(remaining, key=partial(_gain, covered, kev))
        remaining.remove(best)
        if set(best.protects) - covered:
            covered |= set(best.protects)
            picked.append(best)
        else:
            not_selected[best.mitigation_id] = "What it protects is already covered by the ones picked."
    kept = _without_redundant(picked)
    for item in picked:
        if item not in kept:
            not_selected[item.mitigation_id] = "What it protects is already covered by the ones picked."
    selected: list[RecommendedMitigation] = []
    changes: list[Change] = []
    covered = set()
    for item in kept:
        new = set(item.protects) - covered
        covered |= new
        changes += item.changes
        adds_kev = len(new & kev)
        how = "no change on the machine" if item.kind in ("ips_threat_ids", "acl_block") else "a change on the machine"
        selected.append(
            RecommendedMitigation(
                mitigation_id=item.mitigation_id,
                title=item.title,
                kind=item.kind,
                why=f"Stops {len(new)} more exposed, {len(new & known)} known exploited and {adds_kev} of those "
                f"critical, with {how}.",
                adds=len(new),
                adds_kev=adds_kev,
            )
        )
    _, after, broken = what_if(environment, mitigations, changes) if changes else (environment, tags, [])
    still = _not_stopped(after)
    left = sorted(pair for pair in known if tuple(pair.split(" on ", 1)) in still)
    held = []
    for item in found:
        if item.status == "proceed":
            continue
        would_stop = set(item.protects) & set(left)
        if item.changes:
            _, alone, _ = what_if(environment, mitigations, item.changes)
            open_alone = _not_stopped(alone)
            would_stop |= {pair for pair in left if tuple(pair.split(" on ", 1)) not in open_alone}
        if would_stop:
            held.append(
                HeldOption(
                    mitigation_id=item.mitigation_id,
                    title=item.title,
                    would_stop=sorted(would_stop),
                    why_held=" ".join(item.hold_reasons),
                )
            )
    option_exists = {pair for item in held for pair in item.would_stop}
    return Recommendation(
        selected=selected,
        not_selected=not_selected,
        kev_exposed_now=funnel(tags).kev_exposed,
        kev_exposed_after=funnel(after).kev_exposed,
        left_exposed=left,
        no_option=[pair for pair in left if pair not in option_exists],
        held_options=held,
        reachable_after=reachable_left_open(after),
        other_exposed_after=sum(item.exposed and not counts_as_known_exploited(item) for item in after),
        breaks=broken,
    )


def _plan_digest(plan: Plan) -> str:
    return canonical_hash(plan.model_dump(mode="json", exclude={"plan_hash"}))


def plan_change(
    environment: Environment, mitigations: list[FlowMitigation], selected: list[str], accept_holds: bool = False
) -> Plan:
    """The exact changes for the selected mitigations, bound to this environment by hash. A held mitigation only gets
    planned when the caller accepts its holds, and they're then part of what the person approves."""
    candidates = {item.mitigation_id: item for item in match_mitigations(environment, mitigations)}
    selected = list(dict.fromkeys(selected))
    unknown = [item for item in selected if item not in candidates]
    if unknown:
        raise ValueError(f"unknown mitigation ids: {', '.join(unknown)}")
    changes = [change for mitigation_id in selected for change in candidates[mitigation_id].changes]
    if not changes:
        raise ValueError("nothing to apply: the selected mitigations need no change here")
    holds = [f"{item}: {reason}" for item in selected for reason in candidates[item].hold_reasons]
    if holds and not accept_holds:
        raise ValueError(f"held, and not accepted: {' '.join(holds)}")
    before_tags = tag_cves(environment, mitigations)
    _, after_tags, broken = what_if(environment, mitigations, changes)
    still_exposed = _not_stopped(after_tags)
    protects = sorted(
        _pair(item) for item in before_tags if item.exposed and (item.cve, item.host) not in still_exposed
    )
    if not protects:
        raise ValueError("nothing to apply: the selected mitigations wouldn't stop any exposure here")
    by_id = {item.id: item for item in mitigations}
    plan = Plan(
        plan_hash="",
        environment_hash=environment_hash(environment),
        mitigations_hash=mitigations_hash(mitigations),
        label=environment.label,
        mitigation_ids=selected,
        changes=changes,
        expected_protects=protects,
        expected_breaks=broken,
        hold_reasons=holds,
        impact=[_impact(environment, by_id[item], candidates[item]) for item in selected],
        test_first=_tests_first(environment, changes, {pair.partition(" on ")[2] for pair in protects}),
        before=funnel(before_tags),
        expected_after=funnel(after_tags),
    )
    plan.plan_hash = _plan_digest(plan)
    return plan


def apply_plan(environment: Environment, plan: Plan, approved_hash: str) -> Environment:
    """The approval gate: the plan must be the one that was approved, for the environment it was computed on."""
    if approved_hash != plan.plan_hash:
        raise ValueError("the approved hash doesn't match this plan")
    if environment_hash(environment) != plan.environment_hash:
        raise ValueError("the environment changed after this plan was made; plan again")
    if _plan_digest(plan) != plan.plan_hash:
        raise ValueError("this plan was edited after it was made")
    updated = environment.model_copy(deep=True)
    for change in plan.changes:
        apply_change(updated, change)
    return updated


def _changed_besides_the_plan(baseline: Environment, current: Environment, plan: Plan) -> list[str]:
    """What differs from the baseline with exactly this plan applied. Nothing else writes to the model, so anything here
    was changed by hand, and a tag can't see all of it: a forged control, a deleted finding."""
    expected = baseline.model_copy(deep=True)
    for change in plan.changes:
        apply_change(expected, change)
    if environment_hash(expected) == environment_hash(current):
        return []
    differences: list[str] = []
    for kind, left, right in (
        ("zone", {item.id: item for item in expected.zones}, {item.id: item for item in current.zones}),
        ("device", {item.id: item for item in expected.devices}, {item.id: item for item in current.devices}),
        ("host", {item.id: item for item in expected.hosts}, {item.id: item for item in current.hosts}),
        (
            "allowed flow",
            {item.name: item for item in expected.allowed_flows},
            {item.name: item for item in current.allowed_flows},
        ),
    ):
        differences += [f"{kind} {name}" for name in sorted({*left, *right}) if left.get(name) != right.get(name)]
    return differences or ["the file's other fields"]


def verify(baseline: Environment, current: Environment, mitigations: list[FlowMitigation], plan: Plan) -> Verification:
    """Recompute from the changed environment instead of trusting the plan, and report anything that differs."""
    before_tags = tag_cves(baseline, mitigations)
    after_tags = tag_cves(current, mitigations)
    exposed_before = {(item.cve, item.host) for item in before_tags if item.exposed}
    exposed_after = {(item.cve, item.host) for item in after_tags if item.exposed}
    not_stopped = _not_stopped(after_tags)
    checks: list[FlowCheck] = []
    for pair in plan.expected_protects:
        cve, _, host = pair.partition(" on ")
        ok = (cve, host) not in not_stopped
        checks.append(
            FlowCheck(
                name=f"no longer exposed: {pair}",
                passed=ok,
                detail="In the simulation, the path is closed or something on it stops the exploit."
                if ok
                else "Still exposed after the change.",
            )
        )
    new_exposure = sorted(exposed_after - exposed_before)
    checks.append(
        FlowCheck(
            name="no new exposure",
            passed=not new_exposure,
            detail=", ".join(f"{cve} on {host}" for cve, host in new_exposure) or "None.",
        )
    )
    inputs_match = (
        _plan_digest(plan) == plan.plan_hash
        and environment_hash(baseline) == plan.environment_hash
        and mitigations_hash(mitigations) == plan.mitigations_hash
    )
    checks.append(
        FlowCheck(
            name="the inputs the plan was made on",
            passed=inputs_match,
            detail="Unchanged." if inputs_match else "The plan, baseline or mitigations aren't the original ones.",
        )
    )
    changed = _changed_besides_the_plan(baseline, current, plan)
    shown = ", ".join(changed[:MAX_REPORTED_PROBLEMS])
    checks.append(
        FlowCheck(
            name="only the planned changes",
            passed=not changed,
            detail=f"Also changed: {shown}." if changed else "Nothing else changed.",
        )
    )
    planned_breaks: list[str] = []
    for flow in baseline.allowed_flows:
        if flow_passes(baseline, flow):
            ok = flow_passes(current, flow)
            expected_break = flow.name in plan.expected_breaks
            if expected_break and not ok:
                planned_breaks.append(flow.name)
            checks.append(
                FlowCheck(
                    name=f"allowed traffic: {flow.name}",
                    passed=ok or expected_break,
                    detail="Still passes."
                    if ok
                    else "BROKEN, as the approved plan said it would be."
                    if expected_break
                    else "Blocked, which the plan did not predict.",
                )
            )
    return Verification(
        plan_hash=plan.plan_hash,
        mitigation_ids=plan.mitigation_ids,
        passed=all(check.passed for check in checks),
        before=funnel(before_tags),
        after=funnel(after_tags),
        checks=checks,
        planned_breaks=planned_breaks,
    )
