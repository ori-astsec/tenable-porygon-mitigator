"""Collect what a PAN-OS firewall really enforces and write it as the flow's firewall export.

Answers, per CVE: is a signature installed (the content version's predefined vulnerability threats), would a
vulnerability profile block it, is that profile attached to an allow rule, and has it fired (threat logs). The export
has the same shape as `flow/sources` firewall files, plus an `ips` section with those answers.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from datetime import UTC, datetime
from typing import Any

from porygon_mitigator.integrations.panos.client import PanosClient, PanosError, first_child_tag, members, text

DEVICE = "/config/devices/entry[@name='localhost.localdomain']"
SHARED = "/config/shared"
SIGNATURES_CMD = "<show><predefined><xpath>/predefined/threats/vulnerability</xpath></predefined></show>"
SYSTEM_INFO_CMD = "<show><system><info></info></system></show>"
ROUTES_CMD = "<show><routing><route></route></routing></show>"
RESOURCES_CMD = ("<show><running><resource-monitor><minute><last>15</last></minute></resource-monitor>"
                 "</running></show>")
VULNERABILITY_LOG_QUERY = "(subtype eq vulnerability)"
BLOCKING_ACTIONS = {"drop", "reset-client", "reset-server", "reset-both", "block-ip"}
ZONE_LAYERS = ("layer3", "layer2", "virtual-wire", "tap")
# What a rule holds that says nothing about which traffic it matches, or that the flow reads itself.
_RULE_FIELDS_READ = frozenset(
    {
        "from",
        "to",
        "source",
        "destination",
        "application",
        "service",
        "action",
        "disabled",
        "negate-source",
        "negate-destination",
        "profile-setting",
        "description",
        "tag",
        "group-tag",
        "log-setting",
        "log-start",
        "log-end",
        "option",
        "qos",
        "disable-inspect",
        "icmp-unreachable",
    }
)
_TRAILING_ID = re.compile(r"\((\d+)\)\s*$")


def _entries(element: ET.Element | None) -> list[ET.Element]:
    return [] if element is None else list(element.iterfind("entry"))


def parse_signatures(root: ET.Element) -> dict[str, dict[str, Any]]:
    """Predefined vulnerability threats: threat ID -> name, severity, CVEs, default action, host side."""
    signatures: dict[str, dict[str, Any]] = {}
    for entry in root.iter("entry"):
        name = entry.findtext("threatname")
        if name is None or not entry.get("name"):
            continue
        signatures[entry.get("name", "")] = {
            "name": name.strip(),
            "severity": text(entry, "severity"),
            "category": text(entry, "category"),
            "cves": sorted({cve.upper() for cve in members(entry, "cve") if cve}),
            "default_action": text(entry, "default-action") or "alert",
            "client": text(entry, "affected-host/client") == "yes",
            "server": text(entry, "affected-host/server") == "yes",
        }
    return signatures


def _rule_matches(rule: ET.Element, signature: dict[str, Any]) -> bool:
    threat_name = text(rule, "threat-name", "any")
    if threat_name != "any" and threat_name.lower() not in signature["name"].lower():
        return False
    cves = members(rule, "cve") or ["any"]
    if "any" not in cves and not set(cves) & set(signature["cves"]):
        return False
    host = text(rule, "host", "any")
    if host in ("client", "server") and not signature[host]:
        return False
    category = text(rule, "category", "any")
    if category != "any" and category != signature["category"]:
        return False
    severities = members(rule, "severity") or ["any"]
    return "any" in severities or signature["severity"] in severities


def profile_actions(profile: ET.Element, signatures: dict[str, dict[str, Any]]) -> dict[str, str]:
    """The action a vulnerability profile takes on each signature: its first matching rule, a threat exception
    overriding it, and `default` resolved to the signature's own default action. Signatures no rule matches aren't
    inspected by this profile."""
    rules = _entries(profile.find("rules"))
    actions: dict[str, str] = {}
    for threat_id, signature in signatures.items():
        for rule in rules:
            if _rule_matches(rule, signature):
                actions[threat_id] = first_child_tag(rule, "action") or "default"
                break
    for exception in _entries(profile.find("threat-exception")):
        actions[exception.get("name", "")] = first_child_tag(exception, "action") or "default"
    return {
        threat_id: signatures.get(threat_id, {}).get("default_action", "alert") if action == "default" else action
        for threat_id, action in actions.items()
    }


def _address_objects(*roots: ET.Element | None) -> dict[str, dict[str, str]]:
    found: dict[str, dict[str, str]] = {}
    for root in roots:
        for entry in _entries(root):
            for kind in ("ip-netmask", "fqdn", "ip-range"):
                if entry.findtext(kind):
                    found[entry.get("name", "")] = {kind.replace("-", "_"): text(entry, kind)}
    return found


def _service_objects(*roots: ET.Element | None) -> dict[str, dict[str, str]]:
    found: dict[str, dict[str, str]] = {}
    for root in roots:
        for entry in _entries(root):
            for protocol in ("tcp", "udp"):
                port = entry.findtext(f"protocol/{protocol}/port")
                if port:
                    found[entry.get("name", "")] = {"port": port.strip(), "protocol": protocol}
    return found


def _groups(root: ET.Element | None, tag: str) -> dict[str, list[str]]:
    return {entry.get("name", ""): members(entry, tag) for entry in _entries(root)}


def _limits(entry: ET.Element) -> list[str]:
    """Anything else on a rule that may narrow it, known or not: a deny with one of these doesn't close a host."""
    limits = []
    for child in entry:
        if child.tag in _RULE_FIELDS_READ:
            continue
        if child.tag == "rule-type" and text(entry, "rule-type") == "universal":
            continue
        if child.tag == "target" and all(item.tag == "negate" for item in child):
            continue
        named = members(entry, child.tag)
        if named == ["any"] or (not len(child) and text(entry, child.tag) in ("", "any")):
            continue
        limits.append(child.tag)
    return limits


def _rule(entry: ET.Element, profile_groups: dict[str, str], rulebase: str) -> dict[str, Any]:
    profile = members(entry.find("profile-setting/profiles"), "vulnerability")
    group = members(entry.find("profile-setting"), "group")
    vulnerability = profile[0] if profile else profile_groups.get(group[0]) if group else None
    rule: dict[str, Any] = {
        "name": entry.get("name", ""),
        "rulebase": rulebase,
        "from": members(entry, "from") or ["any"],
        "to": members(entry, "to") or ["any"],
        "source": members(entry, "source") or ["any"],
        "destination": members(entry, "destination") or ["any"],
        "application": members(entry, "application") or ["any"],
        "service": members(entry, "service") or ["any"],
        "action": text(entry, "action", "allow"),
        "disabled": text(entry, "disabled") == "yes",
        "negate_source": text(entry, "negate-source") == "yes",
        "negate_destination": text(entry, "negate-destination") == "yes",
    }
    if vulnerability:
        rule["profile_setting"] = {"vulnerability": vulnerability}
    limited_by = _limits(entry)
    if limited_by:
        rule["limited_by"] = limited_by
    return rule


def _zones(root: ET.Element | None) -> list[dict[str, Any]]:
    zones = []
    for entry in _entries(root):
        interfaces = next((members(entry.find("network"), layer) for layer in ZONE_LAYERS
                           if entry.find(f"network/{layer}") is not None), [])
        zones.append({"name": entry.get("name", ""), "display_name": entry.get("name", ""), "interfaces": interfaces,
                      "kind": "unknown", "cidrs": [], "attacker_vantage": None})
    return zones


def _routes(root: ET.Element, zones: list[dict[str, Any]]) -> list[dict[str, Any]]:
    zone_of = {interface: zone["name"] for zone in zones for interface in zone["interfaces"]}
    routes = []
    for entry in root.iter("entry"):
        destination = entry.findtext("destination")
        if destination is None or "A" not in text(entry, "flags").split():
            continue
        routes.append({"destination": destination.strip(), "nexthop": text(entry, "nexthop"),
                       "interface": text(entry, "interface"), "zone": zone_of.get(text(entry, "interface")),
                       "nexthop_device": None})
    return routes


def _threat_id(entry: ET.Element) -> str:
    if entry.findtext("tid"):
        return text(entry, "tid")
    found = _TRAILING_ID.search(text(entry, "threatid"))
    return found.group(1) if found else ""


def summarize_hits(entries: list[ET.Element]) -> dict[str, dict[str, Any]]:
    """Threat-log entries per threat ID: how often it fired and what the firewall did."""
    actions: dict[str, Counter[str]] = defaultdict(Counter)
    for entry in entries:
        threat_id = _threat_id(entry)
        if threat_id:
            actions[threat_id][text(entry, "action", "unknown")] += int(text(entry, "repeatcnt", "1") or 1)
    return {threat_id: {"count": sum(counts.values()), "blocked": sum(n for action, n in counts.items()
                                                                       if action in BLOCKING_ACTIONS),
                        "actions": dict(counts)} for threat_id, counts in sorted(actions.items())}


def _dataplane_cpu(root: ET.Element) -> float | None:
    values = [int(item) for node in root.iter("value") for item in (node.text or "").split(",")
              if item.strip().isdigit()]
    return round(sum(values) / len(values), 1) if values else None


async def _optional(notes: list[str], label: str, call: Any) -> Any:
    try:
        return await call
    except PanosError as error:
        notes.append(f"{label}: not collected ({error})")
        return None


async def collect(client: PanosClient, *, vsys: str = "vsys1", panorama: PanosClient | None = None,
                  device_group: str | None = None, read_logs: bool = True) -> dict[str, Any]:
    """One firewall's export. With `panorama` and `device_group`, the device group's pre- and post-rules wrap the
    firewall's own rules in PAN-OS evaluation order, and its profiles and objects are included."""
    notes: list[str] = []
    base = f"{DEVICE}/vsys/entry[@name='{vsys}']"
    info = (await client.op(SYSTEM_INFO_CMD)).find("result/system")
    signatures = parse_signatures(await client.op(SIGNATURES_CMD))
    group_base = f"{DEVICE}/device-group/entry[@name='{device_group}']" if device_group else None
    group_reader = panorama if panorama and group_base else None

    async def read(path: str, *, from_group: bool = False) -> ET.Element | None:
        if from_group:
            if group_reader is None or group_base is None:
                return None
            return await group_reader.config(f"{group_base}/{path}")
        return await client.config(f"{base}/{path}")

    profiles_xml = [await client.config(f"{SHARED}/profiles/vulnerability"), await read("profiles/vulnerability"),
                    await read("profiles/vulnerability", from_group=True)]
    profile_group_xml = [await read("profile-group"), await read("profile-group", from_group=True)]
    profile_groups = {name: values[0] for root in profile_group_xml for name, values in _groups(root, "vulnerability")
                      .items() if values}
    rules = [
        *[_rule(entry, profile_groups, "pre") for entry in
          _entries(await read("pre-rulebase/security/rules", from_group=True))],
        *[_rule(entry, profile_groups, "local") for entry in _entries(await read("rulebase/security/rules"))],
        *[_rule(entry, profile_groups, "post") for entry in
          _entries(await read("post-rulebase/security/rules", from_group=True))],
    ]
    zones = _zones(await read("zone"))
    routes_xml = await _optional(notes, "routes", client.op(ROUTES_CMD))
    profiles: dict[str, dict[str, Any]] = {}
    for root in profiles_xml:
        for entry in _entries(root):
            actions = profile_actions(entry, signatures)
            profiles[entry.get("name", "")] = {
                "threat_exceptions": sorted(item.get("name", "") for item in _entries(entry.find("threat-exception"))),
                "blocked_threat_ids": sorted((tid for tid, action in actions.items() if action in BLOCKING_ACTIONS),
                                             key=int),
                "alerted_threat_ids": sorted((tid for tid, action in actions.items() if action == "alert"), key=int),
            }
    hits: dict[str, dict[str, Any]] = {}
    if read_logs:
        entries = await _optional(notes, "threat logs", client.logs("threat", VULNERABILITY_LOG_QUERY))
        hits = summarize_hits(entries or [])
    resources = await _optional(notes, "dataplane load", client.op(RESOURCES_CMD))
    content = text(info, "threat-version")
    return {
        "hostname": text(info, "hostname", client.host),
        "display_name": f"{text(info, 'model', 'PAN-OS')} {text(info, 'hostname')}".strip(),
        "type": "PaloAltoNGFW",
        "sw_version": text(info, "sw-version"),
        "threat_prevention_license": bool(content) and content != "0",
        "zones": zones,
        "virtual_router": {"name": "runtime", "routes": _routes(routes_xml, zones) if routes_xml is not None else []},
        "address_objects": _address_objects(await client.config(f"{SHARED}/address"), await read("address"),
                                            await read("address", from_group=True)),
        "address_groups": {**_groups(await read("address-group"), "static"),
                           **_groups(await read("address-group", from_group=True), "static")},
        "service_objects": _service_objects(await client.config(f"{SHARED}/service"), await read("service"),
                                            await read("service", from_group=True)),
        "service_groups": {**_groups(await read("service-group"), "members"),
                           **_groups(await read("service-group", from_group=True), "members")},
        "security_rules": rules,
        "vulnerability_profiles": profiles,
        "ips": {
            "content_version": content,
            "signatures_installed": len(signatures),
            "signatures": {tid: sig for tid, sig in signatures.items() if sig["cves"]},
            "hits": hits,
            "dataplane_cpu_avg_percent": _dataplane_cpu(resources) if resources is not None else None,
        },
        "collection": {
            "source": "PAN-OS XML API (read-only)",
            "host": client.host,
            "target": client.target,
            "vsys": vsys,
            "device_group": device_group,
            "collected_at": datetime.now(UTC).isoformat(timespec="seconds"),
            "notes": notes,
        },
    }


def cve_coverage(export: dict[str, Any], cves: list[str]) -> list[dict[str, Any]]:
    """Per CVE: its installed signatures, the profiles that block them, the enabled allow rules carrying those
    profiles, and threat-log hits. `enforced` needs all three: a signature, a blocking profile, a rule using it."""
    signatures = export["ips"]["signatures"]
    by_cve: dict[str, list[str]] = defaultdict(list)
    for threat_id, signature in signatures.items():
        for cve in signature["cves"]:
            by_cve[cve].append(threat_id)
    rules_by_profile: dict[str, list[str]] = defaultdict(list)
    for rule in export["security_rules"]:
        profile = (rule.get("profile_setting") or {}).get("vulnerability")
        if profile and rule["action"] == "allow" and not rule.get("disabled"):
            rules_by_profile[profile].append(rule["name"])
    rows = []
    for cve in cves:
        threat_ids = sorted(by_cve.get(cve.upper(), []), key=int)
        blocking = sorted(name for name, profile in export["vulnerability_profiles"].items()
                          if set(threat_ids) & set(profile["blocked_threat_ids"]))
        rules = sorted({rule for name in blocking for rule in rules_by_profile.get(name, [])})
        hits = [export["ips"]["hits"][tid] for tid in threat_ids if tid in export["ips"]["hits"]]
        rows.append({
            "cve": cve.upper(),
            "threat_ids": threat_ids,
            "installed": bool(threat_ids),
            "blocking_profiles": blocking,
            "enforcing_rules": rules,
            "enforced": bool(rules),
            "hits": sum(item["count"] for item in hits),
            "blocked_hits": sum(item["blocked"] for item in hits),
        })
    return rows
