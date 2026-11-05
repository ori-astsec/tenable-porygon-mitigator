"""Map a Tenable asset-export record (and the asset's vulnerability-export rows) to a MachineProfile.

Checked against the Tenable partner lab tenant (2026-11-03) for Windows, Ubuntu and FortiGate assets. Accepts the
export schema (v1 and v2: `operating_systems`, `network.open_ports`...) and the singular names of
`GET /assets/{uuid}` (`operating_system`, `system_type`, `fqdn`...); vulnerability rows carry `plugin.{id,cve}`,
`port.{port,protocol,service}`, `state` and `output`.
"""

from __future__ import annotations

import re
from typing import Any

from porygon_mitigator.integrations.tenable_one import plugin_outputs
from porygon_mitigator.models.machine import (
    ConfigState,
    Finding,
    MachineProfile,
    OpenPort,
    OSInfo,
    SecurityTool,
    Software,
)

_DISTROS: tuple[tuple[str, str], ...] = (
    ("ubuntu", "ubuntu"), ("debian", "debian"), ("red hat", "rhel"), ("rhel", "rhel"), ("centos", "centos"),
    ("rocky", "rocky"), ("alma", "almalinux"), ("suse", "suse"), ("amazon linux", "amazon"),
    ("oracle linux", "ol"), ("fedora", "fedora"), ("alpine", "alpine"),
)
_APPLIANCES: tuple[tuple[str, str, str], ...] = (
    ("pan-os", "panos", "Palo Alto Networks"), ("palo alto", "panos", "Palo Alto Networks"),
    ("fortios", "fortios", "Fortinet"), ("fortigate", "fortios", "Fortinet"),
    ("netscaler", "netscaler", "Citrix"), ("citrix adc", "netscaler", "Citrix"),
    ("check point gaia", "gaia", "Check Point"), ("threat defense", "ftd", "Cisco"),
    ("ios xe", "ios_xe", "Cisco"), ("ios-xe", "ios_xe", "Cisco"), ("adaptive security appliance", "asa", "Cisco"),
    ("cisco ios", "ios", "Cisco"), ("big-ip", "tmos", "F5"), ("tmos", "tmos", "F5"),
    ("junos", "junos", "Juniper Networks"), ("esxi", "esxi", "VMware"),
)
# When plugins disagree on a service: what is running now wins, then its disabled start type, then plain inactive.
_SERVICE_STATE_RANK = {"stopped": 0, "disabled": 1, "running": 2}
# Endpoint security products recognisable from installed software or connector names.
_TOOLS: tuple[tuple[str, str, str, str], ...] = (
    ("crowdstrike", "edr", "CrowdStrike", "Falcon"),
    ("sentinelone", "edr", "SentinelOne", "Singularity"),
    ("defender", "edr", "Microsoft", "Defender for Endpoint"),
    ("carbon_black", "edr", "VMware", "Carbon Black"),
    ("carbon black", "edr", "VMware", "Carbon Black"),
    ("cortex xdr", "edr", "Palo Alto Networks", "Cortex XDR"),
    ("traps", "edr", "Palo Alto Networks", "Cortex XDR"),
    ("sophos", "edr", "Sophos", "Intercept X"),
    ("trend micro", "av", "Trend Micro", "Apex One"),
    ("symantec endpoint", "av", "Broadcom", "Symantec Endpoint Protection"),
    ("cylance", "edr", "BlackBerry", "Cylance"),
    ("mcafee", "av", "Trellix", "Endpoint Security"),
    ("trellix", "edr", "Trellix", "Endpoint Security"),
)


def _first(*values: Any) -> str | None:
    for value in values:
        if isinstance(value, list) and value:
            return str(value[0])
        if isinstance(value, str) and value:
            return value
    return None


def os_info(names: list[str]) -> tuple[OSInfo, str | None]:
    """OS details and, for appliances, the vendor."""
    name = names[0] if names else ""
    lowered = name.lower()
    for needle, key, vendor in _APPLIANCES:
        if needle in lowered:
            # Gaia names lead with the Linux kernel ("Linux Kernel 3.10 on Check Point Gaia R81.20").
            pattern = r"\b(R\d+(?:\.\d+)*)" if key == "gaia" else r"(\d+(?:[.\-]\d+)+(?:-h\d+)?)"
            version = re.search(pattern, name)
            return OSInfo(platform="network_os", name=name, version=version.group(1) if version else None,
                          distribution=key), vendor
    if "windows" in lowered:
        build = re.search(r"\b(10\.0\.\d+(?:\.\d+)?)\b", name) or re.search(r"\bbuild\s+(\d+)", lowered)
        return OSInfo(platform="windows", name=name, version=build.group(1) if build else None,
                      distribution="windows"), None
    if any(word in lowered for word in ("mac os", "macos", "os x")):
        version = re.search(r"(\d+(?:\.\d+)+)", name)
        return OSInfo(platform="macos", name=name, version=version.group(1) if version else None,
                      distribution="macos"), None
    for needle, key in _DISTROS:
        if needle in lowered:
            version = re.search(r"(\d+(?:\.\d+)*)", lowered[lowered.find(needle):])
            kernel = re.search(r"\b(\d+\.\d+\.\d+-[\w.\-]+)\b", name)
            return OSInfo(platform="linux", name=name, version=version.group(1) if version else None,
                          distribution=key, kernel=kernel.group(1) if kernel else None), None
    if "linux" in lowered:
        return OSInfo(platform="linux", name=name), None
    return OSInfo(platform="other", name=name or None), None


def _tools(texts: list[str]) -> list[SecurityTool]:
    found: dict[str, SecurityTool] = {}
    for text in texts:
        lowered = text.lower().replace("_", " ")
        for needle, category, vendor, product in _TOOLS:
            if needle.replace("_", " ") in lowered and product not in found:
                found[product] = SecurityTool(category=category, vendor=vendor, product=product)  # type: ignore[arg-type]
    return list(found.values())


def profile_from_tenable(asset: dict[str, Any], findings: list[Any]) -> MachineProfile:
    raw_network = asset.get("network")
    network: dict[str, Any] = raw_network if isinstance(raw_network, dict) else {}
    # Exports use plural field names; GET /assets/{uuid} uses singular ones (operating_system, fqdn, ipv4...).
    name = (_first(asset.get("name"), network.get("fqdns"), asset.get("fqdns"), asset.get("fqdn"),
                   network.get("hostnames"), asset.get("hostnames"), asset.get("hostname"),
                   network.get("netbios_names"), asset.get("netbios_names"), asset.get("netbios_name"),
                   network.get("ipv4s"), asset.get("ipv4s"), asset.get("ipv4"), asset.get("id")) or "tenable-asset")
    os_names = [str(item) for item in asset.get("operating_systems") or asset.get("operating_system") or [] if item]
    os, vendor = os_info(os_names)

    software: list[Software] = []
    for cpe in asset.get("installed_software") or []:
        if isinstance(cpe, str) and cpe.startswith("cpe:"):
            software.append(Software(cpe=cpe))

    ports: dict[tuple[int, str], OpenPort] = {}
    for item in network.get("open_ports") or asset.get("open_ports") or []:
        if isinstance(item, dict) and str(item.get("port", "")).isdigit():
            key = (int(item["port"]), str(item.get("protocol") or "tcp").lower())
            ports[key] = OpenPort(port=key[0], protocol="udp" if key[1] == "udp" else "tcp",
                                  service_names=[str(s) for s in item.get("service_names") or []])

    found: list[Finding] = []
    services: dict[str, str] = {}
    for row in findings:
        if not isinstance(row, dict):
            continue
        plugin = row.get("plugin") or {}
        plugin_id = int(plugin.get("id") or 0)
        output = str(row.get("output") or "")
        if plugin_id in (22869, 20811, 83991) and output:
            software.extend(plugin_outputs.installed_software(plugin_id, output))
        if plugin_id in plugin_outputs.PORT_PLUGIN_IDS and output:
            for port in plugin_outputs.listening_ports(plugin_id, output):
                ports.setdefault((port.port, port.protocol), port)
        if plugin_id in (10456, 44401) and output:
            for service, service_state in plugin_outputs.service_states(plugin_id, output).items():
                if _SERVICE_STATE_RANK[service_state] >= _SERVICE_STATE_RANK.get(services.get(service, ""), 0):
                    services[service] = service_state
        state = str(row.get("state") or "OPEN").lower()
        port_info = row.get("port") or {}
        if str(port_info.get("port", "")).isdigit() and 0 < int(port_info["port"]) < 65536 and state != "fixed":
            key = (int(port_info["port"]), str(port_info.get("protocol") or "tcp").lower())
            service = str(port_info.get("service") or "")
            ports.setdefault(key, OpenPort(port=key[0], protocol="udp" if key[1] == "udp" else "tcp",
                                           service_names=[service] if service else []))
        for cve in plugin.get("cve") or []:
            if re.fullmatch(r"CVE-\d{4}-\d{4,}", str(cve)):
                found.append(Finding(
                    cve=str(cve), plugin_id=plugin_id or None,
                    port=int(port_info["port"]) if str(port_info.get("port", "")).isdigit() else None,
                    protocol=port_info.get("protocol"), source="tenable",
                    state=state if state in ("open", "reopened", "fixed") else "open",  # type: ignore[arg-type]
                ))

    tool_hints = [str(item) for item in asset.get("installed_software") or []]
    tool_hints += [s.product or "" for s in software]
    tool_hints += [str(source.get("name", "")) for source in asset.get("sources") or [] if isinstance(source, dict)]
    raw_ids = asset.get("third_party_ids")
    third_party: dict[str, Any] = raw_ids if isinstance(raw_ids, dict) else asset
    if any(third_party.get(key) for key in ("mcafee_epo_guid", "mcafee_epo_agent_guid")):
        tool_hints.append("mcafee")

    roles = [str(item) for item in asset.get("system_types") or asset.get("system_type") or asset.get("types") or []]
    exposed = asset.get("is_public")
    return MachineProfile(
        name=name,
        os=os,
        vendor=vendor,
        roles=roles,
        installed_software=software,
        open_ports=sorted(ports.values(), key=lambda p: (p.port, p.protocol)),
        internet_exposed=exposed if isinstance(exposed, bool) else None,
        network_path=[],
        security_tools=_tools(tool_hints),
        findings=found,
        config_state=ConfigState(services=services) if services else None,  # type: ignore[arg-type]
        source="tenable_one",
    )
