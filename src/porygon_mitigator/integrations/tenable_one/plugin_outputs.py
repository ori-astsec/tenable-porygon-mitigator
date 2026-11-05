"""Read machine facts out of Tenable enrichment plugin outputs (EXPERIMENTAL: formats follow Nessus plugin output
as commonly seen; validate each parser against lab data).

    22869  Software Enumeration (SSH)                 -> installed packages (dpkg / rpm)
    20811  Microsoft Windows Installed Software       -> installed programs
    83991  macOS Software Enumeration                 -> installed applications
    11219 / 14272 / 34220 / 14274 / 25221 / 34252  port scanners and listeners -> open ports
    10456 / 44401  Windows services (SMB / config)    -> service states
"""

from __future__ import annotations

import json
import re
from typing import Literal

from porygon_mitigator.models.actions import identifier
from porygon_mitigator.models.machine import OpenPort, Software

_DPKG = re.compile(r"^\s*ii\s+(\S+?)(?::\S+)?\s+(\S+)\s", re.MULTILINE)
_RPM = re.compile(
    r"^\s*([A-Za-z0-9_.+-]+?)-((?:\d+:)?[0-9][^-|\s]*-[^|\s]+?)(?:\.(?:x86_64|noarch|i686|aarch64))?(?:\||\s|$)",
    re.MULTILINE,
)
_WINDOWS_PROGRAM = re.compile(r"^\s*(.+?)\s+\[version\s+([^\]]+)\]", re.MULTILINE)
_MAC_APP = re.compile(r"(?ms)^\s*(?:Application Name|Name)\s*:\s*(.+?)\s*$.*?^\s*Version\s*:\s*(\S+)")
_PORT = re.compile(r"\b(\d{1,5})/(tcp|udp)\b", re.IGNORECASE)
_LISTEN = re.compile(r"listening on [\d.:*\[\]a-f]*:(\d{1,5}) \((tcp|udp)\)", re.IGNORECASE)
_SERVICE = re.compile(r"^\s*(\S[^:\n]{0,60}?)\s*:\s*(\S[^\n]*)$", re.MULTILINE)
_SERVICE_ENTRY = re.compile(r"^.*\[ (.+?) \]\s*$", re.MULTILINE)
_SERVICE_NAME = re.compile(r"^\s*Service name\s*:\s*(.+?)\s*$", re.MULTILINE)
_ACTIVE_SERVICES = "Active Services :"
_INACTIVE_SERVICES = "Inactive Services :"
PORT_PLUGIN_IDS = (11219, 14272, 34220, 14274, 25221, 34252)
_LISTENER_PROCESS = re.compile(r"Executable\s*:\s*([^\r\n]+?)\s*(?:$|\r?\n)|process '([^']+)'", re.MULTILINE)
_DISABLED_SERVICES = "The following services are disabled :"
_NEXT_START_TYPE = "The following services"


def installed_software(plugin_id: int, output: str) -> list[Software]:
    found: list[Software] = []
    if plugin_id == 22869:
        for name, version in _DPKG.findall(output):
            found.append(Software(product=name, package=name, version=version))
        if not found:
            for name, version in _RPM.findall(output):
                found.append(Software(product=name, package=name, version=version))
    elif plugin_id == 20811:
        for name, version in _WINDOWS_PROGRAM.findall(output):
            found.append(Software(product=name.strip(" -"), version=version.strip()))
    elif plugin_id == 83991:
        for name, version in _MAC_APP.findall(output):
            found.append(Software(product=name.strip(), version=version.strip()))
    return found


def _json_listeners(output: str) -> list[OpenPort] | None:
    """Ports from the JSON form of a port plugin (`{"listening": [...]}`), or None if the output isn't that form."""
    try:
        data = json.loads(output)
    except (ValueError, RecursionError):
        return None
    listening = data.get("listening") if isinstance(data, dict) else None
    if not isinstance(listening, list):
        return None
    ports: dict[tuple[int, str], OpenPort] = {}
    for item in listening:
        port = item.get("port") if isinstance(item, dict) else None
        if not isinstance(port, int) or not 0 < port < 65536:
            continue
        protocol: Literal["tcp", "udp"] = "udp" if str(item.get("protocol")).lower() == "udp" else "tcp"
        name = item.get("service_name")
        ports[(port, protocol)] = OpenPort(port=port, protocol=protocol, service_names=[str(name)] if name else [])
    return [ports[key] for key in sorted(ports)]


def listening_ports(plugin_id: int, output: str) -> list[OpenPort]:
    if plugin_id not in PORT_PLUGIN_IDS:
        return []
    structured = _json_listeners(output)
    if structured is not None:
        return structured
    pairs = _LISTEN.findall(output) or _PORT.findall(output)
    ports = {(int(port), proto.lower()) for port, proto in pairs if 0 < int(port) < 65536}
    return [OpenPort(port=port, protocol="udp" if proto == "udp" else "tcp") for port, proto in sorted(ports)]


def listener_processes(plugin_id: int, output: str) -> dict[int, str]:
    """Port -> process name from the JSON form of a port plugin; empty for any other form."""
    if plugin_id not in PORT_PLUGIN_IDS:
        return {}
    try:
        data = json.loads(output)
    except (ValueError, RecursionError):
        return {}
    listening = data.get("listening") if isinstance(data, dict) else None
    processes: dict[int, str] = {}
    for item in listening if isinstance(listening, list) else []:
        if isinstance(item, dict) and isinstance(item.get("port"), int):
            found = _LISTENER_PROCESS.search(str(item.get("plugin_output") or ""))
            if found:
                processes[item["port"]] = (found.group(1) or found.group(2)).replace("\\", "/").split("/")[-1].lower()
    return processes


def _service_key(name: str) -> str:
    """A service name in the form `disable_service` targets take, so config_state lookups match."""
    return identifier(name.strip().lower().removesuffix(".service"))


def service_states(plugin_id: int, output: str) -> dict[str, str]:
    """Service key -> state. 10456 lists services as running or stopped; 44401 is read only for the ones it lists
    as disabled, because 10456 reports those as merely inactive."""
    if plugin_id == 44401:
        _, _, rest = output.partition(_DISABLED_SERVICES)
        section = rest.split(_NEXT_START_TYPE, 1)[0]
        return {key: "disabled" for name in _SERVICE_NAME.findall(section) if (key := _service_key(name))}
    if plugin_id != 10456:
        return {}
    if _ACTIVE_SERVICES in output or _INACTIVE_SERVICES in output:
        active, _, inactive = output.partition(_INACTIVE_SERVICES)
        states = {key: "stopped" for name in _SERVICE_ENTRY.findall(inactive) if (key := _service_key(name))}
        states.update({key: "running" for name in _SERVICE_ENTRY.findall(active) if (key := _service_key(name))})
        return states
    services: dict[str, str] = {}
    for name, _display in _SERVICE.findall(output):
        key = name.strip().lower()
        if re.fullmatch(r"[a-z0-9_.$-]{2,64}", key):
            services[key] = "running"
    return services
