"""What Tenable's scanner could not see, read from the scan's own metadata in the vulnerability export.

A machine with no severe findings may be safe, or local checks may never have run. These plugins say which:

    19506   Nessus Scan Information: credentials used, port scanner, scan settings
    141118  a login succeeded (often over a protocol that doesn't run OS checks)
    104410  credentials were provided and the login failed
    110385  logged in without enough privilege
    117887  OS patch assessment available: local checks ran
    21745   OS patch assessment failed
    117886  OS patch assessment not available
    24260   an HTTP service answered
    11936   OS identification and its confidence

Only metadata is read and reported; nothing here touches the tenant or the network. This covers Tenable VM scan data
only, not findings from Tenable Cloud Security or OT Security.
"""

from __future__ import annotations

import ipaddress
import re
import statistics
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import Any

from porygon_mitigator.models.coverage import (
    CoverageGap,
    CoverageReport,
    CoverageStatus,
    GapImpact,
    GapKind,
    GapSummary,
    MachineCoverage,
    StatusSummary,
)

SCAN_INFO = 19506
VALID_LOGIN = 141118
CREDENTIAL_FAILURE = 104410
INSUFFICIENT_PRIVILEGE = 110385
ASSESSMENT_AVAILABLE = 117887
ASSESSMENT_FAILED = 21745
ASSESSMENT_UNAVAILABLE = 117886
HTTP_INFO = 24260
OS_IDENTIFICATION = 11936

SEVERE = {"critical", "high"}
LOCAL_PORT_SOURCES = {"netstat", "wmi_netstat", "snmp_scanner"}
NETWORK_GEAR = {"firewall", "router", "switch"}
WEB_SERVICES = {"www", "http", "https"}
MIN_OS_CONFIDENCE = 70
LATEST_SCAN_WINDOW_DAYS = 1
STALE_FINDING_DAYS = 7
NOT_SEEN_DAYS = 90
MAX_SETTING_VALUES = 5
SETTINGS_REPORTED = (
    "Port range",
    "Thorough tests",
    "Safe checks",
    "Paranoia level",
    "CGI scanning",
    "Web application tests",
    "Display superseded patches",
)
VM_ONLY_NOTE = (
    "Covers Tenable VM scan data only: findings from Tenable Cloud Security or OT Security are not included, so "
    "no_scan_data does not mean no Tenable product sees the asset."
)
# Junos routing-engine addresses repeat on every device, so sharing one says nothing about identity.
_NON_IDENTIFYING_NETWORKS = (ipaddress.ip_network("128.0.0.0/16"),)

_FIELD = re.compile(r"^[ \t]*([A-Za-z][A-Za-z /()-]+?)[ \t]*:[ \t]*(\S.*?)[ \t]*$", re.MULTILINE)
_CONFIDENCE = re.compile(r"Confidence level\s*:\s*(\d+)")
_PROTOCOL = re.compile(r"^\s*Proto(?:col)?\s*:\s*(\S+)", re.MULTILINE)

_GAPS: dict[GapKind, tuple[GapImpact, str, str]] = {
    "no_scan_data": (
        "high",
        "No open findings or scan information in this export; its vulnerabilities are unknown here.",
        "Check for a recent licensed scan, or read its findings from the product that sees it (OT, cloud).",
    ),
    "no_scan_metadata": (
        "high",
        "Has findings, but no scan information says whether local checks ran.",
        "Export informational findings too, since plugin 19506 is informational, then rerun this report.",
    ),
    "credential_failure": (
        "high",
        "Credentials were provided, but no login succeeded, so local checks did not run.",
        "Repair the credential or the login rule for this host, then rescan.",
    ),
    "login_not_used": (
        "high",
        "A login succeeded, but the scan reports no credentialed checks and no OS patch assessment ran.",
        "Check the account's privileges and the scan policy for this device type, then rescan.",
    ),
    "no_credentials": (
        "high",
        "No login was recorded, so patches and local software were not checked.",
        "Add credentials or an agent, or check why the scan didn't try one.",
    ),
    "patch_assessment_failed": (
        "high",
        "The OS patch assessment failed, so missing patches may not be reported.",
        "Read the errors in plugin 21745 and rescan.",
    ),
    "stale_findings": (
        "high",
        "The latest scan did not re-check these severe findings: they are open from an older scan.",
        "Restore the access the older scan had, then rescan before trusting them either way.",
    ),
    "partial_login_failure": (
        "medium",
        "One login worked and another failed, so checks over the failed protocol did not run.",
        "Repair the failed credential if that protocol matters for this host.",
    ),
    "insufficient_privilege": (
        "medium",
        "Logged in without enough privilege, so some local checks did not run.",
        "Give the scan account the privileges it needs.",
    ),
    "patch_assessment_unavailable": (
        "medium",
        "Tenable has no OS patch assessment for this host as scanned.",
        "Check plugin 117886's reason; this host may need a different credential type or an agent.",
    ),
    "ports_not_probed": (
        "medium",
        "Ports came from inside the machine or SNMP, so they don't show what the network can reach.",
        "Run a network port scan from each network segment that matters.",
    ),
    "web_tests_disabled": (
        "medium",
        "Runs a web service, and the scan had CGI or web application tests disabled.",
        "Enable web tests, or cover it with Tenable Web App Scanning.",
    ),
    "superseded_patches": (
        "low",
        "The supersedence plugin did not run, so patches that were already replaced can inflate the count.",
        "Enable supersedence in the scan policy.",
    ),
    "not_recently_seen": (
        "low",
        "Not seen recently, so what is known about it may be out of date.",
        "Rescan it, or retire the record.",
    ),
    "ambiguous_os": (
        "low",
        "The OS is unknown or a low-confidence guess, so OS-based matching is unreliable.",
        "Log in to confirm the OS.",
    ),
    "shared_identity": (
        "low",
        "Shares an IP or MAC address with another asset record, so it may be split or wrongly merged.",
        "Check for duplicate asset records.",
    ),
}
_NO_LOCAL_CHECKS: set[GapKind] = {"credential_failure", "login_not_used", "no_credentials", "patch_assessment_failed"}
_STATUS_ORDER: tuple[CoverageStatus, ...] = ("surface_only", "partial", "unknown", "no_scan_data", "covered")
_IMPACT_ORDER: dict[GapImpact, int] = {"high": 0, "medium": 1, "low": 2}


def _time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else None


def _strings(value: Any) -> list[str]:
    return [str(item) for item in value if item] if isinstance(value, list) else []


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _network(asset: dict[str, Any]) -> dict[str, Any]:
    return _dict(asset.get("network"))


def _name(asset: dict[str, Any]) -> str:
    network = _network(asset)
    for key in ("fqdns", "hostnames", "netbios_names", "ipv4s"):
        names = _strings(network.get(key)) or _strings(asset.get(key))
        if names:
            return names[0]
    return str(asset.get("id") or "unknown")


def _identifying_ip(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    if address.is_loopback or address.is_link_local or address.is_unspecified:
        return False
    return not any(address in network for network in _NON_IDENTIFYING_NETWORKS)


def _addresses(asset: dict[str, Any]) -> set[str]:
    """IPs and MACs that identify this machine: not loopback or link-local, and not on a virtual interface."""
    network = _network(asset)
    found = {
        value for value in _strings(network.get("ipv4s")) or _strings(asset.get("ipv4s")) if _identifying_ip(value)
    }
    interfaces = network.get("network_interfaces")
    for interface in interfaces if isinstance(interfaces, list) else []:
        if not isinstance(interface, dict):
            continue
        if interface.get("virtual") or interface.get("aliased"):
            found -= set(_strings(interface.get("ipv4s")))
            continue
        found.update(mac.lower() for mac in _strings(interface.get("mac_addresses")))
    return found


def _asset_from_row(row: dict[str, Any], asset_id: str) -> dict[str, Any]:
    """A finding can name an asset the asset export didn't return; keep it rather than lose its findings."""
    info = _dict(row.get("asset"))
    names = [str(info[key]) for key in ("fqdn", "hostname", "netbios_name", "ipv4") if info.get(key)]
    return {
        "id": asset_id,
        "hostnames": names[:1],
        "operating_systems": _strings(info.get("operating_system")),
        "system_types": [str(info["device_type"])] if info.get("device_type") else [],
    }


def _plugin(row: dict[str, Any]) -> dict[str, Any]:
    return _dict(row.get("plugin"))


def _plugin_id(row: dict[str, Any]) -> int:
    value = _plugin(row).get("id")
    return value if isinstance(value, int) else 0


def _port(row: dict[str, Any]) -> dict[str, Any]:
    return _dict(row.get("port"))


def _output(row: dict[str, Any]) -> str:
    return str(row.get("output") or "")


def _severe(row: dict[str, Any]) -> bool:
    severity = row.get("severity")
    return isinstance(severity, str) and severity.lower() in SEVERE


def _gap(kind: GapKind, detail: str, *plugin_ids: int) -> CoverageGap:
    return CoverageGap(kind=kind, impact=_GAPS[kind][0], detail=detail, plugin_ids=list(plugin_ids))


def _protocols(rows: list[dict[str, Any]]) -> str:
    return ", ".join(sorted({found for row in rows for found in _PROTOCOL.findall(_output(row))})) or "unknown"


def _source_names(asset: dict[str, Any]) -> list[str]:
    sources = asset.get("sources")
    return sorted(
        {str(item.get("name")) for item in sources if isinstance(item, dict)} if isinstance(sources, list) else set()
    )


def _access_gaps(by_plugin: dict[int, list[dict[str, Any]]], fields: dict[str, str]) -> list[CoverageGap]:
    gaps: list[CoverageGap] = []
    credentialed = fields.get("Credentialed checks", "").lower()
    logins = by_plugin.get(VALID_LOGIN, [])
    failures = by_plugin.get(CREDENTIAL_FAILURE, [])
    local_checks_ran = credentialed.startswith("yes") or ASSESSMENT_AVAILABLE in by_plugin
    if failures:
        over = _protocols(failures)
        if local_checks_ran or logins:
            gaps.append(_gap("partial_login_failure", f"Login failed over {over}.", CREDENTIAL_FAILURE))
        if not local_checks_ran and not logins:
            gaps.append(_gap("credential_failure", f"Login failed over {over}.", CREDENTIAL_FAILURE))
    if logins and not local_checks_ran:
        detail = f"Logged in over {_protocols(logins)}; the scan reports credentialed checks: no."
        gaps.append(_gap("login_not_used", detail, VALID_LOGIN, SCAN_INFO))
    if not failures and not logins and not local_checks_ran:
        gaps.append(_gap("no_credentials", "The scan reports credentialed checks: no.", SCAN_INFO))
    if ASSESSMENT_FAILED in by_plugin:
        gaps.append(_gap("patch_assessment_failed", "Plugin 21745 reported it.", ASSESSMENT_FAILED))
    privilege = by_plugin.get(INSUFFICIENT_PRIVILEGE, [])
    if privilege:
        gaps.append(_gap("insufficient_privilege", f"Limited over {_protocols(privilege)}.", INSUFFICIENT_PRIVILEGE))
    if ASSESSMENT_UNAVAILABLE in by_plugin and not local_checks_ran:
        gaps.append(_gap("patch_assessment_unavailable", "Plugin 117886 reported it.", ASSESSMENT_UNAVAILABLE))
    return gaps


def _stale_gap(rows: list[dict[str, Any]], scan_row: dict[str, Any]) -> CoverageGap | None:
    scanned = _time(scan_row.get("last_found"))
    if scanned is None:
        return None
    stale = 0
    oldest = scanned
    for row in rows:
        found = _time(row.get("last_found"))
        if _severe(row) and found is not None and scanned - found >= timedelta(STALE_FINDING_DAYS):
            stale += 1
            oldest = min(oldest, found)
    if not stale:
        return None
    detail = f"{stale} severe findings not re-checked, the oldest last seen {(scanned - oldest).days} days before it."
    return _gap("stale_findings", detail, SCAN_INFO)


def _port_gap(fields: dict[str, str]) -> CoverageGap | None:
    sources = {item.strip().lower() for item in fields.get("Port scanner(s)", "").split(",") if item.strip()}
    if sources - LOCAL_PORT_SOURCES:
        return None
    how = ", ".join(sorted(sources)) or "no port scanner (agent scan or none reported)"
    return _gap("ports_not_probed", f"Ports came from {how}.", SCAN_INFO)


def _test_gaps(rows: list[dict[str, Any]], fields: dict[str, str]) -> list[CoverageGap]:
    gaps: list[CoverageGap] = []
    web = any(str(_port(row).get("service")).lower() in WEB_SERVICES or _plugin_id(row) == HTTP_INFO for row in rows)
    disabled = [
        key for key in ("CGI scanning", "Web application tests") if fields.get(key, "").lower().startswith("disabled")
    ]
    if web and disabled:
        gaps.append(_gap("web_tests_disabled", f"Disabled in the scan: {', '.join(disabled).lower()}.", SCAN_INFO))
    supersedence = fields.get("Display superseded patches", "").lower()
    if "did not launch" in supersedence and any(_plugin(row).get("has_patch") for row in rows):
        gaps.append(_gap("superseded_patches", "The scan reports the supersedence plugin did not launch.", SCAN_INFO))
    return gaps


def _os_gap(asset: dict[str, Any], by_plugin: dict[int, list[dict[str, Any]]]) -> CoverageGap | None:
    """A confident OS identification settles it; several names alone are often a product and its kernel."""
    guesses = list(
        dict.fromkeys(
            part.strip()
            for name in _strings(asset.get("operating_systems"))
            for part in name.splitlines()
            if part.strip()
        )
    )
    if not guesses:
        return _gap("ambiguous_os", "No OS was identified.", OS_IDENTIFICATION)
    identified = [_CONFIDENCE.search(_output(row)) for row in by_plugin.get(OS_IDENTIFICATION, [])]
    confidences = [int(found.group(1)) for found in identified if found]
    if confidences:
        if max(confidences) >= MIN_OS_CONFIDENCE:
            return None
        return _gap(
            "ambiguous_os", f"Identified as {guesses[0]} with confidence {max(confidences)}.", OS_IDENTIFICATION
        )
    if len(guesses) > 1:
        return _gap("ambiguous_os", f"{len(guesses)} OS guesses, such as {guesses[0]}.", OS_IDENTIFICATION)
    return None


def _latest_scan_row(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """The newest scan decides what a machine's coverage is now, whatever order the export returned."""
    dated = [(found, row) for row in rows if (found := _time(row.get("last_found")))]
    return max(dated, key=lambda item: item[0])[1] if dated else rows[0]


def _from_latest_scan(
    by_plugin: dict[int, list[dict[str, Any]]], scan_row: dict[str, Any]
) -> dict[int, list[dict[str, Any]]]:
    """Only rows from that scan say what access it had: a login that worked in January says nothing about today. The
    scan's id decides when the export has one, and otherwise rows within a day of it count."""
    scanned = _time(scan_row.get("last_found"))
    if scanned is None:
        return by_plugin
    scan_id = _dict(scan_row.get("scan")).get("uuid")

    def same_scan(row: dict[str, Any]) -> bool:
        row_scan = _dict(row.get("scan")).get("uuid")
        if scan_id and row_scan:
            return bool(row_scan == scan_id)
        found = _time(row.get("last_found"))
        return found is None or scanned - found < timedelta(LATEST_SCAN_WINDOW_DAYS)

    kept: dict[int, list[dict[str, Any]]] = {}
    for plugin_id, rows in by_plugin.items():
        current = [row for row in rows if same_scan(row)]
        if current:
            kept[plugin_id] = current
    return kept


def _status(gaps: list[CoverageGap], has_rows: bool, has_scan: bool) -> CoverageStatus:
    if not has_rows:
        return "no_scan_data"
    if not has_scan or any(gap.kind == "no_scan_metadata" for gap in gaps):
        return "unknown"
    if any(gap.kind in _NO_LOCAL_CHECKS for gap in gaps):
        return "surface_only"
    return "partial" if any(gap.impact != "low" for gap in gaps) else "covered"


def _machine(
    asset: dict[str, Any], rows: list[dict[str, Any]], shared_with: int, as_of: datetime | None
) -> MachineCoverage:
    by_plugin: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_plugin[_plugin_id(row)].append(row)
    scan_rows = by_plugin.get(SCAN_INFO, [])
    gaps: list[CoverageGap] = []
    if scan_rows:
        scan_row = _latest_scan_row(scan_rows)
        fields = dict(_FIELD.findall(_output(scan_row)))
        if "Credentialed checks" in fields:
            gaps += _access_gaps(_from_latest_scan(by_plugin, scan_row), fields)
        else:
            gaps.append(_gap("no_scan_metadata", "The scan information doesn't state credentialed checks.", SCAN_INFO))
        for gap in (_stale_gap(rows, scan_row), _port_gap(fields), _os_gap(asset, by_plugin)):
            gaps += [gap] if gap else []
        gaps += _test_gaps(rows, fields)
    elif rows:
        gaps.append(_gap("no_scan_metadata", f"{len(rows)} findings, and no plugin 19506 row."))
    else:
        sources = ", ".join(_source_names(asset)) or "no source reported"
        last_scan = _dict(asset.get("scan")).get("last_scan_time")
        scanned = f" Last scan recorded: {str(last_scan)[:10]}." if last_scan else ""
        gaps.append(_gap("no_scan_data", f"Known from: {sources}.{scanned}"))

    last_seen = _time(_dict(asset.get("timestamps")).get("last_seen"))
    if as_of and last_seen and as_of - last_seen > timedelta(NOT_SEEN_DAYS):
        gaps.append(_gap("not_recently_seen", f"Last seen {(as_of - last_seen).days} days before the newest data."))
    if shared_with:
        gaps.append(_gap("shared_identity", f"Shares an address with {shared_with} other asset records."))
    gaps.sort(key=lambda gap: _IMPACT_ORDER[gap.impact])

    severe = sum(_severe(row) for row in rows)
    status = _status(gaps, bool(rows), bool(scan_rows))
    names = _strings(asset.get("operating_systems"))
    return MachineCoverage(
        asset_id=str(asset.get("id") or ""),
        name=_name(asset),
        os=names[0].splitlines()[0] if names and names[0].splitlines() else None,
        system_types=_strings(asset.get("system_types")),
        sources=_source_names(asset),
        status=status,
        severe_findings=severe,
        looks_clean=status == "surface_only" and severe == 0,
        gaps=gaps,
    )


def _sort_key(machine: MachineCoverage) -> tuple[int, bool, bool, str]:
    gear = bool(NETWORK_GEAR & set(machine.system_types))
    return (_STATUS_ORDER.index(machine.status), not machine.looks_clean, not gear, machine.name.lower())


def scan_coverage(
    assets: list[dict[str, Any]], findings: list[dict[str, Any]], as_of: datetime | None = None
) -> CoverageReport:
    """Build the report from asset export records and vulnerability export rows. Fixed findings are ignored.

    `as_of` defaults to the newest timestamp in the data, so the same export always gives the same report."""
    rows = [row for row in findings if isinstance(row, dict) and str(row.get("state") or "").upper() != "FIXED"]
    rows_by_asset: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        rows_by_asset[str(_dict(row.get("asset")).get("uuid") or "")].append(row)

    known = {str(asset.get("id") or ""): asset for asset in assets if isinstance(asset, dict)}
    for asset_id, asset_rows in rows_by_asset.items():
        if asset_id and asset_id not in known:
            known[asset_id] = _asset_from_row(asset_rows[0], asset_id)
    known.pop("", None)

    if as_of is None:
        moments = [_time(row.get("last_found")) for row in rows]
        moments += [_time(_dict(asset.get("timestamps")).get("last_seen")) for asset in known.values()]
        as_of = max((moment for moment in moments if moment), default=None)

    owners: dict[str, set[str]] = defaultdict(set)
    for asset_id, asset in known.items():
        for address in _addresses(asset):
            owners[address].add(asset_id)
    shared: dict[str, set[str]] = defaultdict(set)
    for members in owners.values():
        if len(members) > 1:
            for asset_id in members:
                shared[asset_id] |= members - {asset_id}

    machines = sorted(
        (
            _machine(asset, rows_by_asset.get(asset_id, []), len(shared.get(asset_id, ())), as_of)
            for asset_id, asset in known.items()
        ),
        key=_sort_key,
    )

    statuses: list[StatusSummary] = []
    for status in _STATUS_ORDER:
        members_severe = [machine.severe_findings for machine in machines if machine.status == status]
        statuses.append(
            StatusSummary(
                status=status,
                machines=len(members_severe),
                severe_findings=sum(members_severe),
                median_severe_findings=statistics.median(members_severe) if members_severe else 0,
            )
        )
    gap_counts = Counter(gap.kind for machine in machines for gap in machine.gaps)
    gaps = [
        GapSummary(kind=kind, impact=_GAPS[kind][0], machines=count, meaning=_GAPS[kind][1], fix=_GAPS[kind][2])
        for kind, count in gap_counts.items()
    ]
    gaps.sort(key=lambda gap: (_IMPACT_ORDER[gap.impact], -gap.machines, gap.kind))

    settings: dict[str, Counter[str]] = defaultdict(Counter)
    has_scan_info = False
    for asset_rows in rows_by_asset.values():
        scan_rows = [row for row in asset_rows if _plugin_id(row) == SCAN_INFO]
        if scan_rows:
            has_scan_info = True
            fields = dict(_FIELD.findall(_output(_latest_scan_row(scan_rows))))
            for key in SETTINGS_REPORTED:
                if key in fields:
                    settings[key][fields[key]] += 1

    warnings = [VM_ONLY_NOTE]
    if rows and not has_scan_info:
        warnings.insert(
            0,
            "No scan information in this export: it probably left out informational findings, so "
            "coverage can't be judged. Export them too and rerun.",
        )

    return CoverageReport(
        as_of=as_of,
        machines_total=len(machines),
        open_findings=sum(len(asset_rows) for asset_id, asset_rows in rows_by_asset.items() if asset_id),
        statuses=statuses,
        gaps=gaps,
        warnings=warnings,
        scan_settings={key: dict(values.most_common(MAX_SETTING_VALUES)) for key, values in settings.items()},
        machines=machines,
    )
