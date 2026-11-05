"""Markdown scan coverage report. ASCII-only so it renders in any terminal."""

from __future__ import annotations

from porygon_mitigator.models.coverage import CoverageReport, MachineCoverage
from porygon_mitigator.text import to_ascii

DEFAULT_MACHINE_LIMIT = 25
_STATUS_TITLE = {
    "surface_only": "No local checks ran",
    "partial": "Local checks ran, with gaps",
    "unknown": "Scan information missing",
    "no_scan_data": "No scan data in this export",
    "covered": "No high or medium gaps found",
}


def _cell(text: object) -> str:
    return to_ascii(str(text)).replace("|", "/").replace("\n", " ")


def _machine_line(machine: MachineCoverage) -> str:
    os_name = f", {_cell(machine.os)}" if machine.os else ""
    return f"- **{_cell(machine.name)}**{os_name}: {machine.severe_findings} severe findings"


def _headline(report: CoverageReport) -> str:
    by_status = {item.status: item for item in report.statuses}
    surface = by_status["surface_only"]
    scanned = surface.machines + by_status["partial"].machines + by_status["covered"].machines
    if not scanned:
        return "**No machine in this data has usable scan information**, so coverage can't be judged."
    return (
        f"**{surface.machines} of {scanned} scanned machines had no local checks**, and they hold "
        f"{surface.severe_findings} of the severe findings in this data. Few findings there may just mean the scanner "
        "couldn't look."
    )


def render_coverage_markdown(report: CoverageReport, limit: int = DEFAULT_MACHINE_LIMIT) -> str:
    limit = max(1, limit)
    lines = ["# Scan coverage report", "", _headline(report), ""]
    lines += [f"> {_cell(warning)}" for warning in report.warnings]
    lines += [
        "",
        f"{report.machines_total} machines, {report.open_findings} open findings"
        + (f", data as of {report.as_of.date().isoformat()}." if report.as_of else "."),
        "",
        "| Coverage | Machines | Severe findings | Median per machine |",
        "|---|---|---|---|",
    ]
    lines += [
        f"| {_STATUS_TITLE[item.status]} | {item.machines} | {item.severe_findings} | {item.median_severe_findings:g} |"
        for item in report.statuses
    ]
    lines += [
        "",
        "## What to fix first",
        "",
        "| Gap | Impact | Machines | What it means | Fix |",
        "|---|---|---|---|---|",
    ]
    lines += [
        f"| `{gap.kind}` | {gap.impact} | {gap.machines} | {_cell(gap.meaning)} | {_cell(gap.fix)} |"
        for gap in report.gaps
    ]

    clean = [machine for machine in report.machines if machine.looks_clean]
    if clean:
        lines += ["", f"## No severe findings, but no local checks ran ({len(clean)})", ""]
        lines += [_machine_line(machine) for machine in clean[:limit]]
        if len(clean) > limit:
            lines.append(f"- and {len(clean) - limit} more")

    listed = [machine for machine in report.machines if machine.status in ("surface_only", "partial", "unknown")]
    if listed:
        lines += ["", f"## Machines with gaps (first {min(limit, len(listed))} of {len(listed)})", ""]
        for machine in listed[:limit]:
            lines.append(_machine_line(machine))
            lines += [f"  - `{gap.kind}`: {_cell(gap.detail)}" for gap in machine.gaps if gap.impact != "low"]

    unscanned = [machine for machine in report.machines if machine.status == "no_scan_data"]
    if unscanned:
        shown = min(limit, len(unscanned))
        lines += ["", f"## Known machines with no scan data (first {shown} of {len(unscanned)})", ""]
        lines += [_machine_line(machine) for machine in unscanned[:limit]]

    if report.scan_settings:
        lines += ["", "## Scan settings used", "", "| Setting | Value | Machines |", "|---|---|---|"]
        for key, values in report.scan_settings.items():
            lines += [f"| {_cell(key)} | {_cell(value)} | {count} |" for value, count in values.items()]

    lines += [
        "",
        "Read from the scan's own metadata in the export. It shows what the scanner reports about its own access, not "
        "whether a machine is safe, and machine names are never written to the CVE cache.",
        "",
    ]
    return "\n".join(lines)
