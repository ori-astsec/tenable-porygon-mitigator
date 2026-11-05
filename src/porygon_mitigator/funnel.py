"""Exposure funnel over Tenable findings: all open -> high/critical -> remote -> stoppable by an IPS signature.

One finding is one plugin result on one asset (a vulnerability-export row). Severity and reachability come from the
plugin's own CVSS (v3, else v2): high/critical is a base score of 7.0 or more, remote is attack vector Network. The
last stage looks the finding's CVEs up in the IPS rule catalogues, per vendor. A signature existing at a vendor does
not mean a device of that vendor sits in front of the asset; machine assessments answer that.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from typing import Any

from porygon_mitigator.config import Settings

HIGH_CVSS = 7.0
OPEN_STATES = {"open", "reopened"}
DEFAULT_CHECKPOINT_SEARCHES = 25
TOP_FINDINGS = 10
# IPS catalogue source -> vendor shown in the funnel, in display order.
IPS_VENDORS: dict[str, str] = {
    "snort3": "Cisco Talos (Snort 3 community)",
    "et_open": "Proofpoint ET Open",
    "threat_vault": "Palo Alto Networks",
    "checkpoint": "Check Point",
}
NOT_COVERED = ("FortiGuard (Fortinet) is not machine-readable: its pages sit behind a bot challenge.",)

Progress = Callable[[str], None]


@dataclass
class Stage:
    name: str
    findings: int
    assets: int
    cves: int


@dataclass
class VendorCoverage:
    vendor: str
    source: str
    findings: int
    cves: int
    note: str = ""


@dataclass
class Funnel:
    stages: list[Stage]
    vendors: list[VendorCoverage]
    top: list[dict[str, Any]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _score(plugin: dict[str, Any]) -> float | None:
    for key in ("cvss3_base_score", "cvss_base_score"):
        value = plugin.get(key)
        if isinstance(value, (int, float)) and value > 0:
            return float(value)
    return None


def _network(plugin: dict[str, Any]) -> bool:
    for key in ("cvss3_vector", "cvss_vector"):
        vector = plugin.get(key)
        if isinstance(vector, dict) and (vector.get("access_vector") or vector.get("raw")):
            return str(vector.get("access_vector") or "").lower() == "network" or "AV:N" in str(vector.get("raw"))
        if isinstance(vector, str) and vector:
            return "AV:N" in vector
    return False


def is_high_critical(row: dict[str, Any]) -> bool:
    score = _score(row.get("plugin") or {})
    if score is None:  # no CVSS on the plugin: fall back to Tenable's own severity
        return str(row.get("severity") or "").lower() in ("high", "critical")
    return score >= HIGH_CVSS


def is_remote(row: dict[str, Any]) -> bool:
    return _network(row.get("plugin") or {})


def _cves(row: dict[str, Any]) -> list[str]:
    return [str(cve).upper() for cve in (row.get("plugin") or {}).get("cve") or [] if cve]


def _asset(row: dict[str, Any]) -> str:
    return str((row.get("asset") or {}).get("uuid") or "")


def _stage(name: str, rows: list[dict[str, Any]]) -> Stage:
    return Stage(name, len(rows), len({_asset(row) for row in rows}), len({cve for row in rows for cve in _cves(row)}))


def remote_high_critical(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    live = [row for row in rows if str(row.get("state") or "open").lower() in OPEN_STATES]
    return [row for row in live if is_high_critical(row) and is_remote(row)]


def priority_cves(rows: list[dict[str, Any]]) -> list[str]:
    """CVEs of the remote high/critical findings, most urgent first: CISA KEV, then VPR, then CVSS."""
    best: dict[str, tuple[int, float, float]] = {}
    for row in remote_high_critical(rows):
        plugin = row.get("plugin") or {}
        vpr = plugin.get("vpr")
        if not isinstance(vpr, dict):
            vpr = {}
        rank = (int(bool(vpr.get("on_cisa_kev"))), float(vpr.get("score") or 0), _score(plugin) or 0.0)
        for cve in _cves(row):
            best[cve] = max(best.get(cve, rank), rank)
    return sorted(best, key=lambda cve: best[cve], reverse=True)


def build_funnel(rows: list[dict[str, Any]], indexes: dict[str, dict[str, Any]],
                 checkpoint_searched: set[str] | None = None) -> Funnel:
    """`indexes` maps catalogue source -> {CVE: {"rules": [...]}}; `checkpoint_searched` is the set of CVEs the
    Check Point search has covered (hits and misses), so its count can say how much was looked at."""
    live = [row for row in rows if str(row.get("state") or "open").lower() in OPEN_STATES]
    severe = [row for row in live if is_high_critical(row)]
    remote = [row for row in severe if is_remote(row)]

    def rules(source: str, row: dict[str, Any]) -> list[str]:
        index = indexes.get(source) or {}
        found: list[str] = []
        for cve in _cves(row):
            entry = index.get(cve)
            if isinstance(entry, dict):
                found += [str(rule) for rule in entry.get("rules") or []]
        return list(dict.fromkeys(found))

    vendors: list[VendorCoverage] = []
    stoppable: list[dict[str, Any]] = []
    for row in remote:
        if any(rules(source, row) for source in IPS_VENDORS):
            stoppable.append(row)
    remote_cves = {cve for row in remote for cve in _cves(row)}
    notes = list(NOT_COVERED)
    for source, vendor in IPS_VENDORS.items():
        hit_rows = [row for row in remote if rules(source, row)]
        hit_cves = {cve for row in hit_rows for cve in _cves(row) if cve in (indexes.get(source) or {})}
        note = ""
        if source == "checkpoint":
            searched = len(remote_cves & (checkpoint_searched or set()))
            note = f"web search: searched {searched:,} of {len(remote_cves):,} remote CVEs"
        elif source not in indexes:
            note = "catalogue not loaded"
        vendors.append(VendorCoverage(vendor, source, len(hit_rows), len(hit_cves), note))
    if "threat_vault" not in indexes:
        notes.append("Palo Alto Networks is not counted: its Threat Vault catalogue needs "
                     "PALO_ALTO_THREAT_VAULT_API_KEY and `porygon catalogs sync --source threat_vault`.")

    by_plugin: dict[int, dict[str, Any]] = {}
    for row in stoppable:
        plugin = row.get("plugin") or {}
        item = by_plugin.setdefault(int(plugin.get("id") or 0), {
            "plugin_id": plugin.get("id"), "name": plugin.get("name"), "cvss": _score(plugin),
            "cves": _cves(row), "assets": set(),
            "signatures": {IPS_VENDORS[source]: found[:3] for source in IPS_VENDORS if (found := rules(source, row))},
        })
        item["assets"].add(_asset(row))
    top = sorted(by_plugin.values(), key=lambda item: (len(item["assets"]), item["cvss"] or 0), reverse=True)
    for item in top:
        item["assets"] = len(item["assets"])
    return Funnel(
        stages=[
            _stage("All open findings", live),
            _stage(f"High + critical (CVSS >= {HIGH_CVSS:.1f})", severe),
            _stage("Remote (attack vector: network)", remote),
            _stage("Stoppable by an IPS signature (any vendor)", stoppable),
        ],
        vendors=vendors,
        top=top[:TOP_FINDINGS],
        notes=notes,
    )


async def run_funnel(rows: list[dict[str, Any]], *, settings: Settings,
                     checkpoint_searches: int = DEFAULT_CHECKPOINT_SEARCHES,
                     progress: Progress | None = None) -> Funnel:
    """Search Check Point for the most urgent remote CVEs (when Claude credentials are set), then build the funnel
    from every IPS catalogue on disk."""
    from porygon_mitigator.catalogs import checkpoint
    from porygon_mitigator.catalogs.lookup import load_indexes

    say = progress or (lambda _message: None)
    notes: list[str] = []
    if checkpoint_searches > 0 and settings.has_anthropic_credentials:
        await checkpoint.search(priority_cves(rows), settings=settings, cap=checkpoint_searches, progress=say)
    elif checkpoint_searches > 0:
        notes.append("Check Point search skipped: set ANTHROPIC_API_KEY to search advisories.checkpoint.com.")
    searched = set(checkpoint.load(settings).get("searched") or {})
    funnel = build_funnel(rows, load_indexes(settings), searched)
    funnel.notes += notes
    return funnel


def render_funnel(funnel: Funnel) -> str:
    lines = ["## Exposure funnel", "", "| Stage | Findings | Assets | CVEs | Kept |", "|---|---:|---:|---:|---:|"]
    previous: int | None = None
    for stage in funnel.stages:
        kept = f"{stage.findings / previous:.0%}" if previous else ""
        lines.append(f"| {stage.name} | {stage.findings:,} | {stage.assets:,} | {stage.cves:,} | {kept} |")
        previous = stage.findings or None
    lines += ["", "### IPS signatures by vendor (remote high/critical findings)", "",
              "| Vendor | Findings | CVEs | Note |", "|---|---:|---:|---|"]
    lines += [f"| {item.vendor} | {item.findings:,} | {item.cves:,} | {item.note} |" for item in funnel.vendors]
    if funnel.top:
        lines += ["", "### Top findings an IPS signature can stop", "", "| Plugin | CVEs | Assets | Signatures |",
                  "|---|---|---:|---|"]
        for item in funnel.top:
            cves = ", ".join(item["cves"][:3]) + (f" +{len(item['cves']) - 3}" if len(item["cves"]) > 3 else "")
            signatures = "; ".join(f"{vendor}: {', '.join(found)}" for vendor, found in item["signatures"].items())
            lines.append(f"| {item['name']} ({item['plugin_id']}) | {cves} | {item['assets']} | {signatures} |")
    if funnel.notes:
        lines += ["", *[f"- {note}" for note in funnel.notes]]
    return "\n".join(lines) + "\n"
