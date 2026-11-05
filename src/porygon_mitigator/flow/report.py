"""The dashboard page: one self-contained HTML file for a browser, and the same page as an MCP App."""

from __future__ import annotations

import json
from importlib import resources
from typing import Any

PLACEHOLDER = "__PORYGON_DATA__"


def dashboard_template() -> str:
    return resources.files("porygon_mitigator.flow").joinpath("dashboard.html").read_text(encoding="utf-8")


def render_dashboard(data: dict[str, Any]) -> str:
    """The page with this run's data embedded. `<` is escaped so tenant strings can't close the script element."""
    payload = json.dumps(data, sort_keys=True).replace("<", "\\u003c")
    return dashboard_template().replace(PLACEHOLDER, payload)


MAX_LISTED = 30


def render_summary(data: dict[str, Any]) -> str:
    """A short plain-text view for terminals."""
    now = data["funnel"]
    lines = [
        f"Run {data['run_id']} ({data['label']} data)",
        data["note"],
        "",
        f"Findings (one CVE on one machine): {now['findings']}",
        f"High and critical: {now['high_critical']}  Remotely exploitable: {now['remotely_exploitable']}  "
        f"Exposed and known exploited: {now['known_exposed']}  Unmitigated: {data['unmitigated']}",
        f"Exposed, high and critical: {now['exposed']}  Exposed, any severity: {data['exposed_total']}",
        f"Can't be judged, so not safe: {now['cant_judge']}",
        f"Remote, critical and known exploited: {now['remote_critical_kev']}",
        f"Of those: {now['kev_reachable']} running and reachable, {now['kev_host_reachable']} machine reachable, "
        f"{now['kev_not_seen_running']} not seen running, "
        f"{now['kev_not_reachable']} with no open path, {now['kev_client_side']} client-side, "
        f"{now['kev_local_only']} needing local access, {now['kev_unknown']} unknown, "
        f"{now['kev_protected']} protected",
        f"Critical known-exploited still exposed: {now['kev_exposed']} "
        f"(started at {data['baseline_funnel']['kev_exposed']})",
        "Known-exploited left open by "
        f"{'the applied plan' if data.get('applied_plan') else 'what is recommended'}: "
        f"{data['unmitigated']}",
        f"Hosts an attacker can reach: {data['scan']['hosts_reachable']} of {data['scan']['hosts_checked']}, "
        f"{data['scan']['undetermined']} checks the map can't settle",
        "",
    ]
    for state, label in (
        ("applied", "Applied plan"),
        ("waiting", "Plans waiting for approval"),
        ("blocked", "Plans that can't apply until the applied one is rolled back"),
        ("stale", "Plans made on an earlier network, which can't apply"),
    ):
        hashes = [plan["plan_hash"] for plan in data["plans"] if plan["state"] == state]
        if hashes:
            lines.append(f"{label}: {', '.join(hashes)}")
    for item in data.get("placed_by_model") or []:
        lines.append(f"- Where {item} sits is a model's guess: anything planned on it needs a person to confirm that.")
    for item in data.get("model_converted") or []:
        lines.append(f"Converted by a model, and checked against the source text: {item}")
    firewall = data.get("firewall") or {}
    for item in firewall.get("devices", []):
        lines.append(
            f"Sent to mock firewall {item['device']}: {len(item['calls'])} API calls, commit job {item['commit_job']}. "
            "It runs on this machine, and no real device changed."
        )
    for note in firewall.get("not_sent", []):
        lines.append(f"Not sent to a mock firewall: {note}")
    urgent = [item for item in data["exposed"] if item["kev"] and item["severity"] == "critical"]
    still = [f"{item['cve']} on {item['host']}" for item in urgent]
    if still:
        lines.append(f"Critical known-exploited still exposed: {', '.join(still[:MAX_LISTED])}")
    # With a plan applied, what it stops has nothing left to protect, which reads as "hold" below.
    lines.append("Mitigations, as they stand with the plan in place:" if data.get("applied_plan") else "Mitigations:")
    for item in data["candidates"]:
        reasons = f" ({' '.join(item['hold_reasons'])})" if item["hold_reasons"] else ""
        lines.append(
            f"  [{item['status']}] {item['mitigation_id']}: protects {len(item['protects'])}, "
            f"{item['protects_kev']} known exploited{reasons}"
        )
    return "\n".join(lines) + "\n"
