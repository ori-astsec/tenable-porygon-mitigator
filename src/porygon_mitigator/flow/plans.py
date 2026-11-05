"""Turn documented mitigation plans (`demo/tenable-lab/plans.jsonl`, or anything of that shape) into flow mitigations.

A plan names a CVE, a type and a source. Palo Alto threat IDs come from a separate list because the plan only links to
Threat Vault. Each mitigation is its own decision: one per CVE and plan, so a person can approve them one at a time.
"""

from __future__ import annotations

import re
from typing import Any

from porygon_mitigator.flow.models import FlowMitigation

_PALO_RISK = "A blocking action resets matching sessions on every rule using the profile, including false positives."
_PALO_ROLLBACK = "Remove the profile from the rule, or set the threat exceptions back to default."
_HOST_TYPES = {"CONFIGURATION", "REGISTRY_KEY", "EDR"}


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


def mitigations_from_plans(
    plans: list[dict[str, Any]], threat_ids: dict[str, list[str]], cves: set[str] | None = None
) -> list[FlowMitigation]:
    """Palo Alto IPS plans become threat-ID changes. One host workaround per CVE becomes a setting, labelled from the
    plan's title and limited to the plan's OS.

    IPS plans without known threat IDs and plans for other firewall vendors are skipped: the flow only simulates a
    Palo Alto firewall, and it can't apply a signature it can't name."""
    result: dict[str, FlowMitigation] = {}
    host_plan_for: set[str] = set()
    for plan in plans:
        cve = str(plan.get("cve") or "")
        if not cve or (cves is not None and cve not in cves):
            continue
        kind = str(plan.get("type") or "")
        title = str(plan.get("title") or "")
        source = str(plan.get("source") or "")
        if kind == "IPS" and plan.get("vendor") == "Palo Alto" and threat_ids.get(cve):
            identifier = f"palo-{_slug(cve)}"
            result[identifier] = FlowMitigation(
                id=identifier,
                title=f"Block {cve} with Palo Alto threat signatures",
                kind="ips_threat_ids",
                cve_ids=[cve],
                fw_type="PaloAltoNGFW",
                threat_ids=threat_ids[cve],
                risk=2,
                side_effects=_PALO_RISK,
                rollback=_PALO_ROLLBACK,
                source_url=source,
            )
        elif kind in _HOST_TYPES and title and plan.get("os") and cve not in host_plan_for:
            host_plan_for.add(cve)
            identifier = f"host-{_slug(cve)}"
            result[identifier] = FlowMitigation(
                id=identifier, title=title, kind="host_setting", cve_ids=[cve], setting=title, risk=2,
                os=str(plan["os"]),
                side_effects="Read the source before applying: its effect depends on how this machine is used.",
                rollback="Reverse the setting, as the source describes.", source_url=source,
            )
    return sorted(result.values(), key=lambda item: item.id)
