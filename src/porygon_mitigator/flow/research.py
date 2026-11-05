"""Where a run's mitigations come from when nobody hands them over: live web research, or Palo Alto's Threat Vault with
your own API key. Both go through the same verified sources as the rest of porygon, and only what the simulation can
enforce becomes a flow mitigation. Everything else is reported, not dropped silently."""

from __future__ import annotations

import re
from typing import Any, Literal

from porygon_mitigator.catalogs.lookup import load_indexes, reload_indexes
from porygon_mitigator.catalogs.sync import sync
from porygon_mitigator.config import Settings
from porygon_mitigator.flow.models import FlowMitigation
from porygon_mitigator.models.actions import KIND_PLATFORM
from porygon_mitigator.models.mitigation import Mitigation
from porygon_mitigator.pipeline import get_record

MitigationSource = Literal["websearch", "threat_vault"]
THREAT_VAULT_SOURCE = "threat_vault"
MIN_CHANGE_RISK = 2
THREAT_VAULT_SIDE_EFFECTS = "A blocking action resets matching sessions on every rule using the profile."
THREAT_VAULT_ROLLBACK = "Remove the threat exceptions from the profile."
_HOST_KINDS = {
    "set_config",
    "disable_app_feature",
    "set_registry_value",
    "delete_registry_key",
    "disable_os_feature",
    "disable_kernel_module",
    "set_sysctl",
    "set_boot_parameter",
    "remove_component",
    "restrict_file_permission",
}
_PLATFORM_OS = {"windows": "Windows", "linux": "Linux"}
_PALO_RULE = re.compile(r"^paloaltonetworks:(\d+)$")


def to_flow_mitigation(item: Mitigation) -> FlowMitigation | str:
    """The simulation's version of a researched mitigation, or why it can't be simulated."""
    common: dict[str, Any] = {
        "id": f"found-{item.id}",
        "title": item.title,
        "cve_ids": [item.cve_id],
        # Every kind here changes something, so a source that states no risk doesn't make it "no change".
        "risk": max([MIN_CHANGE_RISK, *(step.risk for step in item.steps)]),
        "side_effects": item.side_effects.text if item.side_effects else "",
        "rollback": item.rollback.text if item.rollback else "",
        "source_url": next((proof.url for proof in item.evidence if proof.verified), ""),
    }
    kind, target = item.action.kind, item.action.target
    declared: list[str] = [*item.applies_to.platforms]
    platforms = declared or ([KIND_PLATFORM[kind]] if kind in KIND_PLATFORM else [])
    here = [name for name in platforms if name in _PLATFORM_OS]
    if platforms and not here:
        return f"a change for {', '.join(platforms)}, which isn't on this network's list"
    common["os"] = _PLATFORM_OS[here[0]] if len(here) == 1 else None
    if kind == "apply_ips_signature":
        threat = _PALO_RULE.match(target)
        ids = sorted({*([threat.group(1)] if threat else []), *(rule for rule in item.rule_ids if rule.isdigit())})
        if not target.startswith("paloaltonetworks:") or not ids:
            return f"an IPS signature for {target or 'another vendor'}: the simulated firewall is Palo Alto"
        return FlowMitigation(**common, kind="ips_threat_ids", fw_type="PaloAltoNGFW", threat_ids=ids)
    if kind == "restrict_network_access":
        return f"a network restriction on one service, which a flow with no port data can't simulate: {target}"
    if kind == "disable_service":
        return FlowMitigation(**common, kind="disable_service", service=target)
    if kind in _HOST_KINDS:
        return FlowMitigation(**common, kind="host_setting", setting=target)
    return f"a {kind} change, which the simulation can't model"


async def _from_websearch(cve_ids: list[str], settings: Settings) -> tuple[list[FlowMitigation], list[dict[str, str]]]:
    if not settings.has_anthropic_credentials:
        raise ValueError("web research needs ANTHROPIC_API_KEY on the server")
    found: list[FlowMitigation] = []
    skipped: list[dict[str, str]] = []
    for cve in cve_ids:
        try:
            record, _, _ = await get_record(cve, settings=settings)
        except Exception as error:  # one CVE's failed research shouldn't lose the others'
            skipped.append({"cve": cve, "title": "", "why": f"research failed: {type(error).__name__}"})
            continue
        for item in record.active_mitigations():
            converted = to_flow_mitigation(item)
            if isinstance(converted, str):
                skipped.append({"cve": cve, "title": item.title, "why": converted})
            else:
                found.append(converted)
    return found, skipped


async def _from_threat_vault(
    cve_ids: list[str], settings: Settings
) -> tuple[list[FlowMitigation], list[dict[str, str]]]:
    if not settings.threat_vault_api_key:
        raise ValueError("Threat Vault needs PALO_ALTO_THREAT_VAULT_API_KEY on the server")
    index = load_indexes(settings).get(THREAT_VAULT_SOURCE)
    if not index:
        results = await sync([THREAT_VAULT_SOURCE], settings)
        problems = [result.note for result in results if result.note]
        reload_indexes()
        index = load_indexes(settings).get(THREAT_VAULT_SOURCE)
        if not index:
            raise ValueError(f"couldn't load Threat Vault: {'; '.join(problems) or 'no data returned'}")
    found: list[FlowMitigation] = []
    skipped: list[dict[str, str]] = []
    for cve in cve_ids:
        entry = index.get(cve.upper())
        rules = entry.get("rules") if isinstance(entry, dict) else None
        ids = [str(rule) for rule in rules if str(rule).isdigit()] if isinstance(rules, list) else []
        if not ids:
            skipped.append({"cve": cve, "title": "", "why": "Threat Vault has no signature for it"})
            continue
        found.append(
            FlowMitigation(
                id=f"threat-vault-{cve.lower()}",
                title=f"Block {cve} with Palo Alto threat signatures",
                kind="ips_threat_ids",
                cve_ids=[cve],
                fw_type="PaloAltoNGFW",
                threat_ids=ids,
                side_effects=THREAT_VAULT_SIDE_EFFECTS,
                rollback=THREAT_VAULT_ROLLBACK,
            )
        )
    return found, skipped


async def find(
    cve_ids: list[str], source: MitigationSource, settings: Settings | None = None
) -> tuple[list[FlowMitigation], list[dict[str, str]]]:
    settings = settings or Settings()
    if source == "websearch":
        return await _from_websearch(cve_ids, settings)
    return await _from_threat_vault(cve_ids, settings)
