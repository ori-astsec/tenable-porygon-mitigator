"""Turn catalogue index entries for a CVE into mitigation records, one per product that can enforce them."""

from __future__ import annotations

import json
from datetime import date
from functools import lru_cache
from pathlib import Path

from porygon_mitigator.catalogs.templates import SOURCE_INFO, TEMPLATES, ProductTemplate
from porygon_mitigator.config import Settings, package_data_dir
from porygon_mitigator.extract.derive import derive_verify
from porygon_mitigator.models.cve import CveFacts
from porygon_mitigator.models.mitigation import (
    Action,
    AppliesTo,
    Evidence,
    Mitigation,
    Note,
    Step,
    mitigation_id,
)

# Prefix used in the action target, so a rule found in an advisory ("cloudflare:100514") merges with the
# catalogue's record for the same product.
_TARGET_PREFIX = {
    "cisco_secure_firewall": "cisco_secure_firewall",
    "cisco_meraki_mx": "cisco_meraki",
    "snort3": "snort",
    "suricata_et_open": "suricata",
    "f5_awaf": "f5",
    "azure_application_gateway": "azure_application_gateway",
    "azure_front_door": "azure_front_door",
    "cloudflare": "cloudflare",
    "netscaler_waf": "citrix",
    "paloalto_ngfw": "paloaltonetworks",
    "checkpoint_ips": "checkpoint",
}


@lru_cache(maxsize=4)
def _load(dirs: tuple[str, ...]) -> dict[str, dict[str, dict[str, object]]]:
    indexes: dict[str, dict[str, dict[str, object]]] = {}
    for directory in dirs:
        for path in sorted(Path(directory).glob("*.json")):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            source = str(data.get("source") or path.stem)
            if source in SOURCE_INFO and source not in indexes:
                indexes[source] = data.get("cves") or {}
    return indexes


def reload_indexes() -> None:
    """Forget the loaded indexes so the next lookup reads the files again (after a sync or a Check Point search)."""
    _load.cache_clear()


def load_indexes(settings: Settings | None = None) -> dict[str, dict[str, dict[str, object]]]:
    settings = settings or Settings()
    dirs = (str(settings.work_dir() / "catalogs"), str(package_data_dir() / "catalogs"))
    return _load(dirs)


def _rules_text(template: ProductTemplate, rules: list[str]) -> str:
    shown = ", ".join(rules[:8])
    more = f" and {len(rules) - 8} more" if len(rules) > 8 else ""
    noun = template.rule_noun + ("s" if len(rules) != 1 else "")
    return f"{noun} {shown}{more}"


def _link(source: str, cve_id: str, rules: list[str], entry: dict[str, object]) -> str:
    if isinstance(entry.get("link"), str):
        return str(entry["link"])
    template = SOURCE_INFO[source][0]
    return template.format(rule=rules[0], cve=cve_id)


def catalogue_record(template: ProductTemplate, facts: CveFacts, rules: list[str], entry: dict[str, object],
                     today: date) -> Mitigation:
    cve_id = facts.cve_id
    kind = "apply_ips_signature" if template.type == "IPS" else "apply_waf_rule"
    target = f"{_TARGET_PREFIX[template.key]}:{rules[0].lstrip('.').lower()}"
    rules_text = _rules_text(template, rules)
    title = f"Enforce {template.rule_noun}s on {template.product}"
    steps = [Step(text=step.format(rules=rules_text), risk=2 if "Block" in step or "enable" in step.lower() else 0)
             for step in template.steps]
    action = Action(kind=kind, target=target)  # type: ignore[arg-type]
    source_name = SOURCE_INFO[template.source][1]
    evidence = Evidence(
        url=_link(template.source, cve_id, rules, entry),
        quote=f"{source_name} lists {rules_text} for {cve_id}.",
        retrieved_at=today,
        verified=True,
        source_kind="catalog",
    )
    return Mitigation(
        id=mitigation_id(cve_id, template.type, kind, target, rules, title),
        cve_id=cve_id,
        type=template.type,  # type: ignore[arg-type]
        layer=template.layer,  # type: ignore[arg-type]
        title=title,
        summary=(f"{template.product} has {rules_text} that detect exploitation of {cve_id}. Enforcing them in "
                 "blocking mode stops matching exploit traffic before it reaches the host; it does not fix the "
                 "vulnerability."),
        steps=steps,
        action=action,
        rule_ids=rules,
        side_effects=Note(text=template.side_effects, origin="derived") if template.side_effects else None,
        rollback=Note(text=template.rollback, origin="derived"),
        how_to_verify=derive_verify(action),
        applies_to=AppliesTo(
            device_roles=[template.device_role],  # type: ignore[list-item]
            device_vendors=list(template.device_vendors),
            device_products=list(template.device_products),
            conditions=["the exploit traffic passes through this device (and is decrypted if it is TLS)"],
        ),
        evidence=[evidence],
        confidence="vendor_documented",
        origin="catalog",
        first_seen=today,
        last_confirmed=today,
    )


def catalogue_mitigations(facts: CveFacts, today: date, settings: Settings | None = None) -> list[Mitigation]:
    indexes = load_indexes(settings)
    records: list[Mitigation] = []
    for template in TEMPLATES:
        entry = indexes.get(template.source, {}).get(facts.cve_id.upper())
        if not isinstance(entry, dict):
            continue
        raw_rules = entry.get("rules")
        rules = [str(rule) for rule in raw_rules if str(rule)] if isinstance(raw_rules, list) else []
        if rules:
            records.append(catalogue_record(template, facts, rules, entry, today))
    return records
