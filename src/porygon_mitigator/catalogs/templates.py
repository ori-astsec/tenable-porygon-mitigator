"""How a catalogue hit becomes a mitigation for a specific product: steps written for that product."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ProductTemplate:
    key: str
    source: str  # catalogue the rule IDs come from
    product: str
    type: str  # IPS or WAF
    layer: str  # ips or waf
    device_role: str
    device_vendors: tuple[str, ...]
    device_products: tuple[str, ...] = ()
    rule_noun: str = "rule"
    steps: tuple[str, ...] = field(default_factory=tuple)
    side_effects: str = ""
    rollback: str = "Set the rule back to its previous action (alert or disabled) and redeploy the policy."


TEMPLATES: tuple[ProductTemplate, ...] = (
    ProductTemplate(
        key="cisco_secure_firewall", source="snort3", product="Cisco Secure Firewall (Snort 3)", type="IPS",
        layer="ips", device_role="ips", device_vendors=("cisco",),
        device_products=("firepower", "secure_firewall", "ftd", "fmc", "asa"), rule_noun="Talos SID",
        steps=(
            "Update the intrusion rules (Snort rule update / LSP) so the device has the current Talos rule set.",
            "In the intrusion policy applied to traffic for this host, make sure {rules} are enabled with the "
            "Block (drop) action, not Generate Events or Disabled.",
            "Confirm the access control rule that matches this traffic uses that intrusion policy, then deploy.",
            "Intrusion rules only see encrypted traffic that is decrypted on the firewall; check TLS decryption "
            "for HTTPS services.",
        ),
        side_effects="Matching traffic is dropped, including legitimate requests that trigger a false positive.",
    ),
    ProductTemplate(
        key="cisco_meraki_mx", source="snort3", product="Cisco Meraki MX", type="IPS", layer="ips",
        device_role="ips", device_vendors=("cisco",), device_products=("meraki",), rule_noun="Talos SID",
        steps=(
            "In Security & SD-WAN > Threat protection, set intrusion detection and prevention to Prevention "
            "(Detection only logs).",
            "Use the Security ruleset (or a custom intrusion policy based on it) and confirm {rules} are active.",
            "Make sure no allow-list entry or trusted-traffic exclusion covers these rules or this host.",
        ),
        side_effects="Prevention mode drops matching traffic across the MX, including false positives.",
    ),
    ProductTemplate(
        key="snort3", source="snort3", product="Snort 3 IPS", type="IPS", layer="ips", device_role="ips",
        device_vendors=("snort",), rule_noun="SID",
        steps=(
            "Load the current Snort 3 community ruleset.",
            "Make sure {rules} are enabled and set to drop, and that Snort runs inline (IPS mode).",
        ),
        side_effects="Inline drop rules block matching traffic, including false positives.",
    ),
    ProductTemplate(
        key="suricata_et_open", source="et_open", product="Suricata or Snort", type="IPS", layer="ips",
        device_role="ips", device_vendors=("suricata", "netgate", "opnsense", "proofpoint", "securityonion", "snort"),
        rule_noun="ET Open SID",
        steps=(
            "Enable the Proofpoint Emerging Threats Open ruleset and update it.",
            "Make sure {rules} are enabled with a drop action, with the engine running inline (IPS mode).",
        ),
        side_effects="Inline drop rules block matching traffic, including false positives.",
    ),
    ProductTemplate(
        key="f5_awaf", source="f5", product="F5 BIG-IP Advanced WAF / ASM", type="WAF", layer="waf",
        device_role="waf", device_vendors=("f5",), rule_noun="attack signature",
        steps=(
            "Install the latest attack signature update (Live Update).",
            "Make sure the security policy protecting this application includes {rules} in its signature sets.",
            "Take the signatures out of staging and set them to Block; the policy must be in Blocking mode.",
        ),
        side_effects="Blocking signatures reject matching requests, including false positives.",
    ),
    ProductTemplate(
        key="azure_application_gateway", source="azure_appgw", product="Azure Application Gateway WAF", type="WAF",
        layer="waf", device_role="waf", device_vendors=("microsoft",),
        device_products=("application_gateway", "app_gateway", "appgw"), rule_noun="managed rule",
        steps=(
            "Use a managed rule set version on the WAF policy that contains {rules}, and keep them enabled.",
            "Run the WAF policy in Prevention mode (Detection mode only logs).",
        ),
        side_effects="Prevention mode blocks matching requests, including false positives.",
        rollback="Disable the rule override or switch the policy back to Detection mode.",
    ),
    ProductTemplate(
        key="azure_front_door", source="azure_frontdoor", product="Azure Front Door WAF", type="WAF", layer="waf",
        device_role="waf", device_vendors=("microsoft",), device_products=("front_door", "frontdoor"),
        rule_noun="managed rule",
        steps=(
            "Use a Default Rule Set version on the Front Door WAF policy that contains {rules}, and keep them "
            "enabled.",
            "Run the WAF policy in Prevention mode.",
        ),
        side_effects="Prevention mode blocks matching requests, including false positives.",
        rollback="Disable the rule override or switch the policy back to Detection mode.",
    ),
    ProductTemplate(
        key="cloudflare", source="cloudflare", product="Cloudflare WAF", type="WAF", layer="waf", device_role="waf",
        device_vendors=("cloudflare",), rule_noun="managed rule",
        steps=(
            "Deploy the Cloudflare Managed Ruleset on the zone that fronts this service.",
            "Make sure {rules} are enabled with the Block action; new rules sometimes ship disabled or in Log mode.",
        ),
        side_effects="Blocking rules reject matching requests, including false positives.",
    ),
    ProductTemplate(
        key="netscaler_waf", source="netscaler", product="NetScaler Web App Firewall", type="WAF", layer="waf",
        device_role="waf", device_vendors=("citrix",), rule_noun="signature rule",
        steps=(
            "Update the Web App Firewall signatures to a version that contains {rules}.",
            "Enable these signature rules with the Block action in the profile protecting this application.",
        ),
        side_effects="Blocking signatures reject matching requests, including false positives.",
    ),
    ProductTemplate(
        key="paloalto_ngfw", source="threat_vault", product="Palo Alto Networks NGFW", type="IPS", layer="ips",
        device_role="ips", device_vendors=("paloaltonetworks",), rule_noun="threat ID",
        steps=(
            "Install the Applications and Threats content update that includes {rules} (needs an active Threat "
            "Prevention subscription).",
            "Apply a Vulnerability Protection profile that blocks (reset-both) these threat IDs to the security "
            "rules that match traffic to this host.",
            "Decrypt TLS traffic where the exploit can arrive over HTTPS; signatures can't see encrypted payloads.",
        ),
        side_effects="Blocking actions reset matching sessions, including false positives.",
    ),
    ProductTemplate(
        key="checkpoint_ips", source="checkpoint", product="Check Point Quantum Security Gateway (IPS)", type="IPS",
        layer="ips", device_role="ips", device_vendors=("checkpoint",), rule_noun="IPS protection",
        steps=(
            "Install the latest IPS update on the Security Gateway (IPS blade enabled) so it has {rules}.",
            "Set these protections to Prevent in the Threat Prevention profile that covers traffic to this host, "
            "then install the policy.",
        ),
        side_effects="Prevent mode drops matching connections, including false positives.",
        rollback="Set the protections back to Detect (or their previous action) and install the policy.",
    ),
)

SOURCE_INFO: dict[str, tuple[str, str]] = {
    # source -> (rule documentation link template, human name)
    "snort3": ("https://www.snort.org/rule_docs/1-{rule}", "Snort 3 community rules (Talos)"),
    "et_open": ("https://rules.emergingthreats.net/open/snort-2.9.0/rules/", "Proofpoint ET Open"),
    "f5": ("https://docs.cloud.f5.com/docs-v2/platform/reference/attack-signatures?sigId={rule}",
           "F5 attack signatures"),
    "azure_appgw": ("https://learn.microsoft.com/azure/web-application-firewall/ag/"
                    "application-gateway-crs-rulegroups-rules", "Azure Application Gateway WAF rules"),
    "azure_frontdoor": ("https://learn.microsoft.com/azure/web-application-firewall/afds/waf-front-door-drs",
                        "Azure Front Door WAF rules"),
    "cloudflare": ("https://developers.cloudflare.com/waf/change-log/", "Cloudflare WAF changelog"),
    "netscaler": ("https://docs.netscaler.com/en-us/citrix-adc/current-release/signature-alerts.html",
                  "NetScaler WAF signature alerts"),
    "threat_vault": ("https://threatvault.paloaltonetworks.com/?query={cve}", "Palo Alto Networks Threat Vault"),
    "checkpoint": ("https://advisories.checkpoint.com/advisories/", "Check Point IPS advisories"),
}
