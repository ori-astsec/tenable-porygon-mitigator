# Mitigation types, layers and risk

**Types:** `CONFIGURATION` (setting or config file), `REGISTRY_KEY` (Windows registry), `DISABLE` (service, feature,
protocol, module or component), `NETWORK_ACL` (firewall rule, ACL, port block, bind address), `WAF`, `IPS`, `EDR`
(endpoint rule/feature/signature), `OTHER` (concrete vendor interim fix that fits none of these).

**Layers** say where the change happens:

| Layer | Applies when |
|---|---|
| `host` | the change is made on the vulnerable machine itself (including an appliance's own settings) |
| `network_device` | a firewall/router in front of the machine carries the rule |
| `waf` / `ips` | a WAF or IPS of the right vendor sits in the traffic path (or the appliance is that device) |
| `edr` | the named endpoint product runs on the machine |

**Applicability statuses:** `applicable`, `already_applied` (config_state shows it in place), `needs_device`
(right control, but the machine lacks the device/tool), `not_applicable` (wrong platform or product, or withdrawn),
`unknown` (the profile doesn't say enough).

**Step risk:** 0 nothing to run, 1 read-only, 2 changes configuration/files/registry, 3 stops/restarts/removes
something or weakens a control. Commands that download-and-run code or disable security tools are always 3 with
a warning, whatever the source says.

**Verdicts:** `not_affected`, `mitigations_available`, `already_mitigated`, `needs_additional_controls`,
`no_documented_mitigation` (patch or isolate), `unknown`.
