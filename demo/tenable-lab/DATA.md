# Demo data files: field reference

What each data file in this folder holds, field by field. [README.md](README.md) covers where the data comes from and
what numbers it produces. All files are UTF-8; the `.jsonl` files have one JSON object per line, sorted.

## `hosts.json`

The simulated network: the eight hosts and the devices in front of them.

| Field | Type | Meaning |
|---|---|---|
| `network_path` | list | The devices between the internet and every host, outermost first. Same shape as `MachineProfile.network_path` |
| `network_path[].role` | string | `ngfw` or `router` |
| `network_path[].vendor`, `.product`, `.version` | string | The device. Only the firewall is simulated; the router is the lab's own |
| `network_path[].capabilities` | list of string | Enabled security features; `threat_prevention` means the firewall runs IPS signatures |
| `hosts[].name` | string | Host name, used as the key in `overlays/` |
| `hosts[].asset_id` | string | Tenable asset UUID |
| `hosts[].platform` | string | `windows` or `linux`; decides which host workarounds apply |
| `hosts[].segment` | string | The demo segment: Windows servers, Workstations, Linux servers |

## `overlays/<host>.json`

One file per host holding just `network_path`, copied from `hosts.json`. It is a profile overlay: the Tenable mapper
cannot see network devices, so `porygon tenable profile --asset <uuid> --overlay overlays/<host>.json` adds them.

## `cves.jsonl`

One row per distinct CVE on the hosts' open findings (10,933 rows), with public fields only.

| Field | Type | Meaning |
|---|---|---|
| `cve` | string | CVE ID |
| `vector` | string | CVSS vector: v3 (`CVSS:3.x/AV:N/...`) for 10,653, v4 (`CVSS:4.0/...`) for 166, v2 (`AV:N/...`) for 6, empty for 108. `AV:N` is what "remote" means |
| `kev` | bool | On the CISA Known Exploited Vulnerabilities list |

## `plans.jsonl`

The documented mitigation plans for five known-exploited CVEs, kept as examples of the end of the funnel: 57 plans for
CVE-2019-0708, CVE-2020-1350, CVE-2021-34527, CVE-2021-44228 and CVE-2023-44487. The full snapshot had 1,395 plans for
868 CVEs.

| Field | Type | Meaning |
|---|---|---|
| `cve` | string | CVE ID, joins `cves.jsonl` |
| `type` | string | What the plan is (see below) |
| `vendor` | string | Whose product applies it: an IPS/WAF vendor (`Palo Alto`, `Checkpoint`, `F5`, `Fortinet`, ...) or the software vendor for host plans (`Microsoft`, `Broadcom`, ...). Empty for 4 plans that name none |
| `os` | string | The OS a host plan applies to (`Windows`, `Linux`); empty when it applies to any OS or the plan is network-side |
| `title` | string | The plan in one line, as the source states it |
| `source` | string | Public page the plan comes from: the vendor advisory, the signature page or the KB article |

`type` values, split into where the plan is applied:

| Value | Applied on | Plans |
|---|---|---:|
| `IPS` | Network: an IPS signature on a firewall | 31 |
| `WAF` | Network: a web application firewall rule | 5 |
| `CONFIGURATION` | Host: change a setting | 7 |
| `DISABLE` | Host: turn off the vulnerable feature or service | 8 |
| `REGISTRY_KEY` | Host: set a Windows registry value | 6 |

The README's coverage numbers counted a CVE as covered by the firewall when an `IPS` or `WAF` plan named its vendor,
and by the host when a host plan's `os` was empty or matched the host's `platform`.

## `palo_threat_ids.json`

`{CVE: [threat ID, ...]}` for the 22 known-exploited CVEs the demo plans for: identifiers only.

## Not here

The raw Tenable findings, plugin output and the lab's other hosts stay out of the repo, and so does `flow/environment.json`,
the eight hosts' findings, which `build_flow.py` builds locally. So do the per-CVE CVSS scores, severities and flaw
classes, and the plans for every other CVE. Only the fields above are kept.
