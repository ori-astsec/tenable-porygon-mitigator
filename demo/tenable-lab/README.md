# Demo dataset: the simulated Tenable lab network

The network-phase demo: eight hosts from the Tenable partner lab, the simulated network in front of them, the
mitigations the demo plans with, and the public part of the per-CVE snapshot the coverage numbers came from.

Host names, IP addresses and asset ids are random replacements for the lab's real ones. The CVEs, ports, operating systems
and services are the lab's own.

## The simulated network

The Tenable lab has no firewall in front of any host: its FortiGate, PAN-OS and Check Point appliances are scan
targets on the management subnet. For the demo, the eight hosts below sit behind a Palo Alto PA-820 (`fw-1`, PAN-OS 11.1.1),
with the lab's router (`router-56` here) between the firewall and the hosts. Only the
firewall placement is simulated. Palo Alto was chosen because it gives the most coverage: it is the best single
vendor for seven of the eight hosts, and no mix of vendors adds more than 16 CVEs.

| Segment | Hosts |
|---|---|
| Windows servers | dc-2c52, sql-647e, srv-2539 |
| Workstations | wks-7705, wks-90cc |
| Linux servers | ubu-8ced, cent-fa5b, ubu-a393 |

`ubu-a393` really sits behind its own gateway; the simulation moves it behind the same router as the others.

## Files

| File | What it holds |
|---|---|
| `hosts.json` | The hosts (random asset ids, platform, segment) and the simulated `network_path` |
| `overlays/<host>.json` | That `network_path` as a profile overlay: `porygon tenable profile --asset <uuid> --overlay overlays/<host>.json` |
| `cves.jsonl` | Every CVE on the hosts' open findings, with its CVSS vector and CISA KEV flag |
| `plans.jsonl` | The documented mitigation plans for five known-exploited CVEs, kept as examples: type, vendor, OS, title, source link |
| `palo_threat_ids.json` | The Palo Alto threat IDs for the 22 known-exploited CVEs the demo plans for |
| `found_mitigations.json` | Mitigations this project's own search found, with verified quotes: today, Tomcat's for CVE-2025-24813 |
| `flow/mitigations.json` | The 31 mitigations the flow plans with on these hosts: 22 Palo Alto signature sets and 9 host settings |
| `flow/sources/` | The simulated firewall, router, asset and traffic exports |
| `reproduce.py` | Prints what these files hold, offline |

Snapshot taken 2026-11-03. The findings come from the Tenable partner lab tenant. The mitigation plans and threat IDs
come from an external vulnerability dataset; plan sources are the public vendor and advisory pages they cite. Per CVE, only the
public fields are kept, and plans only for the five examples: SIGRed (CVE-2020-1350), PrintNightmare (CVE-2021-34527),
BlueKeep (CVE-2019-0708), Log4Shell (CVE-2021-44228) and HTTP/2 Rapid Reset (CVE-2023-44487).

## The numbers

`uv run python demo/tenable-lab/reproduce.py` prints what these files hold:
10,933 CVEs, 4,049 of them with a network attack vector and 218 on CISA KEV, and the 57 plans kept for the five examples.

## The flow on this network

`flow/mitigations.json` was built from the full plan set with `mitigations_from_plans`
([`flow/plans.py`](../../src/porygon_mitigator/flow/plans.py)), plus `found_mitigations.json`, and is kept as it was. The
hosts and their findings are in `flow/environment.json`, which isn't committed: it holds the lab's real findings.
`build_flow.py` builds it locally from a Tenable export (`--assets`, `--findings`), the CISA KEV catalogue (`--kev`) and a
private file mapping the lab's real names, addresses and asset ids to the random ones (`--identities`, never committed).
Then:

```bash
uv run porygon flow load --environment demo/tenable-lab/flow/environment.json \
  --mitigations demo/tenable-lab/flow/mitigations.json
```

The hosts, ports and findings are the lab's own. The firewall rules are not: the lab has no firewall in front of
anything, so `build_flow.py` publishes a few services chosen so the reachable CVEs are ones with a documented mitigation.
Read any "reachable" count from this environment as the result of that choice, not as a measurement.

The build keeps only remote findings Tenable's plugin rates high or critical, plus known-exploited ones, so its findings
are a subset. The whole-lab numbers in `docs/impact.md` aren't filtered this way. The committed results also gave each
finding its CVE's own severity and flaw class; a rebuild from this folder has neither, so it keeps the plugin's severity
and more findings stay remotely exploitable than in the README's pictures and
[`final-2026-11-04/`](../../evals/flow/results/final-2026-11-04/).

Without the environment, the evals that use the lab skip it or say how to build it.
