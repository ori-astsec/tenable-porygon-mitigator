---
name: exposure-funnel
description: >-
  Narrow a Tenable environment's findings to what an IPS can actually stop, as a funnel: all open findings, then
  high + critical, then remote (network attack vector), then how many have an IPS signature, per vendor (Cisco
  Talos Snort 3, Proofpoint ET Open, Palo Alto, Check Point). Use when the user asks "how much of our exposure can
  an IPS cover", "which findings are remote and critical", "how many of our vulns have a Snort/Check Point
  signature", "give me the funnel for this tenant/subnet", or wants a network-protection view of Tenable data
  before planning compensating controls. Not for a single CVE on one machine (use porygon-mitigator).
---

# Exposure funnel: from all findings to the ones an IPS can stop

The funnel runs on porygon's MCP tool `exposure_funnel` (CLI: `porygon funnel`). It counts, never guesses: every
number in your answer comes from the tool's result.

## The four stages

1. **All open findings**: every open or reopened plugin result on every asset in scope.
2. **High + critical**: the plugin's CVSS base score (v3, else v2) is 7.0 or more.
3. **Remote**: the plugin's CVSS attack vector is Network.
4. **Stoppable by an IPS signature**: at least one of the finding's CVEs has a signature in an IPS catalogue, any
   vendor. The vendor table splits this stage per vendor.

A finding is one plugin on one asset, so the same CVE on ten assets is ten findings. Each stage also gives the
distinct assets and CVEs.

## Workflow

1. **Pick the scope.** The whole tenant by default; a subnet when the user names one (`cidr`, e.g.
   `10.0.48.0/22`); or findings the user already has (`tenable_findings`, vulnerability export rows, for
   example from the Tenable Hexa AI MCP server).
2. **Run it.** Call `exposure_funnel`. Without the MCP server, run
   `porygon funnel --tenable [--cidr ...]` or `porygon funnel --findings-file export.json`.
   - Check Point has no downloadable catalogue. Check Point publishes its IPS advisories online
     (advisories.checkpoint.com, one CPAI advisory per protection), so the tool web-searches that site for the
     most urgent remote CVEs (CISA KEV first, then VPR), up to `checkpoint_searches` (default 25), and caches
     what it finds. Raise the cap when the user wants Check Point coverage across more CVEs; each search is a
     paid Claude web search.
3. **Report.** In this order:
   - the funnel table: each stage's findings, assets and CVEs, and the share kept from the stage above;
   - the vendor table, with each vendor's note. For Check Point always say how many remote CVEs were searched
     ("searched 25 of 7,000"): its count is a floor, not coverage;
   - the top findings an IPS can stop, with their signature IDs;
   - the tool's notes (vendors not covered, missing keys).
4. **Hand off.** For any finding the user wants to act on, offer porygon-mitigator's `assess_machine` /
   `find_mitigations` for that CVE and asset: it checks whether a device of the right vendor sits in front of the
   machine and gives the steps, risk and rollback.

## Hard rules

- **Only report numbers the tool returned.** Don't extrapolate Check Point's searched sample to the whole funnel,
  and don't add vendors or signatures from memory.
- **A signature existing is not protection in place.** Say "has a signature at <vendor>", never "is protected":
  the device has to be in the traffic path, run that vendor's engine, and have the rule enabled in block mode.
- **Say what is not covered.** FortiGuard (Fortinet) isn't machine-readable, and Palo Alto needs a Threat Vault
  key; mention them when the user's devices are from those vendors.
- **Never run commands or change device policy.** Show steps for a person to review.
- **Findings stay local.** Don't paste asset names, addresses or findings into public places.
