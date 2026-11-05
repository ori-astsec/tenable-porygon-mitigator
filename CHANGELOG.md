# Changelog

## 0.1.0 (unreleased)

- Flow: priority comes from whether the internet reaches a host, with no port data or port analysis. Each CVE is compared with what's
  running on its machine, and software not seen running stays exposed. A signature counts when it's on every rule letting traffic through, and whether it catches the exploit is assumed. The funnel ends with Unmitigated, every tool
  refuses unknown arguments, the bundled networks have the internet as their only attacker.
- `docs/impact.md`: the flow on all 160 hosts of the lab. `scripts/build_visuals.py` builds the README's pictures from a real run.
- Flow: the funnel runs all findings, high and critical (each CVE's own severity in the lab data), remotely exploitable, exposed and known exploited, unmitigated. Recommend focuses on known-exploited findings.
- Flow: applying a plan sends its firewall changes as PAN-OS XML API calls to a mock firewall on this machine, verify reads
  them back, and rollback restores the config. It refuses any other address, so no real device can change.
- MCP server (`porygon-mcp`) with `find_mitigations`, `assess_machine`, `get_cve_mitigations`, `list_cached_cves`,
  `source_status`, `exposure_funnel`, a CVE record resource and a `mitigate_asset` prompt.
- CLI (`porygon`): `mitigate`, `cache`, `catalogs sync`, `funnel`, `profile`, `tenable profile`.
- Exposure funnel and the `exposure-funnel` skill: Tenable findings -> high/critical -> remote -> stoppable by an IPS
  signature per vendor, with Check Point IPS protections found by capped web search of advisories.checkpoint.com.
- Live research: CVE.org / NVD / CISA KEV facts; Red Hat, Ubuntu, Microsoft CVRF and GitHub advisory data; ranked
  references; Claude web search; Claude extraction with code-side quote and command verification.
- Per-machine matching: affectedness (scanner findings, distro package states, CPE ranges), applicability per layer,
  already-applied checks, ranking and verdicts; machine-aware gap-fill search.
- IPS/WAF catalogues: Snort 3 community, ET Open, F5, Azure WAF, Cloudflare, NetScaler, Palo Alto Threat Vault.
- IPS/WAF signature search for network-reachable CVEs, and a signature-only gap-fill for machines whose in-path
  devices have no applicable rule.
- Tenable One integration skeleton (experimental).
- `porygon panos collect` / `panos coverage`: a read-only PAN-OS XML API collector (firewall, or through Panorama)
  writing the flow's firewall export with resolved vulnerability profiles, installed signatures and threat-log hits,
  and a per-CVE check of whether a signature is installed, blocked and enforced.
- `porygon-normalizer`: a package check names a package, so it names the package's service when the host lists it,
  and a command a person runs (sudo, an installer) isn't a process. `normalizer_eval` places hosts before scoring verdicts.
- A firewall file's `threat_exceptions` are never read as blocked signatures (they are overrides, often allow or alert):
  only `blocked_threat_ids` counts, and `porygon panos collect` writes that. The healthcheck no longer relies on
  `assert` and reports every check even when one raises something unexpected. The `porygon` agent calls `scan_coverage`, which
  reads the live tenant, only when asked.
- `porygon rules find`: the open Snort 3 community and ET Open (Suricata) rules for a CVE, with rule text, default
  state and license.
- `porygon tag`: bulk normalization into the flow's `normalized.json`, from public CVE records and scanner text, with
  the same checks as the flow's normalizer (now shared in `flow/normalize.py`).
- Model grid: extraction, tagging and the agent on Haiku, Sonnet and Opus at
  three effort levels. Extraction prompt `extract-v1` (access restrictions to the named product are a NETWORK_ACL
  control), tagging prompt v4 at effort medium, an agent rule against per-zone counts, and truncated structured output
  handled instead of crashing.
- Tagging eval (`evals/tagging/`): 44 hand-labelled public CVEs, frozen text, five-repeat runs on Bedrock. Its first pick,
  v3b, scored 0.743 vs 0.638 for the first version on the held-out split; the model grid then moved `porygon tag` to
  v4 (`evals/tagging/prompts/v4.md`).
- Map and scan agent benchmark (`evals/flow/bench/`): the real `porygon` agent on synthetic Tenable networks, 11
  behaviours with a dev and a holdout case each, deterministic checks on what it did and a judge, calibrated on hand
  labels, on what it said.
- The `porygon` agent's map and scan prompt, tuned on that benchmark: it says it has no file tools, starts from the run
  that's loaded instead of collecting the bundled example over it, says what a Tenable export lacks and still passes one
  to the loader, quotes the map's totals, and only calls a host closed when the scan says it can tell. On the final code Haiku
  5.5 scores 0.994 on dev and 0.990 on holdout, against 0.950 and 0.923 before, though holdout was read while fixing.
- The flow on a simulated network, from a route mapper to a verified plan: `porygon` agent, `flow_*` MCP tools, MCP App dashboard, approval by `/porygon-mitigator:porygon-apply`.
- Flow steps for collecting simulated firewall, router, asset and vendor sources, mapping routes to single rules,
  normalizing vulnerabilities with a Haiku subagent, recommending a plan, showing its impact, and finding mitigations by
  web search or Threat Vault.
- Scan coverage report (`scan_coverage`, `porygon tenable coverage`): what the VM scanner could not see, per machine.
- The simulated scan names every host it can't judge and why
  (unplaced, unconnected zone, no matchable address), and says how many of its rows
  it lists; collecting refuses a source file that isn't one JSON object.
- Claude Code skill and plugin packaging.
