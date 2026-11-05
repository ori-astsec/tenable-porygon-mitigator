# The flow

Given a network map, the findings on each host and a list of mitigations, the flow answers: what can an attacker reach,
which CVEs does that leave exposed, and which fix helps without breaking anything? A person then approves the change, and
the flow checks the result. **All of it runs on a simulated network: applying a plan edits a model and sends the firewall
changes to a mock firewall on this machine, and no real firewall or machine changes.**

## Where code stops, the agent proposes

Most steps are code. Where code stops, the agent can propose something, and code checks it before it counts:

| Step | What the agent does | What code checks |
|---|---|---|
| Collect | `flow_read_source` and `flow_save_source`: converts a file in another format | The readers accept the shape, and every name and address is in the text it read. The run is marked `model_converted` |
| Map | `flow_propose_zone`: places a host code couldn't | The zone exists, and it's refused if anything would stop counting as open. It's marked `placed_by: model` |
| Normalize | Reads scanner text into details | They can only add exposure, and a class needs a quote |
| Scan | `flow_check_path`: a zone the scan doesn't cover | Code gives the answer, and it isn't added to the funnel |
| Match | `flow_find_mitigations`: finds new ones | Code simulates each one |
| Recommend | `flow_try_mitigations`: tests another set | Code simulates it and gives the verdict. Held mitigations still need a person |
| Verify | Reads the firewall's log through `flow_verify` | Code decides pass, fail and whether to advise rollback |

Tag and Plan stay code, and only a person can Approve. A converted source can still be wrong: a real rule left out reads as
closed, and the text check can't see what's missing. That's why the run says so. `flow_read_source` only reads source-like
files, and refuses hidden folders and names that look like secrets, but it can't know which path a person really meant.

## The mock firewall

`porygon flow apply` sends a plan's firewall changes as PAN-OS XML API calls to a mock (`integrations/panos/mock.py`):
threat exceptions on a vulnerability profile, the profile on a rule, or a deny rule moved to the top, then a commit. It
reads the config back and refuses the plan if that isn't what was planned, so nothing applies. `flow_verify` reads it
again and fails if the firewall has drifted from the model, and `porygon flow rollback` loads the earlier config and
commits it. `porygon flow firewall` shows the calls that were sent.

**Traffic.** Before planning, `flow_watch_traffic` lets the agent read the mock's traffic log over the API (a log job, as on
a real firewall) and replays each session against each mitigation: what it would drop that has to keep working, unknown
traffic it would drop, and attacks it would stop. A mitigation that drops needed traffic is held, including a signature
that false-alarms on it, which `allowed_flows` alone can't show. After a person applies, `flow_verify` reads the log again:
needed traffic now dropped fails verify and sets `rollback_advised` with the reason. Unknown traffic dropped is listed for a
person to look at, and traffic a person accepted breaking when they planned it doesn't count. The agent reports it and
gives the rollback command, but only a person can run it. `examples/flow/nightly-job-environment.json` shows this: a job the
watch can't see starts after the change, and trips the signature.

The log is simulated from `observed_traffic` in the environment (`sources/traffic.json` when collecting), and the mock works
out each session's fate from its own running config. A session is `needed` if it matches an allowed flow, `attack` if it
trips a signature otherwise, and `unknown` if neither, so real traffic would need a better answer than that.

The mock isn't a device and enforces nothing. It listens on 127.0.0.1 with a key made for that run, only while a call
runs, and keeps its config in the run's folder. The code that sends changes refuses any address but this machine, so it
can't reach a real firewall. It speaks only the calls a plan needs, and its commit only checks that a rule's profile and
services exist. Host changes, such as stopping a service, stay in the model, and a device that isn't PAN-OS is listed as
not sent. That these calls would work on a real PAN-OS device is untested.

## Steps

| Step | MCP tool | CLI | What happens |
|---|---|---|---|
| Map | `flow_collect` | `flow collect` | Reads firewall, router and asset sources (prepared files here) |
| Map | `flow_map_routes`, or `flow_load_environment` for a prepared file | `flow map`, or `flow load`, `flow demo` | Joins them, places each host in a zone, and maps routes to the rule deciding each path |
| Tag | `flow_vulnerabilities_to_normalize`, `flow_save_normalized` (the `porygon-normalizer` subagent, on Haiku) | none | Extracts each CVE's details from the scanner's text |
| Scan | `flow_reachability` | `flow reach` | Which hosts every attacker zone can reach, through the firewall rules |
| Scan | `flow_tag_cves` | `flow tags` | The runtime analysis: a verdict for each CVE on each host, and the funnel |
| Recommend | `flow_match_mitigations`, `flow_find_mitigations` | `flow match` | Simulates each mitigation: what it protects, what it breaks. Can also find more by web search or Threat Vault |
| Recommend | `flow_recommend_plan` | `flow recommend` | What to mitigate and why, worked out before asking anyone |
| Recommend | `flow_plan_change` | `flow plan` | The exact change, its impact, where to try it first, and its hash |
| Approve | none | `/porygon-mitigator:porygon-apply <hash>`, `flow apply` | A person applies the plan to the simulation |
| Verify | `flow_verify` | `flow verify` | Recomputes from the changed network, compares it with the plan, and fails on anything else that changed |
| Verify | none | `/porygon-mitigator:porygon-rollback`, `flow rollback` | Restores the network as it was before the plan |
| Show | `flow_dashboard` | `flow report --out f.html` | The dashboard, inline as an MCP App or as one HTML file |

Each step writes JSON under `~/.porygon/flow/<run id>/` (`PORYGON_FLOW_DIR` moves it), so the MCP server and a terminal see
the same run. The same inputs give the same run id, and the same plan hash as long as the saved normalized details match. A run with an applied plan won't restart, and no other run starts on top of it: roll it
back, or pass `--restart` to `flow load`, `flow map` or `flow demo`. The MCP tool has no such option, and it needs absolute paths.

The flow refuses input it can't evaluate instead of guessing: an unknown zone, device or host, a duplicate id, no attacker
zone, or a rule with a destination it can't read (a named address object). Replace those with CIDRs or host ids. Otherwise
the rule would fall through to the default deny and its hosts would read as safe.

## Collecting the network

The hard part of this work comes before any analysis. A firewall rule says `addr-web-01`, not an IP. A route points at a
device or an interface. Which rule decides a path only shows once routes and rules are joined. So the flow does it as visible steps, reading from a `sources/` folder:

| Step | File | What it holds |
|---|---|---|
| `firewall` | `firewalls/<device>.json` | Zones, routes, address and service objects, security rules, IPS profiles |
| `router` | `routers/<device>.json` | Routing tables |
| `assets` | `assets.json` | Each host's addresses and zone, and network events, which become the allowed traffic list |

**In the demo these files are prepared in advance. No firewall, router or scanner is contacted, and each step says so.** They're shaped
like real exports, and a test checks that collecting them gives the same reachability as `environment.json`.
Hosts and findings come from `environment.json` beside the folder, and `mitigations.json`
and an optional `normalized.json` from there too. `flow_map_routes` then shows, for every path from an attacker zone, the route
each device picks and the one rule that decides it, plus the rules no such path reaches. Two exports that disagree about a zone stop the run, and a reference it can't resolve does too, and so does a rule depending on something the model can't represent (a specific source,
a negated address, a specific application on any service, a zone the routes disagree with). Disabled rules are skipped.

A real Palo Alto firewall can fill `firewalls/<device>.json`: `porygon panos collect --host <firewall> --out
sources/firewalls/<device>.json` reads it over the XML API, read-only (add `--target <serial>` to go through Panorama, and
`--device-group` for that group's pre- and post-rules). It resolves each vulnerability profile to the signatures it blocks, so
`vulnerability_profiles` holds what the device really enforces, and adds an `ips` section: the content version, the installed
signatures that name a CVE, and threat-log hits per signature. Router and asset files are still prepared.
Zones come without a kind, so mark which ones are attacker vantages before loading.

## Tagging CVEs

A scanner finding names a product and a fix, not which process runs it or what an attacker needs. The `porygon-normalizer`
subagent, on Haiku, extracts per CVE: flaw class, process names, loaded libraries, protocols, affected versions,
exploitation requirements and constraints. Requirements from the CVSS vector are added by code.

Model output can only add exposure, never remove it. A process name can turn a CVE into `reachable` on a reachable host. A
wrong one can at most turn `host_reachable` into `not_seen_running`, which still counts as exposed. Neither clears an
`unknown`. A flaw class is for a person to read and never changes a
verdict, and it's kept only if it quotes the finding's own words. So a model can raise a false alarm, but can't clear a CVE.

For many CVEs at once, `porygon tag --environment environment.json --out normalized.json` does the same outside the agent:
it adds each CVE's public record (CVE.org and NVD) to the scanner text, asks Haiku for the same fields in batches, and runs
the same checks (`flow/normalize.py`), so a class is kept only when its quote is in that text. The flow reads the
`normalized.json` beside `environment.json` when it collects.

## Runtime analysis

Priority comes from one question per host: can the internet reach it? There's no port data and no port analysis. Each CVE on
each machine then gets one verdict, by checking that against what's running there. The Normalize step names the software, and
the machine's own processes and services say whether it's running.

| Verdict | Meaning |
|---|---|
| `reachable` | The internet reaches the host, and the scanner reached this service over the network or the software named for this CVE is running there |
| `host_reachable` | The internet reaches the host, but nothing ties this CVE to anything running there. Weaker evidence |
| `not_seen_running` | The internet reaches the host, and the software named for this CVE isn't among what it reports running. **Still counted as exposed** |
| `not_reachable` | The rules stop every path, or it's exploited from the client side |
| `local_only` | It needs local access |
| `unknown` | The host isn't on the map or has no address the rules can match, or the map doesn't connect it. Never safe |

A rule either opens a host or doesn't. An allow rule opens it whatever services it names. A deny limited to some services or
applications is left out when a firewall export is read, because it can't be said to close the host, so we err toward exposed.
A CVE counts as protected by a signature only if every open path to the host carries it. Whether the signature catches the exploit
is assumed. A host setting counts wherever it applies.

A shared host such as `svchost.exe` says nothing about a flaw, so it ties nothing, and neither does a long list of names, which
is the machine's own processes copied back. A wrong name can raise a false alarm but can't clear a CVE.

## Mapping routes to what sits in front of a device

Give devices `routes`. The most specific route for a host's address decides its zone, and `next_hop_device` gives the chain
of devices traffic crosses to reach it. A declared `zone` on the host wins, then routes, then zone `cidrs`. A default route
never places a host, and the most specific route across all entry devices wins. A host none of those place stays `unknown`, and so does one whose entry devices disagree or whose addresses fall in different zones: a host has one zone here, and picking one would hide what an attacker reaches through the other. Tenable has no firewall routes, so these have to come from the firewall's configuration.

## The funnel

Each step counts one CVE on one machine, and is a subset of the step before it:

| Step | What it counts |
|---|---|
| All findings | Every CVE on every machine in the data |
| High & critical | What's rated high or critical. A Tenable patch plugin gives all its CVEs one rating, so the lab data replaces it with each CVE's own. A live run keeps the scanner's |
| Remotely exploitable | Of those, not client-side and not needing local access. Tenable's patch plugins give one vector to all their CVEs, so this leans on the flaw's class too |
| Exposed and known exploited | Of those, on CISA's list, and an open path from an attacker zone reaches the machine |
| Unmitigated | Of those, what the recommended mitigations would leave open, or what an applied plan left open |

The funnel keeps a finding even when nothing confirms which service is running, so a weaker `host_reachable` verdict still counts. The bar under it splits the critical ones by evidence.

A finding the data can't judge is counted apart, never as exposed or as safe.

Recommend works on known-exploited findings: it picks what stops the most critical ones, then the most findings, and leaves out a mitigation that stops no
known-exploited finding. It still says what stays exposed.

## Files

`Environment` and `FlowMitigation` in `src/porygon_mitigator/flow/models.py` are the schemas, and `examples/flow/` is a
worked example. Firewall rules are ordered with `from_zone`, `to_zone`, `destination` and `action`, and no match means
deny. A deny limited to some services, applications, users, schedules or anything else the flow doesn't read is dropped, since it
can't be said to close a host. A signature only counts when it's on every allow rule that matches, down to the first deny. A mitigation's `kind` is one of:

- `ips_threat_ids`: block these signatures on the firewall rules along the open paths.
- `acl_block`: add a deny rule for the host, only from the zones that expose it. Allowed traffic from those zones breaks.
- `disable_service`: stop a service. Allowed traffic that names the service breaks.
- `host_setting`: apply a setting on the host, limited to `os` when given.

An IPS change adds the signatures to the profile a rule already uses, or attaches a new one if it has none. It counts even where the
scanner only read the patch level: if the software runs and is reachable, the exploit crosses those rules, and if it doesn't, there's
nothing to attack. Whether the signature catches the exploit is assumed. In a run a model converted, it doesn't count, since a model can
write any profile into the rules. A host setting counts either way, since it doesn't depend on the path.

## Finding more mitigations

`flow_find_mitigations` adds to a run's list from `websearch` (live research, needs `ANTHROPIC_API_KEY`) or `threat_vault` (Palo
Alto's Threat Vault, needs `PALO_ALTO_THREAT_VAULT_API_KEY`). The simulation only models Palo Alto signatures, host blocks, stopping
a service and host settings, so anything else is listed with the reason instead of added.

For Snort and Suricata, `porygon rules find <CVE>...` downloads the Snort 3 community and ET Open rulesets and prints each
CVE's rules with their text, whether they ship enabled, and their license. With a collected export, `porygon panos coverage
--export <file> <CVE>...` says per CVE whether the firewall has a signature installed, blocks it in a profile, applies that
profile on an allow rule, and has seen it fire.

## Deciding and approving

`flow_recommend_plan` picks as few mitigations as it can find that stop the most exposure without breaking allowed traffic: most
KEV pairs first, then most pairs, least risk, and firewall changes before host changes. It's a heuristic, so it isn't always the
smallest set. It says why for each, and what stays exposed, separating pairs with no mitigation from pairs a held one would stop.

Each plan then carries its `impact`: what it changes, what it protects, which allowed traffic crosses it (what a false positive
would hit), side effects and rollback. `test_first` says where to try it: see [testing on images](testing-on-images.md).

## Decisions a person has to make

A mitigation is held when it would break allowed traffic, nothing on the path can enforce it, nothing it covers is exposed,
it would stop none of what it covers, or it would leave part of it exposed. `flow_plan_change` refuses a held mitigation
unless you accept the holds (`accept_holds`, `flow plan --accept-holds`). The plan records them, and traffic a plan breaks is
reported as broken by `flow verify`, under `planned_breaks`, not as passing.

## Approval

The agent has no shell and no MCP tool applies a plan, so it can't approve its own work. `/porygon-mitigator:porygon-apply` can't be invoked
by a model. The plan hash covers the whole plan and binds the approval to it on that exact network: a changed network or an
edited plan is refused. This binds the agent and the commands; a model you give its own shell could still run the CLI.

## Tenable

With data from a tenant, `flow apply` also shows what Tenable can record: a `Porygon:planned-<hash>` tag on the affected assets
and a rescan of them (`--rescan-scan-id`), plus Tenable's own fix text as remediation to do separately. Tenable can't push the
firewall change or install a patch through these APIs.

It's a dry run until you add `--tenable-execute`, and even then it only writes after `flow verify` passes. `flow tenable-follow-up
<hash>` retries it for the applied plan. These calls write to your tenant, and a person has to ask for them; no MCP tool can
make them:

| Call | What it does |
|---|---|
| `POST /tags/values` | Creates the tag |
| `POST /tags/assets/assignments` | Puts it on the affected assets (sends their asset ids) |
| `POST /scans/{id}/launch` | Relaunches that scan on the affected hosts (sends their IP addresses); skipped if there are none |

The tag says a plan was approved, not that a machine changed, since nothing outside the simulation did. Rolling the plan back
leaves it in Tenable. These writes have not been run against a live tenant yet, including what Tenable does when a retry creates the same tag again.

## Measuring it

`tests/` checks the engine with no credentials and no network. `evals/flow/agent_eval.py` runs the real agent through Bedrock,
which costs money.

What the agent does in the map and scan steps has a benchmark of its own,
[`evals/flow/bench/`](../evals/flow/bench/README.md). It runs the real agent on synthetic Tenable networks, checks which
files it loaded and what it did with refused input, and has a judge read its answer against the tools' output. Use it
to change the prompts for those steps.
