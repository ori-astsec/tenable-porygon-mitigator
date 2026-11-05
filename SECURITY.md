# Security

## Reporting a vulnerability

Please report security issues privately through GitHub Security Advisories on this repository
("Report a vulnerability"). Don't open a public issue for a vulnerability. We aim to acknowledge reports within
three working days.

## Threat model

porygon-mitigator reads untrusted web content and turns it into advice that administrators may act on. The main
risks, and what the code does about each:

| Risk | Mitigation in the code |
|---|---|
| A malicious or compromised advisory page injects instructions into the model | Page text is wrapped in an `<untrusted-advisory>` envelope that it can't close; the system prompt says it is data. Every kept quote and command must appear verbatim in that text, so the model can't invent content. |
| A verbatim but dangerous command (download-and-run, disabling AV) reaches a user | Command linting forces risk 3 with a plain warning; the skill and MCP instructions forbid running commands. porygon never executes anything. |
| Server-side request forgery / unexpected egress | One HTTP client, https only, host allowlist (`sources/registry.py`) re-checked on every redirect hop, size cap, no binary downloads. The README egress table is tested against the registry. |
| Secrets leak | Keys are read from environment variables only, never logged, written or put in URLs. `TenableConfig` hides keys from `repr`. gitleaks runs in pre-commit and CI over the full history. |
| Machine data leaks into the shared cache | The cache schema holds CVE-level data only; machine profiles and per-machine reports stay in memory, in the gitignored `output/` or in `~/.porygon/flow`. |
| Copyrighted third-party text redistributed | The committed cache holds short quotes (at most 300 characters), our own summaries and URLs. Full page text stays in the gitignored `.cache/`. Catalogue indexes hold rule IDs and links only. |
| Stale or withdrawn advice | Records carry retrieval dates and a freshness policy; withdrawn workarounds are flagged and never ranked as applicable. |
| Excessive agency through MCP | No MCP tool changes anything outside this machine. `find_mitigations` and `exposure_funnel` write local caches and the `flow_*` tools write run files under `~/.porygon/flow` (`flow_find_mitigations` can also write the local CVE cache). `flow_load_environment` refuses to restart a run with an applied plan. Applying or rolling back a plan isn't a tool: a person runs `/porygon-mitigator:porygon-apply`, and the `porygon` agent has no shell. That gate binds the agent and the slash commands, not a model given its own shell access to the CLI. Tenable writes (a tag and a rescan) need `--tenable-execute` on that same command. All tools declare explicit annotations. stdio transport only, no listener. |

## Outbound connections

See the egress table in the [README](README.md#sources-and-outbound-connections). Data sent: CVE IDs and advisory
text to the Anthropic API; CVE IDs to CVE.org, NVD, OSV and vendor/distro sites; your Tenable API keys only to your
Tenable tenant, plus asset ids and IP addresses if a person passes `--tenable-execute`. Machine profiles are never sent.
