# Tenable One integration (experimental)

Two ways to feed Tenable data into porygon:

1. **Through Claude (no extra keys in porygon).** With the Tenable Hexa AI MCP server connected
   (`https://cloud.tenable.com/mcp/`, your tenant's API keys in `X-ApiKeys`), look up the asset and its findings
   there, then pass the asset record as `tenable_asset` (and the vulnerability rows as `tenable_findings`) to
   porygon's `assess_machine` or `find_mitigations`.
2. **Directly.** Set `TENABLE_ACCESS_KEY` and `TENABLE_SECRET_KEY`, then
   `porygon tenable profile --asset <asset-uuid> --out output/asset.json` exports the asset and its findings with the
   standard bulk export API (read-only), or `--asset-file` maps an export you already have.

What maps: OS and appliance identity (`operating_systems`), installed software CPEs, open ports, internet exposure
(`is_public`), endpoint tools (installed software and connector sources), scanner findings, and the enrichment
plugins for packages (22869/20811/83991), listeners (25221/34252) and services (10456).

What doesn't: the security devices in front of the asset. Add them with `--overlay` (a partial profile with
`network_path`) so WAF/IPS signatures can be matched.

Mapping and parsers follow Tenable's public export schema and common plugin output formats; validate them against
your tenant before relying on them.
