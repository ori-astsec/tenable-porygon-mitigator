# Tenable One integration (experimental)

Two ways to feed Tenable data into porygon:

1. **Through Claude (no extra keys in porygon).** With the Tenable Hexa AI MCP server connected
   (`https://cloud.tenable.com/mcp/`, your tenant's API keys in `X-ApiKeys`), look up the asset and its findings
   there, then pass the asset record as `tenable_asset` (and the vulnerability rows as `tenable_findings`) to
   porygon's `assess_machine` or `find_mitigations`.
2. **Directly.** Set `TENABLE_ACCESS_KEY` and `TENABLE_SECRET_KEY`, then
   `porygon tenable profile --asset <asset-uuid> --out output/asset.json` exports the asset and its findings with the
   standard bulk export API (read-only; the only writes are the opt-in follow-up in [flow.md](flow.md#tenable)), or `--asset-file` maps an export you already have.

What maps: OS and appliance identity (`operating_systems`), installed software CPEs, open ports, internet exposure
(`is_public`), endpoint tools (installed software and connector sources), scanner findings, and the enrichment
plugins for packages (22869/20811/83991), ports (11219/14272/34220/14274/25221/34252) and services (10456, with disabled ones from 44401).

What doesn't: the security devices in front of the asset. Add them with `--overlay` (a partial profile with
`network_path`) so WAF/IPS signatures can be matched.

## Scan coverage

`porygon tenable coverage` (MCP tool `scan_coverage`) reports what the VM scanner could not see on each machine, without
any model calls:

| Status | Meaning |
|---|---|
| `surface_only` | No local checks ran: no login, a failed login, a login the scan didn't use, or a failed patch assessment |
| `partial` | Local checks ran, with gaps such as stale findings, web tests disabled or ports not probed from the network |
| `unknown` | Has findings, but no scan information says whether local checks ran |
| `no_scan_data` | No open findings or scan information in this export; that doesn't prove it was never scanned |
| `covered` | No high or medium gaps found |

`looks_clean` marks a `surface_only` machine with no severe findings: the one most likely to be read as safe.

It reads plugins 19506, 141118, 104410, 110385, 117887, 21745, 117886, 24260 and 11936 from the vulnerability export,
so the export must include informational rows. A live read exports every asset and open finding in the tenant.

The report covers Tenable VM scan data only. Findings from Tenable Cloud Security and OT Security aren't included.

Mapping and parsers follow Tenable's public export schema and common plugin output formats; validate them against
your tenant before relying on them.
