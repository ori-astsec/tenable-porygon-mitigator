# Contributing

Read [AGENTS.md](AGENTS.md) first: it lists the hard rules (never execute commands, untrusted web content,
declared egress, no secrets, public data only in the cache).

```bash
uv sync
uv run ruff check && uv run mypy && uv run pytest
```

## Add a mitigation source

1. Add the host to `HOSTS` in `src/porygon_mitigator/sources/registry.py` with its purpose and category (and to
   `VENDOR_DOMAINS` if web search should prefer it for a vendor).
2. If it has a per-CVE URL or an API, add a fetcher in `sources/structured.py` (structured data) or a template in
   `sources/discover.py` (pages). Return a `SourceDoc` whose `text` is exactly what the extractor should read.
3. Regenerate the README tables: `uv run python scripts/sync_readme.py`.
4. Add a test with a small fixture (no network).

## Add an IPS/WAF catalogue

1. Write a pure parser in `catalogs/parsers.py` (bytes in, `{CVE: [rule ids]}` out) and a loader in
   `catalogs/sync.py`.
2. Add one `ProductTemplate` per product that enforces those rules in `catalogs/templates.py`, with steps in your
   own words from the vendor's public documentation.
3. Store rule IDs and links only. Licensed data goes in `PRIVATE_SOURCES` (local work dir, never committed).

## Change the extraction prompt

Prompts live in `extract/prompts.py`. Bump `PROMPT_VERSION`, and check the extracted mitigations on a few real CVEs before and after.

## Cache contributions

New CVE records written from a checkout land in `src/porygon_mitigator/data/cache/`. Review them before committing:
every mitigation must have verified evidence, and the record must contain no machine data.
