"""Source healthcheck: are the structured sources, page templates and rule catalogues still reachable, and do the
parsers still find what they found when they were written?

    uv run python scripts/healthcheck.py           # everything (downloads the rule catalogues, ~100 MB)
    uv run python scripts/healthcheck.py --quick   # skip the catalogue downloads

Each check uses a well-known CVE. Exits 1 if any check fails. Needs no API key (NVD_API_KEY is used if set). Runs
weekly in CI so a vendor changing its format shows up as a failed job, not as silently missing mitigations.
"""

from __future__ import annotations

import asyncio
import json
import sys
import tempfile
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path

from porygon_mitigator.catalogs.sync import CATALOGUE_MAX_BYTES, DEFAULT_SOURCES, LOADERS, MIN_SHRINK_RATIO
from porygon_mitigator.config import Settings, package_data_dir
from porygon_mitigator.intel.cverecord import fetch_cve_record, parse_cve_record
from porygon_mitigator.intel.kev import load_kev
from porygon_mitigator.intel.nvd import fetch_nvd
from porygon_mitigator.sources.net import Http
from porygon_mitigator.sources.registry import TEMPLATES
from porygon_mitigator.sources.structured import msrc_document, osv_documents, redhat_document, ubuntu_document
from porygon_mitigator.sources.text import mentions_cve, prepare_source_text

LOG4SHELL = "CVE-2021-44228"
TEMPLATE_CVES = {"paloalto": "CVE-2024-3400"}  # templates for one vendor's CVEs; the rest use LOG4SHELL


class CheckFailed(Exception):
    pass


def require(condition: object, message: str) -> None:
    """Not `assert`: python -O would strip it and every check would pass."""
    if not condition:
        raise CheckFailed(message)


@dataclass
class Check:
    name: str
    run: Callable[[Http, Path], Awaitable[str]]
    heavy: bool = False


async def _cve_org(http: Http, _work: Path) -> str:
    record = parse_cve_record(await fetch_cve_record(LOG4SHELL, http))
    require(record["description"] and record["affected"], "no description or affected ranges")
    return f"{len(record['affected'])} affected ranges, {len(record['references'])} references"


async def _nvd(http: Http, _work: Path) -> str:
    record = await fetch_nvd(LOG4SHELL, http, Settings().nvd_api_key)
    if not record or not record["affected"]:
        raise CheckFailed("no CPE ranges")
    return f"{len(record['affected'])} CPE ranges"


async def _kev(http: Http, work: Path) -> str:
    kev = await load_kev(http, work)
    require(LOG4SHELL in kev, "Log4Shell missing from the KEV feed")
    return f"{len(kev)} entries"


async def _redhat(http: Http, _work: Path) -> str:
    doc, attempt, fixes = await redhat_document(LOG4SHELL, http)
    if doc is None or not fixes:
        raise CheckFailed(f"status {attempt.status}, {len(fixes)} package states")
    return f"{len(fixes)} package states, {len(doc.text)} chars"


async def _ubuntu(http: Http, _work: Path) -> str:
    _doc, attempt, fixes = await ubuntu_document("CVE-2024-6387", http)
    require(attempt.status in ("ok", "no_mitigation") and fixes, f"status {attempt.status}, {len(fixes)} states")
    return f"{len(fixes)} package states ({attempt.status})"


async def _msrc(http: Http, work: Path) -> str:
    # SIGRed: its CVRF entry still carries the registry workaround (Follina's was removed in 2026).
    doc, attempt = await msrc_document("CVE-2020-1350", http, work)
    if doc is None or "TcpReceivePacketSize" not in doc.text:
        raise CheckFailed(f"status {attempt.status}, workaround missing")
    return f"{len(doc.text)} chars"


async def _osv(http: Http, _work: Path) -> str:
    docs, attempts = await osv_documents(LOG4SHELL, http)
    require(docs, f"no advisories ({', '.join(a.status for a in attempts) or 'no attempts'})")
    return f"{len(docs)} advisories"


def _template_check(name: str, url_template: str) -> Callable[[Http, Path], Awaitable[str]]:
    async def run(http: Http, _work: Path) -> str:
        cve = TEMPLATE_CVES.get(name, LOG4SHELL)
        url = url_template.format(cve=cve, cve_lower=cve.lower())
        result = await http.get(url)
        text = prepare_source_text(result.text, result.content_type, cve)
        require(mentions_cve(text, cve), f"{url} no longer mentions {cve} (JavaScript-only now?)")
        return f"{len(text)} chars"
    return run


def _catalogue_check(source: str) -> Callable[[Http, Path], Awaitable[str]]:
    async def run(_http: Http, _work: Path) -> str:
        path = package_data_dir() / "catalogs" / f"{source}.json"
        stored = len(json.loads(path.read_text(encoding="utf-8"))["cves"]) if path.exists() else 0
        async with Http(max_bytes=CATALOGUE_MAX_BYTES, timeout=120.0) as http:
            mapping, _links, _urls = await LOADERS[source](http)
        require(mapping and len(mapping) >= stored * MIN_SHRINK_RATIO, f"{len(mapping)} CVEs vs {stored} committed")
        return f"{len(mapping)} CVEs ({stored} committed)"
    return run


CHECKS: list[Check] = [
    Check("cve.org record", _cve_org),
    Check("nvd cve api", _nvd),
    Check("cisa kev feed", _kev),
    Check("red hat security data", _redhat),
    Check("ubuntu cve json", _ubuntu),
    Check("microsoft cvrf", _msrc),
    Check("osv / github advisories", _osv),
    *(Check(f"template {name}", _template_check(name, url)) for name, url in TEMPLATES),
    *(Check(f"catalogue {source}", _catalogue_check(source), heavy=True) for source in DEFAULT_SOURCES),
]


async def run_checks(quick: bool) -> int:
    failures = 0
    with tempfile.TemporaryDirectory() as tmp:
        async with Http() as http:
            for check in CHECKS:
                if quick and check.heavy:
                    continue
                started = time.monotonic()
                try:
                    detail = "ok: " + await check.run(http, Path(tmp))
                except Exception as error:  # a format change can raise anything: report it, run the rest
                    failures += 1
                    detail = f"FAIL: {type(error).__name__}: {error}"
                print(f"{check.name:<28} {time.monotonic() - started:6.1f}s  {detail}", flush=True)
    print(f"\n{failures} check(s) failed" if failures else "\nall checks passed")
    return 1 if failures else 0


def main(argv: list[str]) -> int:
    return asyncio.run(run_checks(quick="--quick" in argv))


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
