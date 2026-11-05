"""Check Point IPS protections, found by Claude web search over advisories.checkpoint.com.

Check Point publishes one IPS advisory (CPAI-YYYY-NNNN) per protection, but the site answers crawlers with a bot
challenge, so there is no catalogue to download. Instead one web search per CVE, restricted to that site, asks for
its advisories; a result counts only when its URL is an advisory page and its title names the CVE. Hits and misses
go to the local work directory as the `checkpoint` catalogue, so machine assessments pick the hits up too.
"""

from __future__ import annotations

import asyncio
import json
import re
from collections.abc import Callable
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any

from porygon_mitigator.config import Settings
from porygon_mitigator.extract.llm import Llm, SearchHit

SOURCE = "checkpoint"
SEARCH_DOMAIN = "advisories.checkpoint.com"
SEARCH_CONCURRENCY = 4
MISS_TTL_DAYS = 30  # a CVE with no advisory is searched again after this long
_ADVISORY = re.compile(r"^https://advisories\.checkpoint\.com/defense/advisories/public/\d{4}/(cpai-\d{4}-\d+)\.html$",
                       re.IGNORECASE)
SYSTEM = "You find Check Point IPS protection advisories. Search, then list advisory URLs only."
PROMPT = ('Search advisories.checkpoint.com for "{cve}" and list the URL of every Check Point IPS advisory '
          "(CPAI-...) that covers {cve}, one per line. If there is none, say so.")

Progress = Callable[[str], None]


def index_path(settings: Settings) -> Path:
    return settings.work_dir() / "catalogs" / f"{SOURCE}.json"


def load(settings: Settings) -> dict[str, Any]:
    try:
        data = json.loads(index_path(settings).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def protections(cve: str, hits: list[SearchHit]) -> tuple[list[str], str | None]:
    """CPAI IDs (upper case) whose advisory URL and title both point at this CVE, and the first advisory's URL."""
    found: dict[str, str] = {}
    for hit in hits:
        match = _ADVISORY.match(hit.url.strip())
        if match and cve.upper() in hit.title.upper():
            found.setdefault(match.group(1).upper(), hit.url.strip())
    return list(found), next(iter(found.values()), None)


def _due(cve: str, data: dict[str, Any], today: date) -> bool:
    if cve in (data.get("cves") or {}):
        return False
    searched = (data.get("searched") or {}).get(cve)
    try:
        return searched is None or today - date.fromisoformat(searched) > timedelta(days=MISS_TTL_DAYS)
    except ValueError:
        return True


def _save(settings: Settings, data: dict[str, Any]) -> None:
    path = index_path(settings)
    path.parent.mkdir(parents=True, exist_ok=True)
    data.update({"source": SOURCE, "name": "Check Point IPS advisories (web search)",
                 "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
                 "source_urls": ["https://advisories.checkpoint.com/advisories/"],
                 "note": "Protection IDs and advisory links found by web search; misses are listed under searched."})
    path.write_text(json.dumps(data, indent=1, sort_keys=True) + "\n", encoding="utf-8")


async def search(cves: list[str], *, settings: Settings, cap: int, progress: Progress | None = None) -> int:
    """Search the first `cap` CVEs that aren't already known (hits are kept, misses expire). Returns the number of
    new searches run."""
    from porygon_mitigator.catalogs.lookup import reload_indexes

    say = progress or (lambda _message: None)
    data = load(settings)
    data.setdefault("cves", {})
    data.setdefault("searched", {})
    today = datetime.now(UTC).date()
    todo = [cve for cve in dict.fromkeys(cves) if _due(cve, data, today)][:max(0, cap)]
    if not todo:
        return 0
    llm = Llm(settings)
    semaphore = asyncio.Semaphore(SEARCH_CONCURRENCY)

    async def one(cve: str) -> None:
        async with semaphore:
            hits, note = await llm.search(system=SYSTEM, prompt=PROMPT.format(cve=cve), domains=[SEARCH_DOMAIN],
                                          max_uses=1)
        if note != "ok" and not hits:
            return  # a failed search is not a miss; try again next run
        rules, link = protections(cve, hits)
        data["searched"][cve] = today.isoformat()
        if rules:
            data["cves"][cve] = {"rules": rules, "link": link}

    say(f"Check Point: searching {len(todo)} CVE(s) on {SEARCH_DOMAIN}")
    await asyncio.gather(*(one(cve) for cve in todo))
    _save(settings, data)
    reload_indexes()
    found = sum(1 for cve in todo if cve in data["cves"])
    say(f"Check Point: {found} of {len(todo)} searched CVE(s) have an IPS protection (cost ${llm.cost.cost_usd:.3f})")
    return len(todo)
