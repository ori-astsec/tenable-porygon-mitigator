"""CISA Known Exploited Vulnerabilities catalog, downloaded at most once a day into the work directory."""

from __future__ import annotations

import json
import time
from datetime import date
from pathlib import Path
from typing import Any

from porygon_mitigator.models.cve import KevInfo
from porygon_mitigator.sources.net import Http

KEV_FEED = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
MAX_AGE_SECONDS = 24 * 3600


def _date(value: Any) -> date | None:
    try:
        return date.fromisoformat(str(value)[:10]) if value else None
    except ValueError:
        return None


async def load_kev(http: Http, work_dir: Path) -> dict[str, dict[str, Any]]:
    path = work_dir / "kev" / "known_exploited_vulnerabilities.json"
    if not path.exists() or time.time() - path.stat().st_mtime > MAX_AGE_SECONDS:
        result = await http.get(KEV_FEED)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(result.body)
    data = json.loads(path.read_text(encoding="utf-8"))
    return {str(item.get("cveID", "")).upper(): item for item in data.get("vulnerabilities", [])}


def kev_info(entry: dict[str, Any] | None) -> KevInfo | None:
    if not entry:
        return None
    ransomware = str(entry.get("knownRansomwareCampaignUse", "")).lower()
    return KevInfo(
        date_added=_date(entry.get("dateAdded")),
        due_date=_date(entry.get("dueDate")),
        required_action=entry.get("requiredAction"),
        known_ransomware=True if ransomware == "known" else (False if ransomware == "unknown" else None),
        notes=entry.get("notes") or None,
    )
