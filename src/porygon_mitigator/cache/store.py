"""The JSON cache: one file per CVE, `cves/<year>/<CVE>.json`, in two layers.

The seed layer ships with the package (and is committed in the repo). The writable layer is where new research lands;
from a source checkout the two are the same directory, so new mitigation instances show up as files to commit.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
import time
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Literal

from porygon_mitigator.config import Settings
from porygon_mitigator.models.cve import CveRecord

CVE_ID = re.compile(r"^CVE-(\d{4})-(\d{4,})$")
MAX_AGE = timedelta(days=60)
FRESHNESS_GATES_DAYS = (7, 90)

Layer = Literal["seed", "local"]


def normalize_cve_id(cve_id: str) -> str:
    cve_id = cve_id.strip().upper()
    if not CVE_ID.match(cve_id):
        raise ValueError(f"not a CVE ID: {cve_id!r} (expected CVE-YYYY-NNNN)")
    return cve_id


def cve_path(base: Path, cve_id: str) -> Path:
    cve_id = normalize_cve_id(cve_id)
    year = cve_id.split("-")[1]
    return base / "cves" / year / f"{cve_id}.json"


def freshness(record: CveRecord, now: datetime | None = None) -> tuple[bool, str]:
    """Fresh unless older than MAX_AGE, or the CVE's age crossed a gate (7 / 90 days after publication) since the
    record was computed: advisories gain workarounds in the first weeks, so those are worth a re-check."""
    now = now or datetime.now(UTC)
    computed = record.computed_at if record.computed_at.tzinfo else record.computed_at.replace(tzinfo=UTC)
    age = now - computed
    if age > MAX_AGE:
        return False, f"computed {age.days} days ago (max {MAX_AGE.days})"
    published = record.facts.published
    if published:
        for gate in FRESHNESS_GATES_DAYS:
            gate_time = datetime.combine(published + timedelta(days=gate), datetime.min.time(), tzinfo=UTC)
            if computed < gate_time <= now:
                return False, f"the CVE turned {gate} days old after this record was computed"
    return True, f"computed {age.days} days ago"


def _atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
        for attempt in range(5):
            try:
                tmp.replace(path)
                break
            except PermissionError:  # Windows: a reader may hold the target open briefly
                if attempt == 4:
                    raise
                time.sleep(0.1 * (attempt + 1))
    finally:
        tmp.unlink(missing_ok=True)


def dump_record(record: CveRecord) -> str:
    """Stable, diff-friendly JSON: model field order, lists sorted by stable keys, two-space indent, trailing \\n."""
    record = record.model_copy(deep=True)
    record.mitigations.sort(key=lambda item: (item.status != "active", item.layer, item.type, item.id))
    record.sources.sort(key=lambda item: (item.origin, item.url))
    payload = record.model_dump(mode="json", exclude_none=False)
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"


@dataclass(frozen=True)
class CachedRecord:
    record: CveRecord
    layer: Layer
    path: Path


@dataclass
class CacheStore:
    write_dir: Path
    seed_dir: Path

    @classmethod
    def from_settings(cls, settings: Settings) -> CacheStore:
        return cls(write_dir=settings.writable_cache_dir(), seed_dir=settings.seed_cache_dir())

    def _layers(self) -> list[tuple[Layer, Path]]:
        if self.write_dir.resolve() == self.seed_dir.resolve():
            return [("seed", self.seed_dir)]
        return [("local", self.write_dir), ("seed", self.seed_dir)]

    def get(self, cve_id: str) -> CachedRecord | None:
        """The newest record for the CVE across layers (by computed_at)."""
        found: list[CachedRecord] = []
        for layer, base in self._layers():
            path = cve_path(base, cve_id)
            if path.is_file():
                record = CveRecord.model_validate_json(path.read_text(encoding="utf-8"))
                found.append(CachedRecord(record=record, layer=layer, path=path))
        if not found:
            return None
        return max(found, key=lambda item: item.record.computed_at)

    def put(self, record: CveRecord) -> Path:
        path = cve_path(self.write_dir, record.cve_id)
        _atomic_write(path, dump_record(record))
        return path

    def list(self) -> list[CachedRecord]:
        seen: dict[str, CachedRecord] = {}
        for layer, base in self._layers():
            for path in sorted((base / "cves").glob("*/CVE-*.json")):
                cve_id = path.stem
                if cve_id in seen:
                    continue
                record = CveRecord.model_validate_json(path.read_text(encoding="utf-8"))
                seen[cve_id] = CachedRecord(record=record, layer=layer, path=path)
        return sorted(seen.values(), key=lambda item: item.record.cve_id)


def record_age_days(record: CveRecord, today: date | None = None) -> int:
    today = today or datetime.now(UTC).date()
    return max(0, (today - record.computed_at.date()).days)
