"""Find open-source IDS/IPS rules for CVEs, with the rule text itself.

The catalogue indexes keep rule IDs only. This downloads the open rulesets (Snort 3 community, ET Open for Suricata),
keeps them in the work directory for a day, and returns every rule whose `reference:cve` names a requested CVE: SID,
message, whether it ships enabled, the full rule, and the license that SID is under. Nothing is committed.
"""

from __future__ import annotations

import io
import re
import tarfile
import time
from collections.abc import Callable, Iterable
from dataclasses import asdict, dataclass
from typing import Any

from porygon_mitigator.catalogs.sync import SNORT3_URL
from porygon_mitigator.config import Settings
from porygon_mitigator.sources.net import FetchError, Http

ET_OPEN_SURICATA_URL = "https://rules.emergingthreats.net/open/suricata-7.0.3/emerging.rules.tar.gz"
RULESET_MAX_BYTES = 64 * 1024 * 1024
CACHE_SECONDS = 24 * 60 * 60
_SID = re.compile(r"\bsid\s*:\s*(\d+)")
_REV = re.compile(r"\brev\s*:\s*(\d+)")
_MSG = re.compile(r'\bmsg\s*:\s*"((?:[^"\\]|\\.)*)"')
_CLASSTYPE = re.compile(r"\bclasstype\s*:\s*([\w-]+)")
_CVE_REF = re.compile(r"reference\s*:\s*cve\s*,\s*(?:CVE-)?(\d{4})-(\d{4,})", re.IGNORECASE)


@dataclass(frozen=True)
class Ruleset:
    key: str
    name: str
    engine: str
    url: str
    license_of: Callable[[int], str]


def _snort3_license(_sid: int) -> str:
    return "GPL-2.0"


def _et_open_license(sid: int) -> str:
    """ET Open's own LICENSE file assigns licenses by SID range."""
    if 1 <= sid <= 3464 or 100_000_000 <= sid <= 100_000_908:
        return "GPL-2.0"
    if 2_000_000 <= sid <= 2_799_999:
        return "BSD (Emerging Threats)"
    return "see the ruleset's LICENSE"


RULESETS: dict[str, Ruleset] = {
    "snort3_community": Ruleset("snort3_community", "Snort 3 community rules (Cisco Talos)", "snort3", SNORT3_URL,
                                _snort3_license),
    "et_open_suricata": Ruleset("et_open_suricata", "Proofpoint ET Open for Suricata 7", "suricata",
                                ET_OPEN_SURICATA_URL, _et_open_license),
}


@dataclass(frozen=True)
class OpenRule:
    cve: str
    ruleset: str
    engine: str
    sid: int
    rev: int
    message: str
    classtype: str
    enabled_by_default: bool
    license: str
    file: str
    rule: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def parse_ruleset(tarball: bytes, ruleset: Ruleset, wanted: set[str]) -> list[OpenRule]:
    """Every rule in the archive that references a wanted CVE, commented-out (disabled by default) ones included."""
    found: list[OpenRule] = []
    with tarfile.open(fileobj=io.BytesIO(tarball), mode="r:gz") as archive:
        for member in archive.getmembers():
            if not member.isfile() or not member.name.endswith(".rules"):
                continue
            handle = archive.extractfile(member)
            if handle is None:
                continue
            for line in handle.read().decode("utf-8", errors="replace").splitlines():
                stripped = line.strip()
                enabled = not stripped.startswith("#")
                rule = stripped.lstrip("#").strip()
                if not rule.startswith(("alert", "drop", "reject", "pass")):
                    continue
                sid = _SID.search(rule)
                if sid is None:
                    continue
                for cve in sorted({f"CVE-{year}-{number}" for year, number in _CVE_REF.findall(rule)} & wanted):
                    rev, message, classtype = _REV.search(rule), _MSG.search(rule), _CLASSTYPE.search(rule)
                    found.append(OpenRule(
                        cve=cve, ruleset=ruleset.key, engine=ruleset.engine, sid=int(sid.group(1)),
                        rev=int(rev.group(1)) if rev else 0, message=message.group(1) if message else "",
                        classtype=classtype.group(1) if classtype else "", enabled_by_default=enabled,
                        license=ruleset.license_of(int(sid.group(1))), file=member.name.rsplit("/", 1)[-1],
                        rule=rule,
                    ))
    return found


async def _ruleset_bytes(ruleset: Ruleset, http: Http, settings: Settings, refresh: bool) -> bytes:
    path = settings.work_dir() / "rulesets" / f"{ruleset.key}.tar.gz"
    if not refresh and path.exists() and time.time() - path.stat().st_mtime < CACHE_SECONDS:
        return path.read_bytes()
    body = (await http.get(ruleset.url)).body
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(body)
    return body


async def find_rules(cves: Iterable[str], *, settings: Settings, rulesets: Iterable[str] = tuple(RULESETS),
                     refresh: bool = False, progress: Callable[[str], None] | None = None,
                     ) -> tuple[dict[str, list[OpenRule]], list[str]]:
    """CVE -> its open rules, best first (enabled, then newest SID), and notes on any ruleset that failed."""
    say = progress or (lambda _message: None)
    wanted = {cve.strip().upper() for cve in cves if cve.strip()}
    by_cve: dict[str, list[OpenRule]] = {cve: [] for cve in sorted(wanted)}
    notes: list[str] = []
    async with Http(max_bytes=RULESET_MAX_BYTES, timeout=120.0) as http:
        for key in rulesets:
            ruleset = RULESETS[key]
            try:
                body = await _ruleset_bytes(ruleset, http, settings, refresh)
                rules = parse_ruleset(body, ruleset, wanted)
            except (FetchError, tarfile.TarError, OSError) as error:
                notes.append(f"{ruleset.name}: not searched ({error})")
                say(f"{key}: failed ({error})")
                continue
            for rule in rules:
                by_cve[rule.cve].append(rule)
            say(f"{key}: {len(rules)} rules for {len({rule.cve for rule in rules})} of {len(wanted)} CVEs")
    for rules in by_cve.values():
        rules.sort(key=lambda rule: (not rule.enabled_by_default, -rule.sid))
    return by_cve, notes


def render_rules(by_cve: dict[str, list[OpenRule]], notes: list[str]) -> str:
    lines = []
    for cve, rules in by_cve.items():
        if not rules:
            lines.append(f"{cve}: no open rule")
            continue
        lines.append(f"{cve}: {len(rules)} rule(s)")
        for rule in rules:
            state = "enabled" if rule.enabled_by_default else "disabled by default"
            lines.append(f"  {rule.ruleset} sid:{rule.sid} rev:{rule.rev} ({state}, {rule.license}) {rule.message}")
            lines.append(f"    {rule.rule}")
    lines.extend(f"note: {note}" for note in notes)
    return "\n".join(lines)
