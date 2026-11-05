from __future__ import annotations

import asyncio
import io
import tarfile
from pathlib import Path

from porygon_mitigator.catalogs.open_rules import RULESETS, find_rules, parse_ruleset
from porygon_mitigator.config import Settings

RULES = "\n".join([
    'alert tcp any any -> any 53 (msg:"ET EXPLOIT SIGRed"; reference:cve,2020-1350; classtype:attempted-admin; '
    'sid:2030533; rev:2;)',
    '# alert tcp any any -> any 53 (msg:"ET EXPLOIT SIGRed old"; reference:cve,CVE-2020-1350; sid:2030500; rev:1;)',
    'alert tcp any any -> any 80 (msg:"GPL legacy"; reference:cve,2020-1350; sid:2001; rev:1;)',
    'alert tcp any any -> any 80 (msg:"unrelated"; reference:cve,2019-0001; sid:2030600; rev:1;)',
    "# a comment that mentions reference:cve,2020-1350 but is no rule",
])


def _tarball(rules: str) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        data = rules.encode()
        info = tarfile.TarInfo("rules/emerging-exploit.rules")
        info.size = len(data)
        archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def test_rules_keep_text_state_and_license() -> None:
    found = parse_ruleset(_tarball(RULES), RULESETS["et_open_suricata"], {"CVE-2020-1350"})
    by_sid = {rule.sid: rule for rule in found}
    assert set(by_sid) == {2030533, 2030500, 2001}
    assert by_sid[2030533].enabled_by_default and by_sid[2030533].message == "ET EXPLOIT SIGRed"
    assert by_sid[2030533].rule.startswith("alert tcp") and by_sid[2030533].classtype == "attempted-admin"
    assert not by_sid[2030500].enabled_by_default and not by_sid[2030500].rule.startswith("#")
    assert by_sid[2030533].license.startswith("BSD") and by_sid[2001].license == "GPL-2.0"


def test_find_uses_the_day_old_download_and_orders_enabled_first(tmp_path: Path) -> None:
    settings = Settings()
    cached = settings.work_dir() / "rulesets" / "et_open_suricata.tar.gz"
    cached.parent.mkdir(parents=True)
    cached.write_bytes(_tarball(RULES))
    by_cve, notes = asyncio.run(find_rules(["cve-2020-1350", "CVE-2021-44228"], settings=settings,
                                           rulesets=["et_open_suricata"]))
    assert notes == []
    assert [rule.sid for rule in by_cve["CVE-2020-1350"]] == [2030533, 2001, 2030500]
    assert by_cve["CVE-2021-44228"] == []
