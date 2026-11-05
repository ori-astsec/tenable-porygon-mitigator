import asyncio
import json
from datetime import date
from typing import Any

import pytest

from porygon_mitigator.catalogs import checkpoint
from porygon_mitigator.catalogs.lookup import catalogue_mitigations, load_indexes, reload_indexes
from porygon_mitigator.config import Settings
from porygon_mitigator.extract.llm import Llm, SearchHit
from porygon_mitigator.funnel import build_funnel, priority_cves, render_funnel
from porygon_mitigator.models import CveFacts

NETWORK = {"access_vector": "Network", "raw": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
LOCAL = {"access_vector": "Local", "raw": "AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"}


def _row(asset: str, plugin_id: int, cves: list[str], score: float, vector: dict[str, str] | None,
         state: str = "OPEN", severity: str = "high", kev: bool = False, vpr: float = 0.0) -> dict[str, Any]:
    plugin: dict[str, Any] = {"id": plugin_id, "name": f"plugin {plugin_id}", "cve": cves, "cvss3_base_score": score,
                              "vpr": {"score": vpr, "on_cisa_kev": kev}}
    if vector:
        plugin["cvss3_vector"] = vector
    return {"asset": {"uuid": asset}, "plugin": plugin, "state": state, "severity": severity}


ROWS = [
    _row("a1", 1, ["CVE-2099-0001"], 9.8, NETWORK, kev=True),              # remote critical, Snort SID
    _row("a2", 1, ["CVE-2099-0001"], 9.8, NETWORK, kev=True),              # same plugin, second asset
    _row("a1", 2, ["CVE-2099-0002"], 7.8, LOCAL),                          # high but local
    _row("a2", 3, ["CVE-2099-0003"], 5.3, NETWORK, severity="medium"),     # remote but medium
    _row("a3", 4, ["CVE-2099-0004"], 8.1, NETWORK, vpr=6.7),               # remote high, Check Point only
    _row("a3", 5, ["CVE-2099-0005"], 7.5, NETWORK, vpr=9.0),               # remote high, no signature
    _row("a1", 1, ["CVE-2099-0001"], 9.8, NETWORK, state="FIXED"),         # fixed: not in the funnel
    _row("a3", 6, [], 0.0, None, severity="info"),                        # info: CVSS 0 means no score
]
INDEXES = {"snort3": {"CVE-2099-0001": {"rules": ["58750"]}}, "et_open": {},
           "checkpoint": {"CVE-2099-0004": {"rules": ["CPAI-2099-0400"]}}}


def test_funnel_stages_use_the_plugin_cvss_and_skip_fixed_findings() -> None:
    funnel = build_funnel(ROWS, INDEXES, checkpoint_searched={"CVE-2099-0004", "CVE-2099-0005"})
    assert [(s.findings, s.assets, s.cves) for s in funnel.stages] == [(7, 3, 5), (5, 3, 4), (4, 3, 3), (3, 3, 2)]
    vendors = {v.source: (v.findings, v.cves) for v in funnel.vendors}
    assert vendors["snort3"] == (2, 1) and vendors["checkpoint"] == (1, 1) and vendors["et_open"] == (0, 0)
    assert "searched 2 of 3 remote CVEs" in next(v.note for v in funnel.vendors if v.source == "checkpoint")
    assert [(item["plugin_id"], item["assets"]) for item in funnel.top] == [(1, 2), (4, 1)]
    assert any("Threat Vault" in note for note in funnel.notes)
    assert "| Stoppable by an IPS signature (any vendor) | 3 | 3 | 2 | 75% |" in render_funnel(funnel)


def test_severity_falls_back_to_tenable_when_the_plugin_has_no_cvss() -> None:
    rows = [_row("a1", 7, ["CVE-2099-0007"], 0.0, NETWORK, severity="critical")]
    assert [s.findings for s in build_funnel(rows, {}).stages][:3] == [1, 1, 1]


def test_most_urgent_cves_come_first() -> None:
    assert priority_cves(ROWS) == ["CVE-2099-0001", "CVE-2099-0005", "CVE-2099-0004"]  # KEV, then VPR


def test_checkpoint_counts_only_advisories_that_name_the_cve() -> None:
    hits = [
        SearchHit(url="https://advisories.checkpoint.com/defense/advisories/public/2019/cpai-2019-0408.html",
                  title="Microsoft RDP Remote Code Execution (CVE-2019-0708)"),
        SearchHit(url="https://advisories.checkpoint.com/defense/advisories/public/2019/cpai-2019-0999.html",
                  title="Microsoft RDP Remote Code Execution (CVE-2019-1181)"),
        SearchHit(url="https://advisories.checkpoint.com/advisories/", title="Advisories mentioning CVE-2019-0708"),
    ]
    rules, link = checkpoint.protections("CVE-2019-0708", hits)
    assert rules == ["CPAI-2019-0408"] and link is not None and link.endswith("cpai-2019-0408.html")


def test_checkpoint_search_is_capped_caches_misses_and_feeds_machine_assessments(
        monkeypatch: pytest.MonkeyPatch) -> None:
    asked: list[str] = []

    async def fake_search(self: Any, *, system: str, prompt: str, domains: list[str], max_uses: int) -> Any:
        assert domains == ["advisories.checkpoint.com"] and max_uses == 1
        cve = prompt.split('"')[1]
        asked.append(cve)
        if cve == "CVE-2099-0004":
            return [SearchHit(url="https://advisories.checkpoint.com/defense/advisories/public/2099/cpai-2099-0400.html",
                              title="Acme Widget RCE (CVE-2099-0004)")], "ok"
        return [], "ok"

    monkeypatch.setattr(Llm, "search", fake_search)
    settings = Settings()
    cves = ["CVE-2099-0004", "CVE-2099-0005", "CVE-2099-0006"]
    assert asyncio.run(checkpoint.search(cves, settings=settings, cap=2)) == 2
    assert sorted(asked) == ["CVE-2099-0004", "CVE-2099-0005"]
    stored = json.loads(checkpoint.index_path(settings).read_text(encoding="utf-8"))
    assert {cve: entry["rules"] for cve, entry in stored["cves"].items()} == {"CVE-2099-0004": ["CPAI-2099-0400"]}
    assert set(stored["searched"]) == {"CVE-2099-0004", "CVE-2099-0005"}
    assert asyncio.run(checkpoint.search(cves, settings=settings, cap=5)) == 1  # only the unsearched one
    reload_indexes()
    assert "CVE-2099-0004" in load_indexes(settings)["checkpoint"]
    records = catalogue_mitigations(CveFacts(cve_id="CVE-2099-0004"), date(2099, 1, 1), settings)
    assert [(r.action.kind, r.action.target) for r in records] == [("apply_ips_signature", "checkpoint:cpai-2099-0400")]
    reload_indexes()
