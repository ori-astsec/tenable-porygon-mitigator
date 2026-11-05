import asyncio
from pathlib import Path
from typing import Any

from porygon_mitigator.intel.cverecord import parse_cve_record
from porygon_mitigator.intel.facts import merge_facts
from porygon_mitigator.intel.nvd import parse_nvd
from porygon_mitigator.sources.registry import is_allowed, lookup, search_domains_for, source_kind_for
from porygon_mitigator.sources.structured import msrc_document
from porygon_mitigator.sources.text import about_other_cve, html_to_text, window_text
from porygon_mitigator.text import contains_normalized

CVE5 = {
    "cveMetadata": {"cveId": "CVE-2099-1234", "datePublished": "2099-01-02T00:00:00Z", "state": "PUBLISHED"},
    "containers": {
        "cna": {
            "title": "Widget RCE",
            "descriptions": [{"lang": "en", "value": "A bug in Widget."}],
            "affected": [{"vendor": "Acme", "product": "Widget", "versions": [
                {"version": "1.0", "lessThan": "1.4.2", "status": "affected"},
                {"version": "2.0", "status": "affected"}]}],
            "workarounds": [{"lang": "en", "value": "Set safe_mode=1 in widget.conf."}],
            "solutions": [{"lang": "en", "value": "Upgrade to 1.4.2."}],
            "metrics": [{"cvssV3_1": {"baseScore": 9.8, "baseSeverity": "CRITICAL", "version": "3.1"}}],
            "problemTypes": [{"descriptions": [{"cweId": "CWE-78"}]}],
            "references": [{"url": "https://acme.example/advisory", "tags": ["vendor-advisory"]}],
        },
        "adp": [{"metrics": [{"other": {"type": "kev", "content": {"dateAdded": "2099-01-05"}}}]}],
    },
}


def test_parse_cve_record() -> None:
    parsed = parse_cve_record(CVE5)
    assert parsed["title"] == "Widget RCE" and parsed["cna_workarounds"] == ["Set safe_mode=1 in widget.conf."]
    ranges = parsed["affected"]
    assert ranges[0].version_start_including == "1.0" and ranges[0].version_end_excluding == "1.4.2"
    assert ranges[1].exact_versions == ["2.0"]
    assert parsed["kev"].date_added.isoformat() == "2099-01-05"
    assert parsed["cvss"].base_score == 9.8 and parsed["cwes"] == ["CWE-78"]


def test_parse_nvd_and_merge() -> None:
    nvd = parse_nvd({
        "published": "2099-01-02T10:00:00",
        "configurations": [{"nodes": [{"cpeMatch": [
            {"vulnerable": True, "criteria": "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*",
             "versionEndExcluding": "1.4.2"},
            {"vulnerable": False, "criteria": "cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*"}]}]}],
        "references": [{"url": "https://acme.example/advisory", "tags": ["Mitigation"]}],
    })
    assert len(nvd["affected"]) == 1 and nvd["affected"][0].product == "widget"
    facts = merge_facts("CVE-2099-1234", parse_cve_record(CVE5), nvd, None)
    assert facts.references[0].tags == ["vendor-advisory", "Mitigation"]
    assert facts.product_keys()[0] == "acme:widget"


def test_registry_allowlist() -> None:
    assert is_allowed("https://access.redhat.com/security/cve/cve-2024-6387")
    assert is_allowed("https://www.cisa.gov/x")
    assert not is_allowed("http://access.redhat.com/x")  # https only
    assert not is_allowed("https://access.redhat.com.evil.example/x")
    assert not is_allowed("https://evil.example/?u=access.redhat.com")
    assert not is_allowed("https://access.redhat.com:8443/x")
    assert lookup("https://foo.ubuntu.com/x") is not None  # subdomain on a dot boundary
    assert source_kind_for("https://github.com/someone/poc") == "user_content"
    assert source_kind_for("https://github.com/advisories/GHSA-x") == "third_party"


def test_search_domains_capped_and_vendor_first() -> None:
    domains = search_domains_for(["Microsoft"], web_app=True, linux=True)
    assert len(domains) <= 15 and domains[0] == "msrc.microsoft.com"
    assert "www.microsoft.com/en-us/msrc" in domains


def test_html_to_text_and_window() -> None:
    html = ("<html><body><nav>menu</nav><main><h2>Workarounds</h2><p>Run <code>reg delete X /f</code>.</p>"
            "<script>evil()</script></main></body></html>")
    text = html_to_text(html)
    assert "menu" not in text and "evil" not in text and "reg delete X /f" in text
    long_text = "\n".join(["filler line"] * 5000 + ["CVE-2099-1234 workaround: set safe_mode=1"] + ["x"] * 10)
    window = window_text(long_text, "CVE-2099-1234", max_chars=500)
    assert "safe_mode=1" in window and len(window) <= 500


def test_quote_matching_normalises_punctuation() -> None:
    page = "Execute the command “reg delete HKEY_CLASSES_ROOT\\ms-msdt /f”. Done"
    assert contains_normalized(page, 'Execute the command "reg delete HKEY_CLASSES_ROOT\\ms-msdt /f".')
    assert not contains_normalized(page, "reg delete HKEY_LOCAL_MACHINE")
    assert not contains_normalized(page, "   ")


def test_about_other_cve() -> None:
    assert about_other_cve("https://x.example/CVE-2020-0001", "CVE-2022-30190")
    assert not about_other_cve("https://x.example/cve-2022-30190.html", "CVE-2022-30190")
    assert not about_other_cve("https://x.example/advisory", "CVE-2022-30190")


class _CannedJson:
    """Stands in for Http: returns canned JSON per URL."""

    def __init__(self, responses: dict[str, Any]) -> None:
        self.responses = responses

    async def get_json(self, url: str, **_kwargs: Any) -> Any:
        return self.responses[url]


def test_cvrf_inline_markup_stays_on_one_line(tmp_path: Path) -> None:
    remediation = ("<p>The following <strong>workaround</strong> may be helpful:</p>"
                   "<pre>reg add HKLM\\SYSTEM\\X /v Y /t REG_DWORD /d 0 /f</pre>")
    cvrf = {"Vulnerability": [{"CVE": "CVE-2099-0002", "Notes": [], "Remediations": [
        {"Type": 0, "Description": {"Value": remediation}}, {"Type": 2, "Description": {"Value": "5014692"}}]}]}
    http = _CannedJson({
        "https://api.msrc.microsoft.com/cvrf/v3.0/updates/CVE-2099-0002": {"value": [{"ID": "2099-Jan"}]},
        "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2099-Jan": cvrf,
    })
    doc, attempt = asyncio.run(msrc_document("CVE-2099-0002", http, tmp_path))  # type: ignore[arg-type]
    assert attempt.status == "ok" and doc is not None
    assert doc.text.splitlines() == ["Workaround:", "The following workaround may be helpful:",
                                     "reg add HKLM\\SYSTEM\\X /v Y /t REG_DWORD /d 0 /f"]


def test_ips_search_asks_in_path_vendors_first_and_keeps_only_this_cves_pages() -> None:
    from porygon_mitigator.extract.llm import SearchHit
    from porygon_mitigator.models import CveFacts
    from porygon_mitigator.sources.discover import ips_search_candidates

    asked: dict[str, Any] = {}

    class FakeLlm:
        async def search(self, *, system: str, prompt: str, domains: list[str], max_uses: int) -> Any:
            asked.update(prompt=prompt, domains=domains)
            return [SearchHit(url="https://www.fortiguard.com/encyclopedia/ips/49207"),
                    SearchHit(url="https://unregistered.example/CVE-2020-0796"),
                    SearchHit(url="https://blog.talosintelligence.com/cve-2019-0708-coverage")], "ok"

    facts = CveFacts(cve_id="CVE-2020-0796", description="SMBv3 compression RCE")
    found, _note = asyncio.run(ips_search_candidates(facts, FakeLlm(), ["fortinet"]))  # type: ignore[arg-type]
    assert asked["domains"][0] == "www.fortiguard.com"
    assert "blog.talosintelligence.com" in asked["domains"]
    assert "fortinet" in asked["prompt"]
    assert [candidate.url for candidate in found] == ["https://www.fortiguard.com/encyclopedia/ips/49207"]


def test_a_page_two_references_redirect_to_is_read_once(monkeypatch: Any) -> None:
    from porygon_mitigator.sources import discover
    from porygon_mitigator.sources.documents import SourceDoc, attempt_for

    advisory = "https://vendor.example/advisory/CVE-2099-0001"

    async def fake_fetch(candidate: Any, cve: str, _http: Any) -> Any:
        final = advisory if "kb" in candidate.url or "viewpage" in candidate.url else candidate.url
        doc = SourceDoc(url=final, publisher="vendor", origin="reference", source_kind="vendor",
                        text=f"{cve}: text of {final}")
        return doc, attempt_for(doc)

    monkeypatch.setattr(discover, "fetch_page", fake_fetch)
    queue = [discover.Candidate(10, "https://vendor.example/kb/faq", "reference"),
             discover.Candidate(10, "https://vendor.example/pages/viewpage?id=1", "reference"),
             discover.Candidate(20, "https://other.example/bulletin", "reference")]
    pages, attempts = asyncio.run(discover.read_pages(queue, "CVE-2099-0001", None, 5, []))  # type: ignore[arg-type]
    assert [page.url for page in pages] == [advisory, "https://other.example/bulletin"]
    assert [attempt.status for attempt in attempts] == ["ok", "skipped", "ok"]
    assert attempts[1].url == "https://vendor.example/pages/viewpage?id=1" and advisory in (attempts[1].note or "")
