import io
import json
import tarfile
from datetime import date

from porygon_mitigator.catalogs import parsers
from porygon_mitigator.catalogs.lookup import catalogue_record
from porygon_mitigator.catalogs.templates import TEMPLATES
from porygon_mitigator.match.applicability import assess_mitigation
from porygon_mitigator.models import AffectednessResult, CveFacts

from .conftest import load_machine


def _tarball(rules: str) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        data = rules.encode()
        info = tarfile.TarInfo("rules/test.rules")
        info.size = len(data)
        archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def test_rules_archive_and_bsd_range() -> None:
    rules = "\n".join([
        'alert tcp any any -> any any (msg:"x"; reference:cve,2021-44228; sid:2034647; rev:1;)',
        '# alert tcp any any -> any any (msg:"off"; reference:cve,2021-44228; sid:2034648; rev:1;)',
        'alert tcp any any -> any any (msg:"gpl"; reference:cve,2021-44228; sid:2101000; rev:1;)',
        'alert tcp any any -> any any (msg:"y"; reference:cve,CVE-2024-3400; sid:2052122; rev:1;)',
    ])
    mapping = parsers.rules_archive(_tarball(rules), sid_range=(2_000_000, 2_099_999))
    assert mapping == {"CVE-2021-44228": ["2034647"], "CVE-2024-3400": ["2052122"]}


def test_f5_and_azure_and_cloudflare_parsers() -> None:
    payload = {"props": {"pageProps": {"docData": {"scope": {"JsonData": [
        {"id": 200104768, "references": [{"type": "cve", "value": "CVE-2021-44228"}]},
        {"id": "x", "references": "CVE-2021-44228"}]}}}}}
    page = f'<script id="__NEXT_DATA__" type="application/json">{json.dumps(payload)}</script>'
    assert parsers.f5_signatures(page) == {"CVE-2021-44228": ["200104768"]}
    azure = "<table><tr><td>944240</td><td>5</td><td>Log4j (CVE-2021-44228, CVE-2021-45046)</td></tr></table>"
    assert parsers.azure_waf(azure)["CVE-2021-45046"] == ["944240"]
    feed = ("<rss><item><link>https://developers.cloudflare.com/changelog/post/x/</link><description>"
            "&lt;table&gt;&lt;tr&gt;&lt;td&gt;Cloudflare Managed Ruleset&lt;/td&gt;&lt;td&gt;...abc&lt;/td&gt;"
            "&lt;td&gt;100514&lt;/td&gt;&lt;td&gt;Log4j (CVE-2021-44228)&lt;/td&gt;&lt;/tr&gt;&lt;/table&gt;"
            "</description></item></rss>")
    mapping, links = parsers.cloudflare_changelog(feed, [])
    assert mapping == {"CVE-2021-44228": ["100514"]} and links["CVE-2021-44228"].endswith("/post/x/")
    history = ("<table><tr><td>Cloudflare Specials</td><td>...def</td><td>100604, 100605</td>"
               "<td>Atlassian Confluence (CVE-2023-22515)</td></tr></table>")
    assert parsers.cloudflare_changelog("", [history])[0] == {"CVE-2023-22515": ["100604", "100605"]}


def test_catalogue_record_matches_device_in_path() -> None:
    template = next(t for t in TEMPLATES if t.key == "cloudflare")
    record = catalogue_record(template, CveFacts(cve_id="CVE-2021-44228"), ["100514", "100515"], {}, date(2026, 11, 2))
    assert record.title == "Enforce managed rules on Cloudflare WAF"
    assert record.action.kind == "apply_waf_rule" and record.action.target == "cloudflare:100514"
    assert record.evidence[0].source_kind == "catalog" and record.evidence[0].verified
    affected = AffectednessResult(status="affected")
    assert assess_mitigation(record, load_machine("java-app-server.json"), affected).status == "applicable"
    assert assess_mitigation(record, load_machine("win10-office-workstation.json"), affected).status == "needs_device"
