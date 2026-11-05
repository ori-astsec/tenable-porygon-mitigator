"""Structured advisory sources: machine-readable APIs that state mitigations without any scraping.

- the CVE record's own `workarounds` / `solutions` (written by the CNA, usually the vendor)
- Red Hat Security Data API (`mitigation`, `statement`, package states)
- Ubuntu CVE JSON (`mitigation`, notes, package states)
- Microsoft CVRF (remediations of type Workaround / Mitigation, FAQ notes)
- OSV / GitHub Security Advisories (advisory text, often with a Workarounds section)
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from porygon_mitigator.models.cve import CveFacts, DistroFix
from porygon_mitigator.sources.documents import SourceAttempt, SourceDoc, error_status
from porygon_mitigator.sources.net import FetchError, Http
from porygon_mitigator.sources.text import html_to_text
from porygon_mitigator.text import normalize_text

_MITIGATION_WORDS = re.compile(r"(?i)\b(workaround|mitigat|disable|block|restrict|config|registry|signature|rule)")


def _lines(*parts: str) -> str:
    out: list[str] = []
    for part in parts:
        for line in part.splitlines():
            line = normalize_text(line)
            if line:
                out.append(line)
    return "\n".join(out)


def _strip_html(value: str) -> str:
    """CVRF fields are HTML fragments: block tags become line breaks, inline tags (<strong>, <a>) stay in the line."""
    return html_to_text(value)




def cna_document(facts: CveFacts) -> SourceDoc | None:
    if not facts.cna_workarounds and not facts.cna_solutions:
        return None
    parts = []
    if facts.cna_workarounds:
        parts.append("Workarounds and mitigations published in the CVE record:")
        parts.extend(facts.cna_workarounds)
    if facts.cna_solutions:
        parts.append("Solutions published in the CVE record:")
        parts.extend(facts.cna_solutions)
    return SourceDoc(
        url=f"https://www.cve.org/CVERecord?id={facts.cve_id}",
        fetched_url=f"https://cveawg.mitre.org/api/cve/{facts.cve_id}",
        publisher="cve.org",
        origin="structured_api",
        source_kind="vendor",
        text=_lines(*parts),
        priority=5,
    )



_RHEL_RE = re.compile(r"red hat enterprise linux (\d+)", re.IGNORECASE)


def _rpm_name(nvr: str) -> tuple[str, str]:
    """'openssh-0:8.7p1-38.el9_4.1' -> ('openssh', '0:8.7p1-38.el9_4.1')."""
    match = re.match(r"^(.+?)-(\d+:)?(\d[^-]*-[^-]+)$", nvr)
    if not match:
        return nvr, ""
    return match.group(1), (match.group(2) or "") + match.group(3)


def redhat_distro_fixes(data: dict[str, Any]) -> list[DistroFix]:
    fixes: list[DistroFix] = []
    for release in data.get("affected_release") or []:
        product = str(release.get("product_name") or "")
        major = _RHEL_RE.search(product)
        package = str(release.get("package") or "")
        if not major or not package:
            continue
        name, version = _rpm_name(package)
        fixes.append(DistroFix(distro="rhel", release=major.group(1), package=name, status="fixed",
                               fixed_version=version or None))
    state_map = {"not affected": "not_affected", "affected": "affected", "will not fix": "wont_fix",
                 "fix deferred": "deferred", "out of support scope": "wont_fix"}
    for state in data.get("package_state") or []:
        product = str(state.get("product_name") or "")
        major = _RHEL_RE.search(product)
        if not major:
            continue
        status = state_map.get(str(state.get("fix_state") or "").lower(), "unknown")
        fixes.append(DistroFix(distro="rhel", release=major.group(1), package=str(state.get("package_name") or ""),
                               status=status))
    return fixes


async def redhat_document(cve_id: str, http: Http) -> tuple[SourceDoc | None, SourceAttempt, list[DistroFix]]:
    api = f"https://access.redhat.com/hydra/rest/securitydata/cve/{cve_id}.json"
    page = f"https://access.redhat.com/security/cve/{cve_id.lower()}"
    try:
        data = await http.get_json(api)
    except FetchError as error:
        status = error_status(error.status, error.reason)
        return None, SourceAttempt(page, "redhat", "structured_api", "distro", status, error.reason), []
    if not isinstance(data, dict):
        return None, SourceAttempt(page, "redhat", "structured_api", "distro", "unreadable"), []
    mitigation = data.get("mitigation")
    mitigation_text = str(mitigation.get("value") if isinstance(mitigation, dict) else mitigation or "")
    statement = str(data.get("statement") or "")
    details = " ".join(str(item) for item in data.get("details") or [])
    fixes = redhat_distro_fixes(data)
    parts = []
    if mitigation_text:
        parts += ["Red Hat mitigation:", mitigation_text]
    if statement:
        parts += ["Red Hat statement:", statement]
    if details:
        parts += ["Details:", details]
    if not mitigation_text and not _MITIGATION_WORDS.search(statement):
        attempt = SourceAttempt(page, "redhat", "structured_api", "distro", "no_mitigation",
                                "no mitigation in Red Hat's data")
        return None, attempt, fixes
    doc = SourceDoc(url=page, fetched_url=api, publisher="redhat", origin="structured_api", source_kind="distro",
                    text=_lines(*parts), priority=10)
    return doc, SourceAttempt(page, "redhat", "structured_api", "distro", "ok"), fixes



UBUNTU_CODENAMES = {
    "trusty": "14.04", "xenial": "16.04", "bionic": "18.04", "focal": "20.04", "jammy": "22.04",
    "kinetic": "22.10", "lunar": "23.04", "mantic": "23.10", "noble": "24.04", "oracular": "24.10",
    "plucky": "25.04", "questing": "25.10", "resolute": "26.04",
}  # fmt: skip
_UBUNTU_STATUS = {"released": "fixed", "not-affected": "not_affected", "needed": "affected", "deferred": "deferred",
                  "ignored": "wont_fix", "needs-triage": "unknown", "pending": "affected", "DNE": "not_affected"}


def ubuntu_distro_fixes(data: dict[str, Any]) -> list[DistroFix]:
    fixes: list[DistroFix] = []
    for package in data.get("packages") or []:
        name = str(package.get("name") or "")
        for status in package.get("statuses") or []:
            codename = str(status.get("release_codename") or "")
            release = UBUNTU_CODENAMES.get(codename, codename)
            mapped = _UBUNTU_STATUS.get(str(status.get("status") or ""), "unknown")
            fixed = str(status.get("description") or "") if mapped == "fixed" else None
            fixes.append(DistroFix(distro="ubuntu", release=release, package=name, status=mapped,
                                   fixed_version=fixed or None))
    return fixes


async def ubuntu_document(cve_id: str, http: Http) -> tuple[SourceDoc | None, SourceAttempt, list[DistroFix]]:
    api = f"https://ubuntu.com/security/cves/{cve_id}.json"
    page = f"https://ubuntu.com/security/{cve_id}"
    try:
        data = await http.get_json(api)
    except FetchError as error:
        status = error_status(error.status, error.reason)
        return None, SourceAttempt(page, "ubuntu", "structured_api", "distro", status, error.reason), []
    if not isinstance(data, dict):
        return None, SourceAttempt(page, "ubuntu", "structured_api", "distro", "unreadable"), []
    fixes = ubuntu_distro_fixes(data)
    mitigation = str(data.get("mitigation") or "").strip()
    notes = [str(note.get("note") or "") for note in data.get("notes") or []]
    relevant_notes = [note for note in notes if _MITIGATION_WORDS.search(note)]
    if not mitigation and not relevant_notes:
        attempt = SourceAttempt(page, "ubuntu", "structured_api", "distro", "no_mitigation",
                                "no mitigation in Ubuntu's data")
        return None, attempt, fixes
    parts = []
    if mitigation:
        parts += ["Ubuntu mitigation:", mitigation]
    if relevant_notes:
        parts += ["Ubuntu notes:", *relevant_notes]
    doc = SourceDoc(url=page, fetched_url=api, publisher="ubuntu", origin="structured_api", source_kind="distro",
                    text=_lines(*parts), priority=10)
    return doc, SourceAttempt(page, "ubuntu", "structured_api", "distro", "ok"), fixes



_CVRF_TYPES = {0: "Workaround", 1: "Mitigation", 3: "None Available"}


async def msrc_document(cve_id: str, http: Http, work_dir: Path) -> tuple[SourceDoc | None, SourceAttempt]:
    page = f"https://msrc.microsoft.com/update-guide/vulnerability/{cve_id}"
    try:
        updates = await http.get_json(f"https://api.msrc.microsoft.com/cvrf/v3.0/updates/{cve_id}")
        doc_ids = [str(item.get("ID")) for item in (updates or {}).get("value", []) if item.get("ID")]
        if not doc_ids:
            return None, SourceAttempt(page, "msrc", "structured_api", "vendor", "not_listed")
        cache = work_dir / "msrc" / f"{doc_ids[0]}.json"
        if cache.exists():
            cvrf = json.loads(cache.read_text(encoding="utf-8"))
        else:
            cvrf = await http.get_json(f"https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/{doc_ids[0]}")
            cache.parent.mkdir(parents=True, exist_ok=True)
            cache.write_text(json.dumps(cvrf), encoding="utf-8")
    except FetchError as error:
        status = error_status(error.status, error.reason)
        return None, SourceAttempt(page, "msrc", "structured_api", "vendor", status, error.reason)
    vulnerability = next((v for v in cvrf.get("Vulnerability", []) if v.get("CVE") == cve_id), None)
    if vulnerability is None:
        return None, SourceAttempt(page, "msrc", "structured_api", "vendor", "not_listed")
    parts: list[str] = []
    seen: set[str] = set()
    for remediation in vulnerability.get("Remediations") or []:
        label = _CVRF_TYPES.get(remediation.get("Type"))
        text = (remediation.get("Description") or {}).get("Value") or ""
        if label and text and text not in seen:
            seen.add(text)
            parts += [f"{label}:", _strip_html(text)]
    for note in vulnerability.get("Notes") or []:
        title = str(note.get("Title") or "")
        value = _strip_html(str(note.get("Value") or ""))
        if title in ("FAQ", "Description", "Mitigations", "Workarounds") and value:
            parts += [f"{title}:", value]
    text = _lines(*parts)
    if not parts or not _MITIGATION_WORDS.search(text):
        return None, SourceAttempt(page, "msrc", "structured_api", "vendor", "no_mitigation",
                                   "CVRF lists no workaround or mitigation")
    doc = SourceDoc(url=page, fetched_url=f"https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/{doc_ids[0]}",
                    publisher="msrc", origin="structured_api", source_kind="vendor", text=text, priority=8)
    return doc, SourceAttempt(page, "msrc", "structured_api", "vendor", "ok")




async def osv_documents(cve_id: str, http: Http) -> tuple[list[SourceDoc], list[SourceAttempt]]:
    docs: list[SourceDoc] = []
    attempts: list[SourceAttempt] = []
    try:
        record = await http.get_json(f"https://api.osv.dev/v1/vulns/{cve_id}")
    except FetchError as error:
        status = error_status(error.status, error.reason)
        attempts.append(SourceAttempt(f"https://osv.dev/vulnerability/{cve_id}", "osv", "structured_api",
                                      "third_party", status, error.reason))
        return docs, attempts
    ghsa_ids = [alias for alias in (record or {}).get("aliases", []) if str(alias).startswith("GHSA-")][:2]
    for ghsa in ghsa_ids:
        page = f"https://github.com/advisories/{ghsa}"
        try:
            advisory = await http.get_json(f"https://api.osv.dev/v1/vulns/{ghsa}")
        except FetchError as error:
            attempts.append(SourceAttempt(page, "github-advisories", "structured_api", "third_party", "unreachable",
                                          error.reason))
            continue
        details = str((advisory or {}).get("details") or "")
        if not re.search(r"(?i)workaround|mitigat", details):
            attempts.append(SourceAttempt(page, "github-advisories", "structured_api", "third_party",
                                          "no_mitigation"))
            continue
        docs.append(SourceDoc(url=page, fetched_url=f"https://api.osv.dev/v1/vulns/{ghsa}",
                              publisher="github-advisories", origin="structured_api", source_kind="third_party",
                              text=_lines(f"{ghsa} ({cve_id})", details), priority=15))
        attempts.append(SourceAttempt(page, "github-advisories", "structured_api", "third_party", "ok"))
    return docs, attempts
