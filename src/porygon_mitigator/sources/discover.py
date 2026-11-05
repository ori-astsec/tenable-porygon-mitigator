"""Find and fetch the advisories worth reading for one CVE.

Order of preference: structured APIs (no scraping), NVD/CNA references tagged as mitigations or vendor advisories,
Claude web search over the registry's advisory domains (plus one over IPS/WAF signature publishers when the CVE is
network-reachable), then per-CVE page templates. Every URL is checked against
the egress registry and against "this page is about another CVE"; pages that never mention the CVE are recorded as
unreadable rather than read.
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from urllib.parse import urlsplit, urlunsplit

from porygon_mitigator.config import Settings
from porygon_mitigator.extract.llm import Llm
from porygon_mitigator.extract.prompts import DISCOVERY_SYSTEM, DISCOVERY_USER, IPS_DISCOVERY_USER
from porygon_mitigator.match.cpe import product_slug
from porygon_mitigator.models.actions import vendor_key
from porygon_mitigator.models.cve import CveFacts, DistroFix
from porygon_mitigator.sources import structured
from porygon_mitigator.sources.documents import Origin, SourceAttempt, SourceDoc, attempt_for, error_status
from porygon_mitigator.sources.net import FetchError, Http
from porygon_mitigator.sources.registry import (
    ips_search_domains_for,
    is_allowed,
    lookup,
    publisher_for,
    search_domains_for,
    source_kind_for,
)
from porygon_mitigator.sources.text import about_other_cve, mentions_cve, prepare_source_text

Progress = Callable[[str], None]
MAX_PAGES_PER_HOST = 2

_TAG_PRIORITY = {
    "mitigation": 20,
    "vendor advisory": 25,
    "vendor-advisory": 25,
    "third party advisory": 45,
    "third-party-advisory": 45,
    "technical-description": 45,
    "us government resource": 35,
    "government-resource": 35,
}
_LINUXY_VENDORS = {"linux", "canonical", "redhat", "debian", "suse", "fedoraproject", "opensuse"}
_WEB_PRODUCTS = ("http", "web", "apache", "tomcat", "struts", "spring", "log4j", "confluence", "jira", "nginx",
                 "exchange", "sharepoint", "iis", "php", "wordpress", "drupal", "gitlab", "jenkins", "citrix",
                 "netscaler", "big-ip", "globalprotect", "fortios", "ivanti", "moveit", "goanywhere")


@dataclass(order=True)
class Candidate:
    priority: int
    url: str = field(compare=False)
    origin: Origin = field(compare=False, default="reference")


@dataclass
class Collected:
    docs: list[SourceDoc] = field(default_factory=list)
    attempts: list[SourceAttempt] = field(default_factory=list)
    distro_fixes: list[DistroFix] = field(default_factory=list)
    search_note: str | None = None


def canonical_url(url: str) -> str:
    """Dedupe key for URLs (case-folded path: advisory sites treat CVE IDs case-insensitively)."""
    parts = urlsplit(url.strip())
    path = (parts.path.rstrip("/") or "/").lower()
    return urlunsplit(("https", (parts.hostname or "").lower(), path, parts.query, ""))


def _vendors(facts: CveFacts) -> list[str]:
    return list(dict.fromkeys(vendor_key(item.vendor) for item in facts.affected if item.vendor))


def _is_web_app(facts: CveFacts) -> bool:
    blob = " ".join([facts.title or "", facts.description[:400], *[item.product for item in facts.affected[:10]]])
    blob = blob.lower()
    return any(word in blob for word in _WEB_PRODUCTS)


_PATCH_BULLETIN = re.compile(r"(?i)/errata/|rhsa-\d|/usn-|/dsa-\d|alas-\d|suse-su-|/notices/|/bulletin")
_CODE_OR_TRACKER = re.compile(
    r"(?i)bugzilla|/commit/|/commits/|/pull/|/issues?/|/changelog|/release-?notes|\.patch$|/patch(es)?/|gitlab\.com/.*/-/"
)
_NEVER_READ = re.compile(r"(?i)known-exploited-vulnerabilities-catalog|/vuln/detail/|/cverecord")


def worth_reading(url: str) -> bool:
    """Skip pages that can't hold a mitigation (catalog listings, NVD/CVE pages we already read as data) and code
    hosting outside GitHub's advisory database (proof-of-concept repositories)."""
    if _NEVER_READ.search(url):
        return False
    host = lookup(url)
    return not (host and host.domain == "github.com" and not urlsplit(url).path.startswith("/advisories"))


def adjust_priority(priority: int, url: str, cve_id: str) -> int:
    if _PATCH_BULLETIN.search(url):
        priority += 30  # patch announcements rarely carry workarounds
    if _CODE_OR_TRACKER.search(url):
        priority += 25
    if cve_id.lower() in url.lower():
        priority -= 5  # a page dedicated to this CVE
    return priority


def reference_candidates(facts: CveFacts) -> list[Candidate]:
    out: list[Candidate] = []
    vendor_domains = {vendor_key(v) for v in _vendors(facts)}
    for ref in facts.references:
        if not is_allowed(ref.url) or about_other_cve(ref.url, facts.cve_id) or not worth_reading(ref.url):
            continue
        tags = [tag.lower() for tag in ref.tags]
        priority = min((_TAG_PRIORITY.get(tag, 99) for tag in tags), default=99)
        host = lookup(ref.url)
        if priority == 99 and host and vendor_key(host.publisher) in vendor_domains:
            priority = 30
        if priority < 99:
            out.append(Candidate(adjust_priority(priority, ref.url, facts.cve_id), ref.url, "reference"))
    return sorted(out)[:16]


def template_candidates(facts: CveFacts, distro_seen: bool) -> list[Candidate]:
    cve = facts.cve_id
    vendors = set(_vendors(facts))
    out: list[Candidate] = []
    if "paloaltonetworks" in vendors:
        out.append(Candidate(22, f"https://security.paloaltonetworks.com/{cve}", "template"))
    if distro_seen or vendors & _LINUXY_VENDORS:
        out.append(Candidate(60, f"https://www.suse.com/security/cve/{cve}.html", "template"))
        out.append(Candidate(65, f"https://security-tracker.debian.org/tracker/{cve}", "template"))
    return out


async def search_candidates(facts: CveFacts, llm: Llm, max_uses: int = 3) -> tuple[list[Candidate], str]:
    vendors = _vendors(facts)
    linux = bool(set(vendors) & _LINUXY_VENDORS) or any("linux" in item.product for item in facts.affected)
    domains = search_domains_for(vendors, web_app=_is_web_app(facts), linux=linux)
    products = ", ".join(dict.fromkeys(f"{item.vendor} {item.product}" for item in facts.affected[:6])) or "unknown"
    first_product = product_slug(facts.affected[0].product).replace("_", " ") if facts.affected else ""
    prompt = DISCOVERY_USER.format(cve_id=facts.cve_id, title=facts.title or facts.description[:160],
                                   products=products, max_uses=max_uses, product=first_product)
    hits, note = await llm.search(system=DISCOVERY_SYSTEM, prompt=prompt, domains=domains, max_uses=max_uses)
    out = []
    for rank, hit in enumerate(hits):
        url = hit.url
        if is_allowed(url) and not about_other_cve(url, facts.cve_id) and worth_reading(url):
            out.append(Candidate(adjust_priority(30 + rank, url, facts.cve_id), url, "search"))
    return out, note


async def ips_search_candidates(facts: CveFacts, llm: Llm, device_vendors: list[str] | None = None,
                                max_uses: int = 2) -> tuple[list[Candidate], str]:
    """A search aimed at IPS/WAF signature publishers; the in-path devices' vendors are searched first."""
    vendors = device_vendors or []
    products = ", ".join(dict.fromkeys(f"{item.vendor} {item.product}" for item in facts.affected[:6])) or "unknown"
    devices = f"The traffic passes through: {', '.join(vendors)}. " if vendors else ""
    prompt = IPS_DISCOVERY_USER.format(cve_id=facts.cve_id, title=facts.title or facts.description[:160],
                                       products=products, max_uses=max_uses, devices=devices)
    hits, note = await llm.search(system=DISCOVERY_SYSTEM, prompt=prompt, domains=ips_search_domains_for(vendors),
                                  max_uses=max_uses)
    out = [
        Candidate(adjust_priority(35 + rank, hit.url, facts.cve_id), hit.url, "search")
        for rank, hit in enumerate(hits)
        if is_allowed(hit.url) and not about_other_cve(hit.url, facts.cve_id) and worth_reading(hit.url)
    ]
    return out, note


async def fetch_page(candidate: Candidate, cve_id: str, http: Http) -> tuple[SourceDoc | None, SourceAttempt]:
    url = candidate.url
    publisher, kind = publisher_for(url), source_kind_for(url)
    try:
        result = await http.get(url)
    except FetchError as error:
        status = error_status(error.status, error.reason)
        return None, SourceAttempt(url, publisher, candidate.origin, kind, status, error.reason)
    if not is_allowed(result.final_url):
        return None, SourceAttempt(url, publisher, candidate.origin, kind, "skipped", "redirected off the registry")
    text = prepare_source_text(result.text, result.content_type, cve_id)
    doc = SourceDoc(url=result.final_url, publisher=publisher, origin=candidate.origin, source_kind=kind, text=text,
                    fetched_url=result.final_url, priority=candidate.priority)
    if not mentions_cve(text, cve_id):
        return None, attempt_for(doc, "unreadable", "page text never mentions the CVE (JavaScript-only page?)")
    return doc, attempt_for(doc, "ok")


async def collect_sources(
    facts: CveFacts,
    http: Http,
    llm: Llm | None,
    settings: Settings,
    *,
    max_sources: int,
    search: bool = True,
    extra: list[Candidate] | None = None,
    progress: Progress | None = None,
) -> Collected:
    cve = facts.cve_id
    out = Collected()
    say = progress or (lambda _message: None)

    cna = structured.cna_document(facts)
    if cna:
        out.docs.append(cna)
        out.attempts.append(attempt_for(cna))
    tasks = [structured.redhat_document(cve, http), structured.ubuntu_document(cve, http)]
    for doc, attempt, fixes in await asyncio.gather(*tasks):
        out.attempts.append(attempt)
        out.distro_fixes.extend(fixes)
        if doc:
            out.docs.append(doc)
    if "microsoft" in _vendors(facts):
        doc, attempt = await structured.msrc_document(cve, http, settings.work_dir())
        out.attempts.append(attempt)
        if doc:
            out.docs.append(doc)
    osv_docs, osv_attempts = await structured.osv_documents(cve, http)
    out.docs.extend(osv_docs)
    out.attempts.extend(osv_attempts)
    say(f"structured sources: {len(out.docs)} with mitigation text")

    candidates = reference_candidates(facts)
    if search and llm is not None:
        found, note = await search_candidates(facts, llm)
        out.search_note = note
        candidates += found
        say(f"web search: {len(found)} candidate pages ({note})")
        if facts.network_reachable():
            ips_found, ips_note = await ips_search_candidates(facts, llm)
            candidates += ips_found
            say(f"IPS signature search: {len(ips_found)} candidate pages ({ips_note})")
    candidates += template_candidates(facts, distro_seen=bool(out.distro_fixes))
    candidates += extra or []
    seen = {canonical_url(doc.url) for doc in out.docs}
    queue: list[Candidate] = []
    per_host: dict[str, int] = {}
    deferred: list[Candidate] = []
    for candidate in sorted(candidates):
        key = canonical_url(candidate.url)
        if key in seen:
            continue
        seen.add(key)
        host = urlsplit(key).hostname or ""
        if per_host.get(host, 0) >= MAX_PAGES_PER_HOST:
            deferred.append(candidate)  # diversity first; read more from one host only if budget remains
            continue
        per_host[host] = per_host.get(host, 0) + 1
        queue.append(candidate)
    queue.extend(deferred)

    pages, attempts = await read_pages(queue, cve, http, max_sources, out.docs)
    out.attempts.extend(attempts)
    out.docs.extend(sorted(pages, key=lambda doc: doc.priority))
    say(f"pages read: {len(pages)} of {len(queue)} candidates")
    return out


async def read_pages(queue: list[Candidate], cve: str, http: Http, max_sources: int,
                     collected: list[SourceDoc]) -> tuple[list[SourceDoc], list[SourceAttempt]]:
    """Fetch candidates in order until `max_sources` pages are read. Two references often redirect to one page: a
    page already read (same final URL or same text) is skipped, not extracted twice."""
    read = {canonical_url(doc.url) for doc in collected} | {doc.sha256 for doc in collected}
    pages: list[SourceDoc] = []
    attempts: list[SourceAttempt] = []
    index = 0
    while len(pages) < max_sources and index < len(queue):
        batch = queue[index: index + max(2, max_sources - len(pages))]
        index += len(batch)
        for candidate, (doc, attempt) in zip(batch, await asyncio.gather(*(fetch_page(c, cve, http) for c in batch)),
                                             strict=True):
            if doc is not None and {canonical_url(doc.url), doc.sha256} & read:
                attempt = replace(attempt, url=candidate.url, status="skipped", note=f"same page as {doc.url}")
                doc = None
            attempts.append(attempt)
            if doc is not None and len(pages) < max_sources:
                read |= {canonical_url(doc.url), doc.sha256}
                pages.append(doc)
    for candidate in queue[index:]:
        attempts.append(SourceAttempt(candidate.url, publisher_for(candidate.url), candidate.origin,
                                      source_kind_for(candidate.url), "skipped", "source budget reached"))
    return pages, attempts
