"""Turn fetched pages into the plain text the extractor reads and the verifier searches.

The extractor and the verifier must see the *same* text, so both use `prepare_source_text()` output.
"""

from __future__ import annotations

import re
import warnings

from bs4 import BeautifulSoup, MarkupResemblesLocatorWarning

from porygon_mitigator.text import normalize_text

_DROP_TAGS = ("script", "style", "noscript", "svg", "nav", "header", "footer", "aside", "form", "iframe", "button")
_BLOCK_TAGS = (
    "p", "div", "li", "ul", "ol", "tr", "table", "section", "article", "h1", "h2", "h3", "h4", "h5", "h6",
    "pre", "blockquote", "br", "dd", "dt", "td", "th",
)  # fmt: skip
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


def html_to_text(html: str) -> str:
    """Main readable text of an HTML page, one block per line."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", MarkupResemblesLocatorWarning)
        soup = BeautifulSoup(html, "html.parser")
    for tag in soup(_DROP_TAGS):
        tag.decompose()
    root = soup.find("main") or soup.find("article") or soup.body or soup
    for tag in root.find_all(_BLOCK_TAGS):
        tag.insert_before("\n")
        tag.insert_after("\n")
    for code in root.find_all("code"):
        code.insert_before(" ")
        code.insert_after(" ")
    text = root.get_text(" ")
    lines = [normalize_text(line) for line in text.splitlines()]
    return "\n".join(line for line in lines if line)


def is_html(content_type: str, body_start: str) -> bool:
    return "html" in content_type.lower() or body_start.lstrip()[:15].lower().startswith(("<!doctype", "<html"))


def mentions_cve(text: str, cve_id: str) -> bool:
    return cve_id.lower() in text.lower()


def about_other_cve(url: str, cve_id: str) -> bool:
    """True when the URL names CVE IDs but not this one: the page is about a different CVE."""
    named = {match.upper() for match in _CVE_RE.findall(url)}
    return bool(named) and cve_id.upper() not in named


_SECTION_HINT = re.compile(
    r"(?i)\b(workaround|mitigat|remediat|solution|recommend|protect|disable|block|signature|threat id|"
    r"temporar|interim|fix|upgrade|update|patch)\w*"
)


def window_text(text: str, cve_id: str, max_chars: int = 24000) -> str:
    """Keep the parts of a long page that matter: everything if it fits, otherwise the lines around mentions of
    the CVE and of mitigation vocabulary, in page order."""
    if len(text) <= max_chars:
        return text
    lines = text.splitlines()
    keep: set[int] = set()
    for index, line in enumerate(lines):
        if cve_id.lower() in line.lower() or _SECTION_HINT.search(line):
            keep.update(range(max(0, index - 3), min(len(lines), index + 12)))
    if not keep:
        return text[:max_chars]
    out: list[str] = []
    total = 0
    previous = -2
    for index in sorted(keep):
        line = lines[index]
        if index != previous + 1 and out:
            out.append("[...]")
        if total + len(line) + 1 > max_chars:
            break
        out.append(line)
        total += len(line) + 1
        previous = index
    return "\n".join(out)


def prepare_source_text(body: str, content_type: str, cve_id: str, max_chars: int = 24000) -> str:
    """HTML -> text (JSON and plain text pass through), normalised, then windowed around the CVE."""
    text = html_to_text(body) if is_html(content_type, body[:200]) else "\n".join(
        normalize_text(line) for line in body.splitlines() if line.strip()
    )
    return window_text(text, cve_id, max_chars)
