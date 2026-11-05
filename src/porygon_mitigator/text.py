"""Text normalisation shared by the fetcher, the evidence verifier and the reports.

A quote counts as verified when its normalised form appears in the normalised source text, so both sides must go
through exactly the same function.
"""

from __future__ import annotations

import re
import unicodedata

_PUNCTUATION = {
    "‘": "'",
    "’": "'",
    "‚": "'",
    "‛": "'",
    "′": "'",
    "“": '"',
    "”": '"',
    "„": '"',
    "″": '"',
    "«": '"',
    "»": '"',
    "‐": "-",
    "‑": "-",
    "‒": "-",
    "–": "-",
    "—": "-",
    "―": "-",
    "−": "-",
    "…": "...",
    " ": " ",
    " ": " ",
    " ": " ",
    "​": "",
    "‌": "",
    "‍": "",
    "﻿": "",
    "­": "",
}
_PUNCT_TABLE = str.maketrans(_PUNCTUATION)
_SPACE = re.compile(r"\s+")


def normalize_text(text: str) -> str:
    """NFKC, ASCII punctuation, collapsed whitespace. Case is kept (commands and registry paths are case-sensitive
    enough that we never lowercase evidence)."""
    text = unicodedata.normalize("NFKC", text).translate(_PUNCT_TABLE)
    return _SPACE.sub(" ", text).strip()


def to_ascii(text: str) -> str:
    """Console-safe rendering: normalised punctuation, then anything still non-ASCII replaced with '?'."""
    return normalize_text(text).encode("ascii", errors="replace").decode("ascii")


def contains_normalized(haystack: str, needle: str) -> bool:
    """Whether `needle` appears in `haystack` after normalising both. Empty needles never match."""
    needle_norm = normalize_text(needle)
    if not needle_norm:
        return False
    return needle_norm in normalize_text(haystack)


def clamp(text: str, limit: int) -> str:
    """Trim to `limit` characters on a word boundary, marking the cut."""
    text = text.strip()
    if len(text) <= limit:
        return text
    cut = text[: limit - 3].rsplit(" ", 1)[0]
    return cut + "..."
