"""Version comparison that copes with the strings scanners and advisories actually use.

`packaging.version` rejects most of them (`8.9p1`, `1:8.9p1-3ubuntu0.10`, `10.2.9-h1`, `13.1-48.47`), so this compares
segment by segment: numbers numerically, words lexically, with pre-release words (rc, beta...) sorting before the
release and other suffixes (p1, h3, update 2) sorting after it.
"""

from __future__ import annotations

import re
from functools import cmp_to_key

_PRE_RELEASE = {"alpha", "a", "beta", "b", "rc", "pre", "preview", "dev", "snapshot", "milestone", "m"}
_SEGMENT = re.compile(r"\d+|[a-z]+")
_DEB_REVISION = re.compile(r"-[^-]*\d[^-]*$")


def split_epoch(version: str) -> tuple[int, str]:
    head, sep, tail = version.partition(":")
    if sep and head.isdigit():
        return int(head), tail
    return 0, version


def upstream_version(version: str) -> str:
    """The upstream part of a distro package version: drop the epoch and the Debian/RPM revision.

    '1:8.9p1-3ubuntu0.10' -> '8.9p1'; '2.14.1-1.el8' -> '2.14.1'; '8.9p1' -> '8.9p1'.
    """
    _, rest = split_epoch(version.strip())
    if "-" in rest:
        stripped = _DEB_REVISION.sub("", rest)
        if stripped:
            return stripped
    return rest


def _segments(version: str) -> list[int | str]:
    return [int(part) if part.isdigit() else part for part in _SEGMENT.findall(version.lower())]


def _tail_sign(tail: list[int | str]) -> int:
    """How a version compares to itself plus `tail`: -1 when the tail is a pre-release marker, else +1 (or 0)."""
    for part in tail:
        if isinstance(part, str):
            return 1 if part in _PRE_RELEASE else -1
        if part != 0:
            return -1
    return 0


def compare_versions(left: str, right: str) -> int:
    """-1, 0 or 1. Epochs win first; then segment-by-segment comparison as described above."""
    left_epoch, left_rest = split_epoch(left.strip())
    right_epoch, right_rest = split_epoch(right.strip())
    if left_epoch != right_epoch:
        return -1 if left_epoch < right_epoch else 1
    a, b = _segments(left_rest), _segments(right_rest)
    for index in range(min(len(a), len(b))):
        x, y = a[index], b[index]
        if x == y:
            continue
        if isinstance(x, int) and isinstance(y, int):
            return -1 if x < y else 1
        if isinstance(x, str) and isinstance(y, str):
            x_pre, y_pre = x in _PRE_RELEASE, y in _PRE_RELEASE
            if x_pre != y_pre:
                return -1 if x_pre else 1
            return -1 if x < y else 1
        # A number against a word at the same position ('1.0.1' vs '1.0rc1', '8.9.1' vs '8.9p1'): the number is a
        # further release of the base, so it sorts after any suffix of that base.
        return 1 if isinstance(x, int) else -1
    if len(a) == len(b):
        return 0
    if len(a) < len(b):
        return _tail_sign(b[len(a):])
    return -_tail_sign(a[len(b):])


def version_key(version: str) -> object:
    return cmp_to_key(compare_versions)(version)


def in_range(
    version: str,
    *,
    start_including: str | None = None,
    start_excluding: str | None = None,
    end_including: str | None = None,
    end_excluding: str | None = None,
    exact: list[str] | None = None,
) -> bool | None:
    """Whether `version` falls in the range. None when the range has no bounds at all (can't tell)."""
    if exact:
        return any(compare_versions(version, item) == 0 for item in exact)
    bounds = (start_including, start_excluding, end_including, end_excluding)
    if not any(bounds):
        return None
    if start_including and compare_versions(version, start_including) < 0:
        return False
    if start_excluding and compare_versions(version, start_excluding) <= 0:
        return False
    if end_including and compare_versions(version, end_including) > 0:
        return False
    return not (end_excluding and compare_versions(version, end_excluding) >= 0)
