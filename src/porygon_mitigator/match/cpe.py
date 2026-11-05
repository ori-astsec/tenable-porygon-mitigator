"""CPE 2.2 / 2.3 parsing and product keys."""

from __future__ import annotations

import re
from dataclasses import dataclass

from porygon_mitigator.models.actions import vendor_key

_ANY = {"*", "-", ""}


@dataclass(frozen=True)
class Cpe:
    part: str
    vendor: str
    product: str
    version: str | None
    update: str | None

    @property
    def key(self) -> str:
        return product_key(self.vendor, self.product)

    @property
    def full_version(self) -> str | None:
        """NVD splits 'OpenSSH 8.9p1' into version '8.9' and update 'p1'; join them back."""
        if not self.version:
            return None
        if self.update and re.fullmatch(r"[a-z]+\d*|\d+", self.update) and not self.version.endswith(self.update):
            return f"{self.version}{self.update}" if self.update[0].isalpha() else f"{self.version}.{self.update}"
        return self.version


def _split_escaped(text: str) -> list[str]:
    parts, current, escape = [], [], False
    for char in text:
        if escape:
            current.append(char)
            escape = False
        elif char == "\\":
            escape = True
        elif char == ":":
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
    parts.append("".join(current))
    return parts


def _clean(value: str | None) -> str | None:
    if value is None:
        return None
    value = value.replace("%2f", "/").replace("%3a", ":").strip()
    return None if value in _ANY else value


def parse_cpe(text: str) -> Cpe | None:
    """Parse 'cpe:2.3:a:openbsd:openssh:8.9:p1:*:*:*:*:*:*' or 'cpe:/a:openbsd:openssh:8.9p1'."""
    text = text.strip().lower()
    if text.startswith("cpe:2.3:"):
        fields = _split_escaped(text[len("cpe:2.3:"):])
    elif text.startswith("cpe:/"):
        fields = _split_escaped(text[len("cpe:/"):])
    else:
        return None
    fields += [""] * (5 - len(fields))
    part, vendor, product = fields[0], _clean(fields[1]), _clean(fields[2])
    if not vendor or not product:
        return None
    return Cpe(part=part or "a", vendor=vendor, product=product, version=_clean(fields[3]), update=_clean(fields[4]))


def product_slug(product: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", product.lower()).strip("_")


def product_key(vendor: str | None, product: str) -> str:
    return f"{vendor_key(vendor)}:{product_slug(product)}"


def products_match(left: str, right: str) -> str | None:
    """Compare two product slugs: 'exact', 'prefix' (windows_11 vs windows_11_21h2), 'contains' (office vs
    microsoft_office_professional_plus_2019, whole tokens only) or None."""
    a, b = product_slug(left), product_slug(right)
    if not a or not b:
        return None
    if a == b or a.replace("_", "") == b.replace("_", ""):
        return "exact"
    if a.startswith(b + "_") or b.startswith(a + "_"):
        return "prefix"
    short, long = (a, b) if len(a) <= len(b) else (b, a)
    if len(short) >= 3 and f"_{short}_" in f"_{long}_":
        return "contains"
    return None
