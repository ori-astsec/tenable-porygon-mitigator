"""Is this machine affected by the CVE at all?

Order of trust: a scanner finding for the CVE on this machine beats everything; then the CVE's vulnerable product
ranges against the machine's installed software (and its OS / appliance identity). Distro packages are only ever
"likely": distributions backport fixes without changing the upstream version.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from porygon_mitigator.match.cpe import parse_cpe, product_slug, products_match
from porygon_mitigator.match.version import compare_versions, in_range, upstream_version
from porygon_mitigator.models.actions import vendor_key
from porygon_mitigator.models.assessment import AffectednessResult
from porygon_mitigator.models.cve import AffectedRange, CveFacts
from porygon_mitigator.models.machine import MachineProfile

DISTRO_PACKAGE_OS = {
    "ubuntu", "debian", "rhel", "redhat", "centos", "rocky", "almalinux", "fedora", "oracle", "ol",
    "suse", "sles", "opensuse", "amazon", "amzn", "alpine",
}  # fmt: skip

# Appliance OS keys -> (vendor key, product slug) the way NVD names them.
_APPLIANCE_IDENTITY = {
    "panos": ("paloaltonetworks", "pan-os"),
    "pan-os": ("paloaltonetworks", "pan-os"),
    "fortios": ("fortinet", "fortios"),
    "netscaler": ("citrix", "netscaler_application_delivery_controller"),
    "tmos": ("f5", "big-ip_local_traffic_manager"),
    "ios_xe": ("cisco", "ios_xe"),
    "ios": ("cisco", "ios"),
    "asa": ("cisco", "adaptive_security_appliance_software"),
    "junos": ("junipernetworks", "junos"),
    "esxi": ("vmware", "esxi"),
}


@dataclass(frozen=True)
class InstalledItem:
    vendor: str  # vendor key, may be empty
    product: str  # product slug
    version: str | None
    label: str
    distro_package: bool


def installed_items(machine: MachineProfile) -> list[InstalledItem]:
    distro = (machine.os.distribution or "").lower()
    from_distro = distro in DISTRO_PACKAGE_OS
    items: list[InstalledItem] = []
    for software in machine.installed_software:
        cpe = parse_cpe(software.cpe) if software.cpe else None
        vendor = vendor_key(software.vendor) if software.vendor else (vendor_key(cpe.vendor) if cpe else "")
        product = product_slug(software.product) if software.product else (product_slug(cpe.product) if cpe else "")
        version = software.version or (cpe.full_version if cpe else None)
        label = software.product or (cpe.product if cpe else "software")
        if version:
            label = f"{label} {version}"
        items.append(InstalledItem(vendor, product, version, label, from_distro and bool(software.package)))
    items.extend(_os_identity(machine))
    return items


def _os_identity(machine: MachineProfile) -> list[InstalledItem]:
    os = machine.os
    version = os.version
    out: list[InstalledItem] = []
    distro = (os.distribution or "").lower()
    if distro in _APPLIANCE_IDENTITY:
        vendor, product = _APPLIANCE_IDENTITY[distro]
        out.append(InstalledItem(vendor, product_slug(product), version, f"{os.name or product} (OS)", False))
    if os.platform == "windows" and os.name:
        name = re.sub(r"(?i)^microsoft\s+", "", os.name)
        name = re.sub(r"(?i)\b(standard|datacenter|enterprise|pro|home|education)\b", "", name)
        out.append(InstalledItem("microsoft", product_slug(name), version, f"{os.name} (OS)", False))
    elif machine.vendor and os.name and not out:
        out.append(InstalledItem(vendor_key(machine.vendor), product_slug(os.name), version, f"{os.name} (OS)", False))
    if os.platform == "linux":
        # Distro kernels carry backports too, so a distro kernel version is treated like a distro package.
        label = f"Linux kernel {os.kernel or '?'}"
        out.append(InstalledItem("linux", "linux_kernel", os.kernel, label, distro in DISTRO_PACKAGE_OS))
    return out


_RHEL_FAMILY = {"rhel", "redhat", "centos", "rocky", "almalinux", "ol", "oracle"}


def _distro_release(machine: MachineProfile) -> tuple[str, str] | None:
    distro = (machine.os.distribution or "").lower()
    version = machine.os.version or ""
    if distro == "ubuntu" and version:
        return "ubuntu", ".".join(version.split(".")[:2])
    if distro in _RHEL_FAMILY and version:
        return "rhel", version.split(".")[0]
    return None


def _package_matches(fix_package: str, installed: str) -> bool:
    fix_package, installed = fix_package.lower(), installed.lower()
    return installed == fix_package or installed.startswith(fix_package + "-") or fix_package.startswith(
        installed + "-")


def distro_verdict(facts: CveFacts, machine: MachineProfile) -> AffectednessResult | None:
    """Exact answer from the distribution's own package data, when the machine runs that distribution and lists the
    package. Backports make this more reliable than upstream version ranges."""
    release = _distro_release(machine)
    if release is None or not facts.distro_fixes:
        return None
    distro, version = release
    for software in machine.installed_software:
        if not software.package or not software.version:
            continue
        for fix in facts.distro_fixes:
            if fix.distro != distro or fix.release != version or not _package_matches(fix.package, software.package):
                continue
            label = f"{software.package} {software.version}"
            name = "Ubuntu" if distro == "ubuntu" else "Red Hat"
            if fix.status == "not_affected":
                return AffectednessResult(status="not_affected", matched_software=[label],
                                          reasons=[f"{name} {version} lists {fix.package} as not affected"])
            if fix.status == "fixed" and fix.fixed_version:
                if compare_versions(software.version, fix.fixed_version) >= 0:
                    return AffectednessResult(status="not_affected", matched_software=[label], reasons=[
                        f"{label} includes {name}'s fix ({fix.fixed_version})"])
                return AffectednessResult(status="affected", matched_software=[label], reasons=[
                    f"{label} is older than {name}'s fixed package {fix.fixed_version}"])
            if fix.status in ("affected", "wont_fix", "deferred"):
                why = {"affected": "no fixed package yet", "wont_fix": "the distribution won't fix it",
                       "deferred": "the fix is deferred"}[fix.status]
                return AffectednessResult(status="affected", matched_software=[label],
                                          reasons=[f"{name} {version}: {fix.package} is affected and {why}"])
    return None


def _vendor_ok(rng: AffectedRange, item: InstalledItem) -> bool:
    return not item.vendor or vendor_key(rng.vendor) == item.vendor


def _range_text(rng: AffectedRange) -> str:
    parts = []
    if rng.version_start_including:
        parts.append(f">= {rng.version_start_including}")
    if rng.version_start_excluding:
        parts.append(f"> {rng.version_start_excluding}")
    if rng.version_end_including:
        parts.append(f"<= {rng.version_end_including}")
    if rng.version_end_excluding:
        parts.append(f"< {rng.version_end_excluding}")
    if rng.exact_versions:
        parts.append("in [" + ", ".join(rng.exact_versions[:5]) + "]")
    return " and ".join(parts) or "any version"


def assess_affected(facts: CveFacts, machine: MachineProfile) -> AffectednessResult:
    findings = [item for item in machine.findings if item.cve.upper() == facts.cve_id.upper()]
    open_findings = [item for item in findings if item.state != "fixed"]
    if open_findings:
        finding = open_findings[0]
        where = f" (plugin {finding.plugin_id})" if finding.plugin_id else ""
        source = finding.source or "a scanner"
        return AffectednessResult(
            status="affected",
            reasons=[f"{source}{where} reports {facts.cve_id} as {finding.state} on this machine"],
            matched_software=[],
        )
    if findings:
        return AffectednessResult(status="not_affected", reasons=[f"the scanner reports {facts.cve_id} as fixed"])

    distro = distro_verdict(facts, machine)
    if distro is not None:
        return distro

    verdicts: list[tuple[str, str, str]] = []  # (status, reason, label)
    for rng in facts.affected:
        for item in installed_items(machine):
            if not _vendor_ok(rng, item):
                continue
            match = products_match(rng.product, item.product)
            if match is None:
                continue
            if not item.version:
                verdicts.append(("likely", f"{item.label} is installed but its version is unknown", item.label))
                continue
            version = upstream_version(item.version) if item.distro_package else item.version
            result = in_range(
                version,
                start_including=rng.version_start_including,
                start_excluding=rng.version_start_excluding,
                end_including=rng.version_end_including,
                end_excluding=rng.version_end_excluding,
                exact=rng.exact_versions or None,
            )
            if result is None:
                verdicts.append(("likely", f"{item.label} matches {rng.product}; the CVE gives no version range",
                                 item.label))
            elif result:
                if item.distro_package:
                    reason = (f"{item.label}: upstream version {version} is in the vulnerable range "
                              f"({_range_text(rng)}), but distro packages often carry backported fixes; "
                              "check the distro's advisory")
                    verdicts.append(("likely", reason, item.label))
                elif match in ("prefix", "contains"):
                    verdicts.append(("likely", f"{item.label} resembles {rng.product} ({_range_text(rng)})",
                                     item.label))
                else:
                    verdicts.append(("affected", f"{item.label} is in the vulnerable range ({_range_text(rng)})",
                                     item.label))
            else:
                verdicts.append(("not_affected", f"{item.label} is outside the vulnerable range ({_range_text(rng)})",
                                 item.label))

    for status in ("affected", "likely"):
        hits = [entry for entry in verdicts if entry[0] == status]
        if hits:
            return AffectednessResult(
                status="affected" if status == "affected" else "likely",
                reasons=list(dict.fromkeys(entry[1] for entry in hits)),
                matched_software=list(dict.fromkeys(entry[2] for entry in hits)),
            )
    if verdicts:
        return AffectednessResult(
            status="not_affected",
            reasons=list(dict.fromkeys(entry[1] for entry in verdicts)),
            matched_software=list(dict.fromkeys(entry[2] for entry in verdicts)),
        )
    products = ", ".join(dict.fromkeys(rng.product for rng in facts.affected)) or "no product data"
    reason = (f"no installed software in the profile matches the CVE's products ({products}); "
              "the inventory may be incomplete")
    return AffectednessResult(status="unknown", reasons=[reason])
