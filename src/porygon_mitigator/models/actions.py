"""The action vocabulary: the one concrete change a mitigation makes, as a normalised `(kind, target)` pair.

Two mitigations from different sources that make the same change get the same pair, whatever their wording. That
pair drives deduplication, "is it already applied on this machine?" checks, and matching against eval gold.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Literal, get_args

ActionKind = Literal[
    "set_config",  # <product>:<setting>=<value>         openssh:logingracetime=0
    "disable_app_feature",  # <product>:<feature>        fortios:ssl_vpn, ios_xe:http_server
    "set_registry_value",  # <hive>\<path>\<name>=<data>  hklm\system\...\tcpreceivepacketsize=65280
    "delete_registry_key",  # <hive>\<path> (a key, or a value under it)   hkcr\ms-msdt
    "disable_service",  # <service name>                 spooler
    "disable_os_feature",  # <feature name>              smb1protocol
    "disable_kernel_module",  # <module>                 nf_tables
    "set_sysctl",  # <key>=<value>                       kernel.unprivileged_userns_clone=0
    "set_boot_parameter",  # <token>                     nosmt
    "remove_component",  # <product>:<component>         log4j:jndilookup
    "restrict_file_permission",  # <path>                /usr/bin/pkexec, %windir%\system32\config
    "restrict_network_access",  # port:<n>/<proto> | <product>
    "block_request_pattern",  # <product>:<path or pattern>   confluence:/setup/*
    "apply_waf_rule",  # <vendor>:<rule id>              cloudflare:100514
    "apply_ips_signature",  # <vendor>:<signature id>     paloaltonetworks:95187
    "enable_endpoint_protection",  # <product>:<rule>     defender:asr_block_office_child_processes
    "avoid_untrusted_input",  # <product>:<input type>    office:documents_from_internet
    "other",
]
ACTION_KINDS: tuple[str, ...] = get_args(ActionKind)

# Kinds that only exist on one platform, so a plan that names no OS still gets the right one.
KIND_PLATFORM: dict[str, str] = {
    "set_registry_value": "windows",
    "delete_registry_key": "windows",
    "disable_os_feature": "windows",
    "disable_kernel_module": "linux",
    "set_sysctl": "linux",
    "set_boot_parameter": "linux",
}

_REGISTRY_HIVES = {
    "hkey_local_machine": "hklm",
    "hkey_current_user": "hkcu",
    "hkey_classes_root": "hkcr",
    "hkey_users": "hku",
    "hkey_current_config": "hkcc",
}
_HIVE_RE = re.compile(r"^(hkey_local_machine|hkey_current_user|hkey_classes_root|hkey_users|hkey_current_config"
                      r"|hklm|hkcu|hkcr|hku|hkcc):?\\+")
_HEX_RE = re.compile(r"^0x[0-9a-f]+$")
_VALUE = r"[a-z0-9_.,:*/ !@+%~-]+"  # cipher lists need ! and @ (high:!3des, -cbc@openssh.com)
_PRODUCT = r"[a-z0-9][a-z0-9._+-]*"

_TARGET_SHAPES: dict[str, re.Pattern[str]] = {
    "set_config": re.compile(rf"^{_PRODUCT}:[a-z0-9][a-z0-9._/+-]*(={_VALUE})?$"),
    "disable_app_feature": re.compile(rf"^{_PRODUCT}:[a-z0-9][a-z0-9._/+-]*$"),
    "set_registry_value": re.compile(rf"^(hklm|hkcu|hkcr|hku|hkcc)(\\[^\\=]+)+={_VALUE}$"),
    "delete_registry_key": re.compile(r"^(hklm|hkcu|hkcr|hku|hkcc)(\\[^\\=]+)+$"),
    "disable_service": re.compile(r"^[a-z0-9][a-z0-9_.@-]*$"),
    "disable_os_feature": re.compile(r"^[a-z0-9][a-z0-9._-]*$"),
    "disable_kernel_module": re.compile(r"^[a-z0-9_]+$"),
    "set_sysctl": re.compile(rf"^[a-z0-9_-]+(\.[a-z0-9_*-]+)+={_VALUE}$"),
    "set_boot_parameter": re.compile(r"^[a-z0-9_.-]+(=[a-z0-9_.,-]+)?$"),
    "remove_component": re.compile(rf"^{_PRODUCT}:[a-z0-9][a-z0-9._/+-]*$"),
    "restrict_file_permission": re.compile(r"^(/\S+|(%[a-z0-9_()]+%|[a-z]:)(\\[^\\]+)+)$"),
    "restrict_network_access": re.compile(rf"^(port:\d{{1,5}}/(tcp|udp)|{_PRODUCT})$"),
    "block_request_pattern": re.compile(rf"^{_PRODUCT}:\S+$"),
    "apply_waf_rule": re.compile(rf"^{_PRODUCT}:[a-z0-9][a-z0-9._-]*$"),
    "apply_ips_signature": re.compile(rf"^{_PRODUCT}:[a-z0-9][a-z0-9._-]*$"),
    "enable_endpoint_protection": re.compile(rf"^{_PRODUCT}:[a-z0-9][a-z0-9._-]*$"),
    "avoid_untrusted_input": re.compile(rf"^{_PRODUCT}:[a-z0-9][a-z0-9._-]*$"),
}

# Vendor spellings collapse to one key so device/tool matching doesn't depend on how a source writes the name.
_VENDOR_ALIASES: dict[str, str] = {
    "paloalto": "paloaltonetworks",
    "paloaltonetworksinc": "paloaltonetworks",
    "pan": "paloaltonetworks",
    "panos": "paloaltonetworks",
    "f5networks": "f5",
    "f5inc": "f5",
    "bigip": "f5",
    "netscaler": "citrix",
    "cloudsoftwaregroup": "citrix",
    "citrixsystems": "citrix",
    "microsoftcorporation": "microsoft",
    "azure": "microsoft",
    "ciscosystems": "cisco",
    "ciscosystemsinc": "cisco",
    "meraki": "cisco",
    "fortinetinc": "fortinet",
    "fortigate": "fortinet",
    "checkpointsoftware": "checkpoint",
    "checkpointsoftwaretechnologies": "checkpoint",
    "amazon": "aws",
    "amazonwebservices": "aws",
    "googlecloud": "google",
    "gcp": "google",
    "cloudflareinc": "cloudflare",
    "akamaitechnologies": "akamai",
    "crowdstrikeinc": "crowdstrike",
    "sentinelone": "sentinelone",
    "sentinellabs": "sentinelone",
    "trellix": "trellix",
    "mcafee": "trellix",
    "kemptechnologies": "kemp",
    "progresskemp": "kemp",
    "juniper": "junipernetworks",
    "sophosltd": "sophos",
}


def vendor_key(name: str | None) -> str:
    """'Palo Alto Networks' -> 'paloaltonetworks'; unknown names are lowercased with non-alphanumerics removed."""
    if not name:
        return ""
    key = re.sub(r"[^a-z0-9]", "", name.lower())
    return _VENDOR_ALIASES.get(key, key)


def identifier(text: str) -> str:
    """A target part as an identifier: lowercase, spaces and stray punctuation become `_`, collapsed and trimmed."""
    text = text.strip().strip("'\"`").lower()
    return re.sub(r"_+", "_", re.sub(r"[^a-z0-9._+@*=,/:-]", "_", text)).strip("_")


def rule_key(rule: str) -> str:
    """A signature or rule ID in comparable form: '3:62541' (Snort GID:SID) and '62541' are one rule."""
    rule = rule.strip().strip("'\"`").lower().lstrip(".")
    return re.sub(r"^\d+:(\d+)$", r"\1", rule)


def _setting(key: str, value: str) -> str:
    value = re.sub(r"\s+", " ", value.strip().strip("'\"`"))
    if _HEX_RE.fullmatch(value):
        value = str(int(value, 16))
    return f"{key.strip()}={value}"


def registry_path(path: str) -> str:
    """Short hive, single backslashes, lowercase: 'HKEY_CLASSES_ROOT\\\\ms-msdt' -> 'hkcr\\ms-msdt'."""
    path = path.strip().strip("'\"`").lower().replace("/", "\\")
    path = re.sub(r"\\+", r"\\", path)
    hive = _HIVE_RE.match(path)
    if not hive:
        return path
    short = _REGISTRY_HIVES.get(hive.group(1), hive.group(1))
    return f"{short}\\{path[hive.end():]}".rstrip("\\")


def _file_path(raw: str) -> str:
    """Unix paths keep their case; Windows paths are case-insensitive, so they are lowercased. A trailing wildcard
    ('/*', '\\*.*') is dropped, so a directory and "everything in it" share one key."""
    unix = raw.startswith("/")
    path = raw.split()[0] if unix else re.sub(r"\\+", r"\\", raw.lower().replace("/", "\\"))
    return re.sub(r"[/\\]\*(\.\*)?$", "", path)


def _product(product: str, known_products: Iterable[str]) -> str:
    slug = identifier(product).replace("-", "_")
    for known in known_products:
        known_slug = identifier(known).replace("-", "_")
        if known_slug == slug or known_slug.endswith(f":{slug}"):
            return identifier(known.split(":")[-1])
    return identifier(product)


def normalize_action(kind: str, target: str, known_products: Iterable[str] = ()) -> tuple[str, str]:
    """Return the stored `(kind, target)`; anything outside the vocabulary or the kind's shape becomes `('other', '')`.

    `known_products` are the CVE's own product names (from its CPEs), so 'OpenSSH' and 'openssh' land on one key.
    """
    other = ("other", "")
    kind = kind.strip().lower()
    if kind not in ACTION_KINDS or kind == "other":
        return other
    known = list(known_products)
    raw = target.strip().strip("'\"`")
    text = raw.lower()
    if kind == "set_config":
        product, _, rest = text.partition(":")
        setting, sep, value = rest.partition("=")
        text = f"{_product(product, known)}:{identifier(setting)}"
        if sep:
            text = _setting(text, value)
    elif kind in ("disable_app_feature", "remove_component", "enable_endpoint_protection", "avoid_untrusted_input"):
        product, _, item = text.partition(":")
        text = f"{_product(product, known)}:{identifier(item)}"
    elif kind in ("apply_waf_rule", "apply_ips_signature"):
        vendor, _, rule = text.partition(":")
        text = f"{vendor_key(vendor)}:{identifier(rule_key(rule))}"
    elif kind == "block_request_pattern":
        product, _, pattern = raw.partition(":")
        text = f"{_product(product, known)}:{pattern.strip()}"
    elif kind == "set_registry_value":
        path, _, value = text.partition("=")
        text = _setting(registry_path(path), value)
    elif kind == "delete_registry_key":
        text = registry_path(text)
    elif kind == "set_sysctl":
        key, _, value = text.partition("=")
        text = _setting(key.strip().replace("/", "."), value)
    elif kind == "disable_service":
        text = identifier(text.removesuffix(".service"))
    elif kind == "disable_kernel_module":
        text = identifier(text.removesuffix(".ko")).replace("-", "_")
    elif kind == "restrict_file_permission":
        text = _file_path(raw)
    elif kind == "restrict_network_access":
        text = re.sub(r"\s+", "", text) if text.startswith("port:") else _product(text, known)
    else:
        text = identifier(text)
    shape = _TARGET_SHAPES.get(kind)
    return (kind, text) if shape is not None and shape.fullmatch(text) else other


def action_platform(kind: str) -> str | None:
    """The platform a kind implies, if it exists on only one."""
    return KIND_PLATFORM.get(kind)
