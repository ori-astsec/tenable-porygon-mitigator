"""Shared vocabularies used by the machine profile, the mitigation records and the assessment."""

from __future__ import annotations

from typing import Literal

Platform = Literal["windows", "linux", "macos", "network_os", "unix", "other"]
"""Operating-system family. `network_os` covers appliances (PAN-OS, FortiOS, NetScaler, Cisco IOS, F5 TMOS...)."""

DeviceRole = Literal["ngfw", "ips", "waf", "load_balancer", "proxy", "router", "vpn_gateway"]
"""Role of a network security device that traffic to the machine crosses."""

SecurityToolCategory = Literal["edr", "av", "hids", "host_firewall"]

MitigationType = Literal[
    "CONFIGURATION",  # change a setting or config file so the vulnerable path can't be reached
    "REGISTRY_KEY",  # set, lock down or delete a Windows registry key/value
    "DISABLE",  # disable/stop a service, feature, protocol, kernel module or component
    "NETWORK_ACL",  # restrict network access to the vulnerable listener (firewall rule, ACL, bind address)
    "WAF",  # web application firewall rule or signature
    "IPS",  # intrusion prevention signature on a network device
    "EDR",  # endpoint protection rule, signature or feature
    "OTHER",  # concrete, source-backed mitigation that fits none of the above
]

Layer = Literal["host", "network_device", "waf", "ips", "edr"]

Confidence = Literal["vendor_documented", "third_party", "derived"]

ApplicabilityStatus = Literal["applicable", "already_applied", "needs_device", "not_applicable", "unknown"]

Affectedness = Literal["affected", "likely", "not_affected", "unknown"]

MachineVerdict = Literal[
    "not_affected",
    "mitigations_available",
    "already_mitigated",
    "needs_additional_controls",
    "no_documented_mitigation",
    "unknown",
]

SourceStatusValue = Literal[
    "ok",  # fetched and at least one mitigation extracted
    "no_mitigation",  # fetched, discusses the CVE, but documents no mitigation
    "not_listed",  # the source has no entry for this CVE
    "unreadable",  # fetched but the text never mentions the CVE (JS-only page, wrong page...)
    "unreachable",  # network error, timeout, HTTP error
    "skipped",  # not attempted (budget, off-allowlist redirect, binary, too large)
]
