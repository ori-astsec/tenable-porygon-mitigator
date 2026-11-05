"""Every host porygon-mitigator may contact, and why.

This module is the single source of truth for outbound network access: the HTTP client refuses any URL (and any
redirect hop) whose host is not listed here, web-search results are filtered against it, and a test keeps the
README's egress table identical to it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal
from urllib.parse import urlsplit

from porygon_mitigator.models.actions import vendor_key
from porygon_mitigator.models.mitigation import SourceKind

Category = Literal["llm", "cve_data", "government", "distro", "vendor", "project", "waf_ips", "research", "tenable"]


@dataclass(frozen=True)
class Host:
    domain: str
    publisher: str
    category: Category
    source_kind: SourceKind
    purpose: str
    search: bool = True  # may be passed to Claude web search as an allowed domain
    search_path: str = ""  # optional path prefix for web search ("/en-us/msrc" -> "www.microsoft.com/en-us/msrc")


HOSTS: tuple[Host, ...] = (
    # Model provider
    Host("api.anthropic.com", "anthropic", "llm", "third_party", "Claude API: extraction, arbitration, web search",
         search=False),
    # CVE data and government sources
    Host("cveawg.mitre.org", "cve.org", "cve_data", "government", "CVE records (CVE JSON 5)", search=False),
    Host("services.nvd.nist.gov", "nvd", "cve_data", "government", "NVD CVE API 2.0: CPE ranges, tagged references",
         search=False),
    Host("nvd.nist.gov", "nvd", "cve_data", "government", "NVD vulnerability pages", search=False),
    Host("www.cisa.gov", "cisa", "government", "government", "CISA KEV catalog, advisories and alerts"),
    Host("kb.cert.org", "cert-cc", "government", "government", "CERT/CC vulnerability notes (often list workarounds)"),
    Host("api.osv.dev", "osv", "cve_data", "third_party", "OSV vulnerability API (GHSA and ecosystem advisories)",
         search=False),
    # Linux distributions
    Host("access.redhat.com", "redhat", "distro", "distro", "Red Hat Security Data API and CVE pages"),
    Host("ubuntu.com", "ubuntu", "distro", "distro", "Ubuntu CVE tracker"),
    Host("security-tracker.debian.org", "debian", "distro", "distro", "Debian security tracker"),
    Host("www.suse.com", "suse", "distro", "distro", "SUSE CVE pages"),
    Host("alas.aws.amazon.com", "amazon-linux", "distro", "distro", "Amazon Linux security advisories"),
    # Platform and product vendors
    Host("api.msrc.microsoft.com", "msrc", "vendor", "vendor", "Microsoft CVRF API (workarounds, mitigations)",
         search=False),
    Host("msrc.microsoft.com", "msrc", "vendor", "vendor", "Microsoft Security Response Center"),
    Host("www.microsoft.com", "msrc", "vendor", "vendor", "MSRC blog guidance", search_path="/en-us/msrc"),
    Host("learn.microsoft.com", "microsoft-docs", "vendor", "vendor", "Microsoft docs (ASR rules, Azure WAF rules)"),
    Host("support.microsoft.com", "microsoft-support", "vendor", "vendor", "Microsoft KB articles"),
    Host("techcommunity.microsoft.com", "microsoft-blogs", "vendor", "vendor", "Microsoft product team guidance"),
    Host("security.paloaltonetworks.com", "paloalto", "vendor", "vendor", "Palo Alto Networks security advisories"),
    Host("unit42.paloaltonetworks.com", "unit42", "research", "vendor", "Unit 42 threat briefs"),
    Host("docs.paloaltonetworks.com", "paloalto-docs", "vendor", "vendor", "Palo Alto Networks documentation"),
    Host("sec.cloudapps.cisco.com", "cisco", "vendor", "vendor", "Cisco security advisories"),
    Host("blog.talosintelligence.com", "talos", "research", "vendor", "Cisco Talos coverage notes"),
    Host("www.fortiguard.com", "fortinet", "vendor", "vendor", "Fortinet PSIRT advisories"),
    Host("support.citrix.com", "citrix", "vendor", "vendor", "Citrix / NetScaler security bulletins"),
    Host("www.netscaler.com", "netscaler", "vendor", "vendor", "NetScaler blog guidance"),
    Host("my.f5.com", "f5", "vendor", "vendor", "F5 security advisories"),
    Host("support.broadcom.com", "broadcom", "vendor", "vendor", "VMware (Broadcom) security advisories"),
    Host("supportportal.juniper.net", "juniper", "vendor", "vendor", "Juniper security advisories"),
    Host("forums.ivanti.com", "ivanti", "vendor", "vendor", "Ivanti security advisories"),
    Host("advisories.checkpoint.com", "checkpoint", "vendor", "vendor", "Check Point advisories"),
    Host("confluence.atlassian.com", "atlassian", "vendor", "vendor", "Atlassian security advisories"),
    Host("www.oracle.com", "oracle", "vendor", "vendor", "Oracle security alerts"),
    Host("www.ibm.com", "ibm", "vendor", "vendor", "IBM security bulletins"),
    # Open-source projects
    Host("logging.apache.org", "apache-logging", "project", "vendor", "Apache Logging (Log4j) security page"),
    Host("httpd.apache.org", "apache-httpd", "project", "vendor", "Apache HTTP Server vulnerabilities"),
    Host("tomcat.apache.org", "apache-tomcat", "project", "vendor", "Apache Tomcat security pages"),
    Host("cwiki.apache.org", "apache-wiki", "project", "vendor", "Apache project security bulletins (Struts...)"),
    Host("www.openssh.com", "openssh", "project", "vendor", "OpenSSH release and security notes"),
    Host("openssl-library.org", "openssl", "project", "vendor", "OpenSSL security advisories"),
    Host("nginx.org", "nginx", "project", "vendor", "nginx security advisories"),
    Host("www.php.net", "php", "project", "vendor", "PHP changelog"),
    Host("nodejs.org", "nodejs", "project", "vendor", "Node.js security releases"),
    Host("www.jenkins.io", "jenkins", "project", "vendor", "Jenkins security advisories"),
    Host("spring.io", "spring", "project", "vendor", "Spring security advisories"),
    Host("about.gitlab.com", "gitlab", "project", "vendor", "GitLab security releases"),
    Host("www.openwall.com", "oss-security", "project", "third_party", "oss-security mailing list archive"),
    Host("curl.se", "curl", "project", "vendor", "curl security advisories"),
    Host("www.papercut.com", "papercut", "vendor", "vendor", "PaperCut security bulletins"),
    Host("github.com", "github-advisories", "project", "third_party", "GitHub security advisories",
         search_path="/advisories"),
    # WAF / IPS / CDN providers and rule catalogues
    Host("developers.cloudflare.com", "cloudflare", "waf_ips", "vendor", "Cloudflare WAF changelog and docs"),
    Host("blog.cloudflare.com", "cloudflare-blog", "waf_ips", "vendor", "Cloudflare WAF rule announcements"),
    Host("docs.aws.amazon.com", "aws-docs", "waf_ips", "vendor", "AWS WAF managed rule documentation"),
    Host("cloud.google.com", "google-cloud", "waf_ips", "vendor", "Cloud Armor preconfigured WAF rules"),
    Host("www.snort.org", "snort", "waf_ips", "catalog", "Snort 3 community rules and rule docs", search=False),
    Host("snort-org-site.s3.amazonaws.com", "snort", "waf_ips", "catalog",
         "Snort rule downloads (snort.org redirects here)", search=False),
    Host("rules.emergingthreats.net", "et-open", "waf_ips", "catalog", "Proofpoint ET Open rules", search=False),
    Host("docs.cloud.f5.com", "f5-signatures", "waf_ips", "catalog", "F5 attack signature reference", search=False),
    Host("docs.netscaler.com", "netscaler-docs", "waf_ips", "catalog", "NetScaler WAF signature updates",
         search=False),
    Host("api.threatvault.paloaltonetworks.com", "threat-vault", "waf_ips", "catalog",
         "Palo Alto Threat Vault API (only with your own key)", search=False),
    # Security research
    Host("www.tenable.com", "tenable", "research", "third_party", "Tenable CVE pages and research blog"),
    Host("blog.qualys.com", "qualys", "research", "third_party", "Qualys threat research"),
    Host("www.rapid7.com", "rapid7", "research", "third_party", "Rapid7 analysis"),
    Host("www.huntress.com", "huntress", "research", "third_party", "Huntress analysis"),
    # Tenable One integration (only when you configure Tenable keys)
    Host("cloud.tenable.com", "tenable-one", "tenable", "vendor", "Tenable One / Tenable VM API (your tenant)",
         search=False),
)

_BY_DOMAIN = {host.domain: host for host in HOSTS}

# Per-CVE URL templates fetched directly (no search needed).
TEMPLATES: tuple[tuple[str, str], ...] = (
    ("redhat", "https://access.redhat.com/security/cve/{cve_lower}"),
    ("ubuntu", "https://ubuntu.com/security/{cve}"),
    ("debian", "https://security-tracker.debian.org/tracker/{cve}"),
    ("suse", "https://www.suse.com/security/cve/{cve}.html"),
    ("tenable", "https://www.tenable.com/cve/{cve}"),
    ("paloalto", "https://security.paloaltonetworks.com/{cve}"),
)

# Vendor key -> domains worth searching for that vendor's CVEs.
VENDOR_DOMAINS: dict[str, tuple[str, ...]] = {
    "microsoft": ("msrc.microsoft.com", "www.microsoft.com", "learn.microsoft.com", "support.microsoft.com",
                  "techcommunity.microsoft.com"),
    "paloaltonetworks": ("security.paloaltonetworks.com", "unit42.paloaltonetworks.com", "docs.paloaltonetworks.com"),
    "cisco": ("sec.cloudapps.cisco.com", "blog.talosintelligence.com"),
    "fortinet": ("www.fortiguard.com",),
    "citrix": ("support.citrix.com", "www.netscaler.com"),
    "f5": ("my.f5.com", "nginx.org"),
    "vmware": ("support.broadcom.com", "spring.io"),
    "broadcom": ("support.broadcom.com",),
    "junipernetworks": ("supportportal.juniper.net",),
    "ivanti": ("forums.ivanti.com",),
    "checkpoint": ("advisories.checkpoint.com",),
    "atlassian": ("confluence.atlassian.com",),
    "oracle": ("www.oracle.com",),
    "ibm": ("www.ibm.com",),
    "apache": ("logging.apache.org", "httpd.apache.org", "tomcat.apache.org", "cwiki.apache.org"),
    "openbsd": ("www.openssh.com", "www.openwall.com"),
    "openssl": ("openssl-library.org",),
    "nginx": ("nginx.org",),
    "php": ("www.php.net",),
    "nodejs": ("nodejs.org",),
    "jenkins": ("www.jenkins.io",),
    "gitlab": ("about.gitlab.com",),
    "linux": ("access.redhat.com", "ubuntu.com", "www.suse.com", "security-tracker.debian.org", "www.openwall.com"),
}
CORE_SEARCH_DOMAINS: tuple[str, ...] = ("www.cisa.gov", "kb.cert.org", "www.tenable.com", "github.com")
DISTRO_SEARCH_DOMAINS: tuple[str, ...] = ("access.redhat.com", "ubuntu.com")
WEB_SEARCH_DOMAINS: tuple[str, ...] = ("blog.cloudflare.com", "learn.microsoft.com")
MAX_SEARCH_DOMAINS = 15

# Device vendor key -> domains that publish that vendor's IPS/WAF signature coverage for a CVE.
IPS_VENDOR_DOMAINS: dict[str, tuple[str, ...]] = {
    "fortinet": ("www.fortiguard.com",),
    "paloaltonetworks": ("unit42.paloaltonetworks.com", "security.paloaltonetworks.com", "docs.paloaltonetworks.com"),
    "cisco": ("blog.talosintelligence.com", "sec.cloudapps.cisco.com"),
    "checkpoint": ("advisories.checkpoint.com",),
    "cloudflare": ("blog.cloudflare.com", "developers.cloudflare.com"),
    "f5": ("my.f5.com",),
    "citrix": ("www.netscaler.com", "support.citrix.com"),
}
# Signature publishers searched for every network-reachable CVE, whatever sits in front of the machine.
IPS_CORE_DOMAINS: tuple[str, ...] = ("blog.talosintelligence.com", "advisories.checkpoint.com",
                                     "unit42.paloaltonetworks.com", "www.fortiguard.com", "blog.cloudflare.com")


def host_of(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def lookup(url_or_host: str) -> Host | None:
    """The registry entry for a URL or host, matching subdomains on a dot boundary."""
    host = host_of(url_or_host) if "/" in url_or_host else url_or_host.lower()
    while host:
        if host in _BY_DOMAIN:
            return _BY_DOMAIN[host]
        _, _, host = host.partition(".")
    return None


def is_allowed(url: str) -> bool:
    parts = urlsplit(url)
    if parts.scheme != "https":
        return False
    try:
        port = parts.port
    except ValueError:
        return False
    return port in (None, 443) and lookup(parts.hostname or "") is not None


def source_kind_for(url: str) -> SourceKind:
    host = lookup(url)
    if host is None:
        return "third_party"
    if host.domain == "github.com" and "/advisories" not in urlsplit(url).path:
        return "user_content"
    return host.source_kind


def publisher_for(url: str) -> str:
    host = lookup(url)
    return host.publisher if host else host_of(url)


def search_domains_for(vendors: list[str], *, web_app: bool, linux: bool) -> list[str]:
    """Up to MAX_SEARCH_DOMAINS allowed domains for one CVE's discovery search: the affected vendors' own sites
    first, then distro trackers (Linux software), WAF vendors (web apps), then the general sources."""
    chosen: list[str] = []
    for vendor in vendors:
        chosen.extend(VENDOR_DOMAINS.get(vendor_key(vendor), ()))
    if linux:
        chosen.extend(DISTRO_SEARCH_DOMAINS)
    if web_app:
        chosen.extend(WEB_SEARCH_DOMAINS)
    chosen.extend(CORE_SEARCH_DOMAINS)
    return _searchable(chosen)


def ips_search_domains_for(device_vendors: list[str]) -> list[str]:
    """Allowed domains for an IPS/WAF signature search: the in-path devices' vendors first, then the core
    signature publishers."""
    chosen: list[str] = []
    for vendor in device_vendors:
        chosen.extend(IPS_VENDOR_DOMAINS.get(vendor_key(vendor), ()))
    chosen.extend(IPS_CORE_DOMAINS)
    return _searchable(chosen)


def _searchable(domains: list[str]) -> list[str]:
    out: list[str] = []
    for domain in domains:
        host = _BY_DOMAIN.get(domain)
        if host is None or not host.search:
            continue
        entry = domain + host.search_path
        if entry not in out:
            out.append(entry)
    return out[:MAX_SEARCH_DOMAINS]


def egress_table() -> list[tuple[str, str]]:
    """(domain, purpose) rows for the README egress table."""
    return [(host.domain, host.purpose) for host in HOSTS]
