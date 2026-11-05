"""The simulated environment the flow runs on, and what each step produces.

Nothing here touches a real device: applying a change edits this model. A firewall rule mirrors how firewall rule bases
are usually stored: ordered, with zones, addresses, `443/tcp`-style services and an action.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

ZoneKind = Literal["internet", "partner", "vpn", "guest", "dmz", "corp", "server", "management", "ot", "unknown"]
RuleAction = Literal["allow", "deny", "drop"]
AccessVector = Literal["network", "adjacent", "local", "physical", "unknown"]
CveTag = Literal["reachable", "host_reachable", "not_seen_running", "not_reachable", "local_only", "unknown"]
TagBasis = Literal[
    "scanner_tested",  # the host is reachable, and the scanner reached this service over the network
    "software_running",  # the host is reachable, and the software named for the CVE is running on it
    "host_open",  # the host is reachable, but nothing ties this CVE to anything running on it: weaker evidence
    "not_seen_running",  # the host is reachable, and the software named for the CVE isn't among what's running
    "no_path",  # the rules stop every path from every vantage
    "not_connected",  # the map has no path to this zone, or more hops than the search covers
    "no_address",  # rules match on addresses and this host has none of that IP version
    "local_vector",  # needs local access
    "not_placed",  # the host isn't placed on the map
    "unknown_vector",  # nothing says how this flaw is reached
    "model_converted",  # no path, but a model converted the rules, so a missing path proves nothing
    "client_side",  # exploited through a client opening something, not by reaching the machine
]
Protection = Literal["ips", "host_control"]
MitigationKind = Literal["ips_threat_ids", "acl_block", "disable_service", "host_setting"]
CandidateStatus = Literal["proceed", "hold"]

ANY = "any"
ROUTER_TYPE = "Router"
INTERNET_ZONE_KINDS = ("internet", "partner", "vpn", "guest")


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Zone(_Strict):
    id: str
    name: str = ""
    kind: ZoneKind = "unknown"
    cidrs: list[str] = Field(default_factory=list)
    attacker_vantage: bool | None = Field(default=None, description="Defaults to true for internet-like zones.")

    @property
    def is_vantage(self) -> bool:
        return self.kind in INTERNET_ZONE_KINDS if self.attacker_vantage is None else self.attacker_vantage


class FirewallRule(_Strict):
    name: str
    from_zone: list[str] = Field(default_factory=lambda: [ANY])
    to_zone: list[str] = Field(default_factory=lambda: [ANY])
    destination: list[str] = Field(default_factory=lambda: [ANY], description="CIDRs, IPs, host ids or `any`.")
    action: RuleAction = "allow"
    vulnerability_profile: str | None = Field(default=None, description="The IPS profile this rule applies.")


class Route(_Strict):
    destination: str = Field(description="A CIDR; 0.0.0.0/0 is the default route.")
    zone: str | None = Field(default=None, description="The zone this route leaves through.")
    next_hop_device: str | None = Field(default=None, description="The device this route hands traffic to.")


class Device(_Strict):
    id: str
    name: str = ""
    fw_type: str = Field(default="PaloAltoNGFW", description="`PaloAltoNGFW`, `Fortigate`, `CiscoASA`...")
    version: str | None = None
    zones: list[str] = Field(default_factory=list, description="Zones this device connects.")
    routes: list[Route] = Field(default_factory=list)
    threat_prevention: bool = Field(default=True, description="Whether it can enforce IPS signatures.")
    rules: list[FirewallRule] = Field(default_factory=list, description="In evaluation order; no match means deny.")
    vulnerability_profiles: dict[str, list[str]] = Field(
        default_factory=dict, description="Profile name -> threat IDs it blocks."
    )


class Finding(_Strict):
    cve: str
    severity: str = "unknown"
    access_vector: AccessVector = "unknown"
    kev: bool = False
    ransomware: bool = False
    title: str = ""
    cvss_vector: str = ""
    family: str = ""
    remote_check: bool = Field(
        default=False, description="The scanner's plugin tested this over the network, not from inside the machine."
    )
    product: str = ""
    solution: str = Field(default="", description="The scanner's own fix text. Third-party data, not instructions.")
    has_patch: bool = False
    vulnerability_class: Literal["server", "client", "kernel", "local", ""] = Field(
        default="", description="Where the flaw is exploited, when the data says. Better than guessing from the title."
    )

    @field_validator("severity")
    @classmethod
    def _lowercase_severity(cls, value: str) -> str:
        return value.lower()


class Host(_Strict):
    id: str
    asset_id: str | None = Field(default=None, description="The scanner's asset id, when it isn't `id`.")
    name: str = ""
    zone: str | None = Field(default=None, description="None means it isn't placed on the map.")
    placed_by: Literal["route", "zone_cidr", "model"] | None = Field(
        default=None, description="Set when a run placed it: how it got `zone`. None for a zone the file declares."
    )
    ips: list[str] = Field(default_factory=list)
    gateway: str | None = None
    os: str | None = None
    system_types: list[str] = Field(default_factory=list)
    local_checks: bool = Field(default=True, description="False: no local checks ran, so findings may be missing.")
    processes: list[str] = Field(default_factory=list, description="Programs the scan saw running on this machine.")
    services: dict[str, str] = Field(default_factory=dict, description="Service name -> running, stopped or disabled.")
    host_controls: dict[str, list[str]] = Field(
        default_factory=dict, description="Applied setting -> the CVEs it mitigates."
    )
    findings: list[Finding] = Field(default_factory=list)


class AllowedFlow(_Strict):
    name: str
    source_zone: str
    host: str
    service: str | None = Field(default=None, description="The service this traffic needs running, if one matters.")


class ObservedTraffic(_Strict):
    """Sessions a firewall's traffic log shows. Here they're simulated: no real packets are read."""

    name: str
    source_zone: str
    host: str
    sessions: int = 1
    threat_ids: list[str] = Field(default_factory=list, description="Signatures this traffic trips, false alarms too.")
    only_after_change: bool = Field(
        default=False, description="First seen after a change, so watching beforehand misses it: a nightly job, say."
    )


class VulnerabilityProfile(_Strict):
    """What normalizing a vulnerability's text gives. Only what the text supports: empty is the honest answer."""

    cve: str
    vulnerability_class: Literal["server", "client", "kernel", "local", ""] = Field(
        default="", description="For a person to read. A model's reading never changes a verdict."
    )
    class_evidence: str = Field(default="", description="The words in the finding that say so, quoted exactly.")
    processes: list[str] = Field(default_factory=list, description="Process names that run the vulnerable code.")
    libraries: list[str] = Field(default_factory=list, description="Libraries a process has to load to be affected.")
    protocols: list[str] = Field(default_factory=list)
    affected_versions: list[str] = Field(default_factory=list)
    exploitation_requirements: list[str] = Field(default_factory=list)
    constraints: str = Field(default="", description="Anything else the text says limits exploitation.")


class Environment(_Strict):
    schema_version: Literal[1] = 1
    label: str = Field(default="synthetic", description="`synthetic`, or `tenant` for data from a real tenant.")
    zones: list[Zone] = Field(default_factory=list)
    devices: list[Device] = Field(default_factory=list)
    hosts: list[Host] = Field(default_factory=list)
    allowed_flows: list[AllowedFlow] = Field(default_factory=list)
    observed_traffic: list[ObservedTraffic] = Field(default_factory=list)
    model_converted: list[str] = Field(default_factory=list, description="Sources a model converted to this format.")
    vulnerabilities: dict[str, VulnerabilityProfile] = Field(
        default_factory=dict, description="Normalized details per CVE, from step 1.5."
    )


class FlowMitigation(_Strict):
    """One mitigation handed to the flow: from porygon's research, a vendor catalogue or a person."""

    id: str
    title: str
    kind: MitigationKind
    cve_ids: list[str]
    fw_type: str | None = Field(default=None, description="For IPS and ACL changes: the firewall type it needs.")
    threat_ids: list[str] = Field(default_factory=list)
    service: str | None = Field(default=None, description="For disable_service: the service to stop.")
    setting: str | None = Field(default=None, description="For host_setting: the setting that gets applied.")
    os: str | None = Field(default=None, description="Only hosts whose OS name contains this, like `Windows`.")
    risk: int = Field(
        default=2, ge=0, le=3, description="0 no change, 1 read-only, 2 changes the system, 3 disruptive."
    )
    side_effects: str = ""
    rollback: str = ""
    source_url: str = ""
    note: str = ""

    @model_validator(mode="after")
    def _has_what_its_kind_needs(self) -> FlowMitigation:
        needed = {
            "ips_threat_ids": self.threat_ids,
            "disable_service": self.service,
            "host_setting": self.setting,
        }
        if self.kind in needed and not needed[self.kind]:
            raise ValueError(f"a {self.kind} mitigation needs its {self.kind.split('_')[-1]} details")
        return self


class PathHop(_Strict):
    device: str
    from_zone: str
    to_zone: str
    rule: str | None = Field(default=None, description="The rule that decided; None means the default deny.")
    action: RuleAction = "deny"
    vulnerability_profile: str | None = None


class HostReach(_Strict):
    vantage: str
    host: str
    reachable: bool
    settled: bool = Field(default=True, description="False: not reachable here only means the map couldn't say.")
    hops: list[PathHop] = Field(default_factory=list, description="The open path, or the path that was closest.")
    open_paths: list[list[PathHop]] = Field(default_factory=list, description="Every path that reaches this host.")


class TaggedFinding(_Strict):
    cve: str
    host: str
    tag: CveTag
    basis: TagBasis
    severity: str
    kev: bool
    access_vector: AccessVector
    vantages: list[str] = Field(default_factory=list)
    protected_by: list[Protection] = Field(default_factory=list)

    @property
    def exposed(self) -> bool:
        return self.tag in ("reachable", "host_reachable", "not_seen_running") and not self.protected_by


class Funnel(_Strict):
    """Every count is distinct (CVE, host) pairs."""

    findings: int
    high_critical: int = Field(description="Rated high or critical.")
    remotely_exploitable: int = Field(description="Of those, not client-side and not needing local access.")
    exposed: int = Field(description="Of those, an open path from an attacker zone reaches the machine.")
    reachable: int = Field(description="Of those, the scanner tested the software or it's seen running.")
    cant_judge: int = Field(description="Remotely exploitable, but the data can't say whether a path reaches it.")
    known_exposed: int = Field(description="Remotely exploitable, known exploited, with an open path to it.")
    remote: int
    remote_critical: int
    remote_critical_kev: int
    kev_reachable: int
    kev_host_reachable: int
    kev_not_seen_running: int
    kev_not_reachable: int
    kev_client_side: int
    kev_local_only: int
    kev_unknown: int
    kev_protected: int
    kev_exposed: int


class Change(_Strict):
    """One simulated change. `preview` shows what it would look like on the real product; nothing runs it."""

    kind: Literal["block_threats", "add_deny_rule", "stop_service", "set_host_control"]
    target: str = Field(description="The device or host id.")
    mitigation_id: str
    threat_ids: list[str] = Field(default_factory=list)
    profile: str | None = None
    rules: list[str] = Field(default_factory=list, description="Security rules that need the profile attached.")
    deny_rule: FirewallRule | None = None
    service: str | None = None
    setting: str | None = None
    cve_ids: list[str] = Field(default_factory=list)
    preview: list[str] = Field(default_factory=list)


class Candidate(_Strict):
    mitigation_id: str
    title: str
    kind: MitigationKind
    status: CandidateStatus
    hold_reasons: list[str] = Field(default_factory=list)
    risk: int
    changes: list[Change] = Field(default_factory=list)
    protects: list[str] = Field(default_factory=list, description="`CVE on host` pairs it stops being exposed.")
    protects_kev: int = 0
    breaks_flows: list[str] = Field(default_factory=list)
    drops_traffic: list[str] = Field(
        default_factory=list, description="Observed traffic it would newly drop that isn't an attack."
    )
    side_effects: str = ""
    rollback: str = ""
    source_url: str = ""


class ChangeImpact(_Strict):
    """What approving one mitigation means, in the terms a person weighs it: what it touches and what it could hurt."""

    mitigation_id: str
    title: str
    kind: MitigationKind
    risk: int
    devices: list[str] = Field(default_factory=list)
    hosts_changed: list[str] = Field(default_factory=list, description="Machines the change is made on.")
    rules: list[str] = Field(default_factory=list, description="`device: rule` entries it adds or edits.")
    hosts_protected: list[str] = Field(default_factory=list)
    protects: int = 0
    protects_kev: int = 0
    traffic_crossing: list[str] = Field(
        default_factory=list, description="Allowed traffic passing through what changes, so what a mistake would hit."
    )
    breaks: list[str] = Field(default_factory=list)
    side_effects: str = ""
    rollback: str = ""
    source_url: str = ""


class ImageTest(_Strict):
    """Where to try the change before production: a clean image of what it runs on."""

    runs_on: str
    targets: list[str]
    image: str


class Plan(_Strict):
    plan_hash: str
    environment_hash: str
    mitigations_hash: str
    label: str
    mitigation_ids: list[str]
    changes: list[Change]
    expected_protects: list[str]
    expected_breaks: list[str]
    hold_reasons: list[str] = Field(default_factory=list, description="Holds the planner chose to accept.")
    impact: list[ChangeImpact] = Field(default_factory=list)
    test_first: list[ImageTest] = Field(default_factory=list)
    before: Funnel
    expected_after: Funnel


class RecommendedMitigation(_Strict):
    mitigation_id: str
    title: str
    kind: MitigationKind
    why: str
    adds: int = Field(description="Exposed pairs this one newly stops, on top of those picked before it.")
    adds_kev: int


class HeldOption(_Strict):
    """A mitigation that wasn't picked but would stop pairs that stay exposed. A person may still want it."""

    mitigation_id: str
    title: str
    would_stop: list[str]
    why_held: str


class Recommendation(_Strict):
    """What to mitigate and how, worked out before asking anyone. A person still decides."""

    selected: list[RecommendedMitigation] = Field(default_factory=list)
    not_selected: dict[str, str] = Field(default_factory=dict, description="Mitigation id -> why it wasn't picked.")
    kev_exposed_now: int
    kev_exposed_after: int
    left_exposed: list[str] = Field(
        default_factory=list, description="Pairs on the known-exploited step still exposed after."
    )
    no_option: list[str] = Field(default_factory=list, description="Of those, the ones no mitigation here would stop.")
    held_options: list[HeldOption] = Field(default_factory=list)
    reachable_after: int = Field(default=0, description="High and critical Reachable pairs this set leaves open.")
    other_exposed_after: int = Field(default=0, description="Exposed pairs that aren't on the known-exploited step.")
    breaks: list[str] = Field(default_factory=list)


class FlowCheck(_Strict):
    name: str
    passed: bool
    detail: str


class Verification(_Strict):
    plan_hash: str
    mitigation_ids: list[str] = Field(default_factory=list)
    passed: bool
    before: Funnel
    after: Funnel
    checks: list[FlowCheck]
    attacks_stopped: int = Field(default=0, description="Sessions tripping a signature that the change now drops.")
    needed_dropped: list[str] = Field(default_factory=list, description="Traffic that must keep working, now dropped.")
    unknown_dropped: list[str] = Field(default_factory=list, description="Traffic nobody declared, now dropped.")
    rollback_advised: bool = False
    rollback_reason: str = ""
    planned_breaks: list[str] = Field(default_factory=list, description="Allowed traffic the plan said it would stop.")
