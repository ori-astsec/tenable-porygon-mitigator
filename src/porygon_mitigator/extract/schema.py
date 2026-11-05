"""The structured output Claude fills in for one advisory.

Kept flat and closed (Literal enums, no numeric/length constraints): the API enforces the shape, and our own code
does everything that needs judgement about trust - quote verification, command checks, normalisation, matching.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from porygon_mitigator.models.actions import ActionKind

RiskWord = Literal["none", "read_only", "changes_system", "disruptive"]
RISK_LEVEL: dict[str, int] = {"none": 0, "read_only": 1, "changes_system": 2, "disruptive": 3}


class LlmStep(BaseModel):
    text: str = Field(description="What to do in this step, in plain words.")
    command: str | None = Field(
        description="The exact command or configuration line for this step, copied character for character from "
        "the advisory. null when the advisory does not show it verbatim."
    )
    risk: RiskWord = Field(
        description="none: nothing to run. read_only: only displays information. changes_system: changes "
        "configuration, files or registry. disruptive: stops, restarts or removes a service, process or component, "
        "or can break functionality users rely on."
    )


class LlmMitigation(BaseModel):
    title: str = Field(description="3-8 words starting with a verb, naming the exact setting, rule or component.")
    type: Literal["CONFIGURATION", "REGISTRY_KEY", "DISABLE", "NETWORK_ACL", "WAF", "IPS", "EDR", "OTHER"]
    layer: Literal["host", "network_device", "waf", "ips", "edr"]
    summary: str = Field(description="1-2 sentences: what the change does and why it blocks or limits the exploit.")
    steps: list[LlmStep]
    action_kind: ActionKind
    action_target: str = Field(description="Target in the format the action kind requires (see instructions).")
    rule_ids: list[str] = Field(description="Signature or rule IDs the advisory names for this mitigation.")
    platforms: list[Literal["windows", "linux", "macos", "network_os", "unix"]] = Field(
        description="Operating systems the host steps apply to. Empty for network-device, WAF and IPS rules."
    )
    device_role: Literal["none", "ngfw", "ips", "waf", "load_balancer", "proxy", "router", "vpn_gateway"] = Field(
        description="For network/WAF/IPS mitigations: the kind of device that enforces it. 'none' for host changes."
    )
    device_vendor: str | None = Field(description="Vendor of the enforcing device, e.g. 'Palo Alto Networks'.")
    security_tool: str | None = Field(
        description="For EDR mitigations: the endpoint product required, e.g. 'Microsoft Defender for Endpoint'."
    )
    conditions: list[str] = Field(
        description="Prerequisites or limits the advisory states, e.g. 'only if HTTP/2 is enabled'."
    )
    side_effects: str | None = Field(description="Impact of applying it, as the advisory states. null if not stated.")
    rollback: str | None = Field(description="How to undo it, as the advisory states. null if not stated.")
    status: Literal["active", "withdrawn"] = Field(
        description="withdrawn when the advisory says this measure is ineffective, superseded or not a workaround."
    )
    withdrawn_reason: str | None
    evidence_quotes: list[str] = Field(
        description="1-3 short passages copied verbatim from the advisory that state this mitigation."
    )


class LlmRemediation(BaseModel):
    summary: str = Field(description="The fix: which update or version resolves the CVE.")
    fixed_versions: list[str]
    evidence_quote: str | None = Field(description="Verbatim passage naming the fix, or null.")


class LlmExtraction(BaseModel):
    discusses_cve: bool = Field(description="Whether the advisory is about the CVE in question.")
    mitigations: list[LlmMitigation]
    remediation: LlmRemediation | None
    no_workaround_quote: str | None = Field(
        description="If the advisory says no workaround or mitigation exists, that sentence copied verbatim."
    )
