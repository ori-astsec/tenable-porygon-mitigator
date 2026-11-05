"""The machine profile: everything porygon knows about one host or appliance.

Field names mirror Tenable's asset export where one exists (`operating_systems`, `installed_software` as CPE
strings, `network.open_ports`, `is_public`), so a Tenable One adapter is a mapping, not a translation.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from porygon_mitigator.models.common import DeviceRole, Platform, SecurityToolCategory

_CVE_PATTERN = r"^CVE-\d{4}-\d{4,}$"


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class OSInfo(_Strict):
    platform: Platform
    name: str | None = Field(default=None, description="Full OS name, e.g. 'Ubuntu 22.04.4 LTS' or 'PAN-OS 10.2.8'.")
    version: str | None = Field(default=None, description="OS version or build, e.g. '22.04', '10.0.17763'.")
    distribution: str | None = Field(
        default=None, description="Lowercase distro or OS key: ubuntu, debian, rhel, windows, panos, netscaler..."
    )
    kernel: str | None = None


class Software(_Strict):
    """One installed product. Give a CPE (2.2 `cpe:/a:...` or 2.3 `cpe:2.3:a:...`), or vendor/product/version."""

    cpe: str | None = None
    vendor: str | None = None
    product: str | None = None
    version: str | None = None
    package: str | None = Field(default=None, description="Distro package name and version string, if known.")

    @model_validator(mode="after")
    def _needs_identity(self) -> Software:
        if not self.cpe and not self.product:
            raise ValueError("installed software needs a cpe or a product")
        return self


class OpenPort(_Strict):
    port: int = Field(ge=0, le=65535)
    protocol: Literal["tcp", "udp"] = "tcp"
    service_names: list[str] = Field(default_factory=list)
    internet_exposed: bool | None = None


class NetworkDevice(_Strict):
    """A security device that traffic to the machine crosses (firewall, IPS, WAF, load balancer...)."""

    role: DeviceRole
    vendor: str
    product: str | None = None
    version: str | None = None
    capabilities: list[str] = Field(
        default_factory=list,
        description="Enabled subscriptions/features, e.g. 'threat_prevention', 'ips', 'waf_managed_rules'.",
    )


class SecurityTool(_Strict):
    category: SecurityToolCategory
    vendor: str
    product: str | None = None
    version: str | None = None


class Finding(_Strict):
    """A scanner finding that reports a CVE on this machine (e.g. a Tenable plugin hit)."""

    cve: str = Field(pattern=_CVE_PATTERN)
    plugin_id: int | None = None
    port: int | None = None
    protocol: str | None = None
    source: str | None = Field(default=None, description="Scanner that reported it, e.g. 'tenable'.")
    state: Literal["open", "reopened", "fixed"] = "open"


class ConfigState(_Strict):
    """Observed configuration, used to tell whether a mitigation is already in place. Absent keys mean unknown."""

    sysctl: dict[str, str] = Field(default_factory=dict, description="sysctl key -> current value.")
    registry: dict[str, str | None] = Field(
        default_factory=dict,
        description="Registry path (hklm\\..., hkcr\\...) -> value data; null means the key/value is absent.",
    )
    services: dict[str, Literal["running", "stopped", "disabled", "not_installed"]] = Field(default_factory=dict)
    kernel_modules_loaded: list[str] | None = Field(default=None, description="null means not collected.")
    kernel_modules_blacklisted: list[str] = Field(default_factory=list)
    os_features: dict[str, bool] = Field(default_factory=dict, description="Windows optional feature -> enabled.")
    app_settings: dict[str, str] = Field(
        default_factory=dict,
        description="'<product>:<setting>' -> current value, e.g. 'openssh:logingracetime': '120'.",
    )

    @field_validator("sysctl", "app_settings")
    @classmethod
    def _lower_keys(cls, value: dict[str, str]) -> dict[str, str]:
        return {key.strip().lower(): str(val).strip() for key, val in value.items()}

    @field_validator("registry")
    @classmethod
    def _lower_registry(cls, value: dict[str, str | None]) -> dict[str, str | None]:
        return {key.strip().lower().replace("/", "\\"): val for key, val in value.items()}


class MachineProfile(_Strict):
    schema_version: Literal[1] = 1
    name: str = Field(description="Hostname or a label for the machine.")
    os: OSInfo
    vendor: str | None = Field(default=None, description="Device vendor for appliances, e.g. 'Palo Alto Networks'.")
    roles: list[str] = Field(default_factory=list, description="Free-form roles: web_server, print_server, dc...")
    installed_software: list[Software] = Field(default_factory=list)
    open_ports: list[OpenPort] = Field(default_factory=list)
    internet_exposed: bool | None = None
    network_path: list[NetworkDevice] = Field(default_factory=list)
    security_tools: list[SecurityTool] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    config_state: ConfigState | None = None
    source: str = Field(default="manual", description="Where the profile came from: manual, tenable_one...")
