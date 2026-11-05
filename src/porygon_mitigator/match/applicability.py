"""Does a mitigation apply to this machine? Is it already in place?

Rules, per mitigation layer:
- host: the machine's platform and installed products must fit; `config_state` can show it's already applied.
- edr: the required endpoint tool must be on the machine.
- waf / ips / network_device: a device of the right vendor and role must sit in front of the machine (or be the
  machine itself, for appliances).
Every decision records its reasons so the report can say *why*.
"""

from __future__ import annotations

from porygon_mitigator.match.affected import installed_items
from porygon_mitigator.match.cpe import product_slug, products_match
from porygon_mitigator.models.actions import vendor_key
from porygon_mitigator.models.assessment import AffectednessResult, MitigationAssessment
from porygon_mitigator.models.common import ApplicabilityStatus
from porygon_mitigator.models.machine import ConfigState, MachineProfile, NetworkDevice
from porygon_mitigator.models.mitigation import Mitigation

# Which device roles can carry a rule written for a given role.
_ROLE_CARRIERS: dict[str, set[str]] = {
    "ips": {"ips", "ngfw"},
    "ngfw": {"ngfw"},
    "waf": {"waf", "load_balancer", "proxy"},
    "load_balancer": {"load_balancer"},
    "proxy": {"proxy", "load_balancer"},
    "router": {"router", "ngfw"},
    "vpn_gateway": {"vpn_gateway", "ngfw"},
}


def _already_applied(mitigation: Mitigation, state: ConfigState | None) -> tuple[bool | None, str]:
    """(True, why) if config_state shows the change in place, (False, why) if it shows it isn't, (None, '') if
    unknown."""
    if state is None:
        return None, ""
    kind, target = mitigation.action.kind, mitigation.action.target
    key, _, value = target.partition("=")
    if kind == "set_sysctl" and key in state.sysctl:
        current = state.sysctl[key]
        return current == value, f"sysctl {key} is {current} (needs {value})"
    if kind == "set_registry_value" and key in state.registry:
        data = state.registry[key]
        return data == value, f"registry {key} is {data if data is not None else 'absent'} (needs {value})"
    if kind == "delete_registry_key" and target in state.registry:
        present = state.registry[target] is not None
        return (not present), f"registry key {target} is {'present' if present else 'absent'}"
    if kind == "disable_service" and target in state.services:
        current = state.services[target]
        done = current in ("disabled", "not_installed")
        note = " (stopped but not disabled; it can start again)" if current == "stopped" else ""
        return done, f"service {target} is {current}{note}"
    if kind == "disable_os_feature" and target in state.os_features:
        enabled = state.os_features[target]
        return (not enabled), f"OS feature {target} is {'enabled' if enabled else 'disabled'}"
    if kind == "disable_kernel_module":
        if target in state.kernel_modules_blacklisted:
            return True, f"kernel module {target} is blacklisted"
        if state.kernel_modules_loaded is not None:
            loaded = target in state.kernel_modules_loaded
            return False, f"kernel module {target} is {'loaded' if loaded else 'not loaded but not blacklisted'}"
    if kind == "set_config" and key in state.app_settings:
        current = state.app_settings[key]
        if not value:
            return None, f"{key} is {current}"
        return current == value, f"{key} is {current} (needs {value})"
    return None, ""


def _host_products_ok(mitigation: Mitigation, machine: MachineProfile) -> tuple[bool | None, str]:
    wanted = mitigation.applies_to.products
    if not wanted:
        return True, ""
    items = installed_items(machine)
    for want in wanted:
        vendor, _, product = want.partition(":")
        for item in items:
            if item.vendor and vendor and vendor_key(vendor) != item.vendor:
                continue
            if products_match(product or vendor, item.product):
                return True, f"{item.label} is installed"
    if machine.installed_software:
        return False, f"none of {', '.join(wanted)} is in the machine's installed software"
    return None, "the profile lists no installed software, so the product can't be checked"


def _tool_present(mitigation: Mitigation, machine: MachineProfile) -> tuple[bool, str]:
    wanted = mitigation.applies_to.security_tools
    if not wanted:
        return True, ""
    for want in wanted:
        vendor, _, hint = want.partition(":")
        for tool in machine.security_tools:
            if vendor_key(tool.vendor) != vendor_key(vendor):
                continue
            name = product_slug(tool.product or "")
            if not hint or product_slug(hint) in name:
                return True, f"{tool.vendor} {tool.product or ''} is on the machine".replace("  ", " ")
    needed = ", ".join(wanted)
    if machine.security_tools:
        have = ", ".join(f"{tool.vendor} {tool.product or ''}".strip() for tool in machine.security_tools)
        return False, f"needs {needed}; the machine runs {have}"
    return False, f"needs {needed}; the profile lists no endpoint security tools"


def _candidate_devices(machine: MachineProfile) -> list[NetworkDevice]:
    devices = list(machine.network_path)
    if machine.os.platform == "network_os" and machine.vendor:
        # An appliance can enforce its own vendor's signatures and settings on itself.
        role = "ngfw" if "firewall" in " ".join(machine.roles).lower() else "ips"
        devices.append(NetworkDevice(role=role, vendor=machine.vendor, product=machine.os.name))  # type: ignore[arg-type]
    return devices


def _device_match(mitigation: Mitigation, machine: MachineProfile) -> tuple[bool, str]:
    roles = mitigation.applies_to.device_roles
    vendors = {vendor_key(item) for item in mitigation.applies_to.device_vendors}
    products = [product_slug(item) for item in mitigation.applies_to.device_products]
    carriers: set[str] = set()
    for role in roles or []:
        carriers |= _ROLE_CARRIERS.get(role, {role})
    for device in _candidate_devices(machine):
        if carriers and device.role not in carriers:
            continue
        if vendors and vendor_key(device.vendor) not in vendors:
            continue
        if products and not any(hint in product_slug(device.product or "") for hint in products):
            continue
        name = f"{device.vendor} {device.product or device.role}".strip()
        return True, f"{name} ({device.role}) is in the traffic path"
    need_role = "/".join(roles) if roles else mitigation.layer
    need_vendor = " or ".join(sorted(vendors)) if vendors else "any vendor"
    if machine.network_path:
        have = ", ".join(f"{d.vendor} {d.role}" for d in machine.network_path)
        return False, f"needs a {need_role} from {need_vendor} in front of the machine; the path has {have}"
    return False, f"needs a {need_role} from {need_vendor} in front of the machine; the profile lists none"


def assess_mitigation(
    mitigation: Mitigation, machine: MachineProfile, affected: AffectednessResult
) -> MitigationAssessment:
    reasons: list[str] = []
    status: ApplicabilityStatus

    if mitigation.status == "withdrawn":
        why = mitigation.withdrawn_reason or "the source no longer recommends it"
        return MitigationAssessment(mitigation=mitigation, status="not_applicable", reasons=[f"withdrawn: {why}"])

    platforms = mitigation.applies_to.platforms
    if mitigation.layer in ("host", "edr") and platforms and machine.os.platform not in platforms:
        reasons.append(f"applies to {'/'.join(platforms)}; this machine runs {machine.os.platform}")
        return MitigationAssessment(mitigation=mitigation, status="not_applicable", reasons=reasons)

    if mitigation.layer in ("waf", "ips", "network_device"):
        ok, why = _device_match(mitigation, machine)
        reasons.append(why)
        status = "applicable" if ok else "needs_device"
    elif mitigation.layer == "edr":
        ok, why = _tool_present(mitigation, machine)
        reasons.append(why)
        status = "applicable" if ok else "needs_device"
    else:
        product_ok, why = _host_products_ok(mitigation, machine)
        if why:
            reasons.append(why)
        if product_ok is False:
            return MitigationAssessment(mitigation=mitigation, status="not_applicable", reasons=reasons)
        tool_ok, tool_why = _tool_present(mitigation, machine)
        if not tool_ok:
            reasons.append(tool_why)
            return MitigationAssessment(mitigation=mitigation, status="needs_device", reasons=reasons)
        status = "applicable" if product_ok else "unknown"
        if platforms:
            reasons.insert(0, f"{machine.os.platform} host")

    if status == "applicable":
        applied, why = _already_applied(mitigation, machine.config_state)
        if why:
            reasons.append(why)
        if applied:
            status = "already_applied"

    if affected.status == "not_affected":
        reasons.append("the machine does not appear to be affected, so this is optional hardening")
    for condition in mitigation.applies_to.conditions:
        reasons.append(f"condition: {condition}")
    return MitigationAssessment(mitigation=mitigation, status=status, reasons=reasons)
