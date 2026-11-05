"""Deterministic 'how to verify' and 'rollback' notes derived from the normalised action.

These are marked `derived` in the record: they follow from the action itself, not from the advisory. They exist so
every disable-type mitigation ships with a way to check it and a way back.
"""

from __future__ import annotations

from porygon_mitigator.models.mitigation import Action, Note


def _registry_cli(path: str) -> str:
    hive, _, rest = path.partition("\\")
    long = {"hklm": "HKLM", "hkcu": "HKCU", "hkcr": "HKCR", "hku": "HKU", "hkcc": "HKCC"}.get(hive, hive.upper())
    return f"{long}\\{rest}"


def derive_verify(action: Action) -> Note | None:
    kind, target = action.kind, action.target
    key, _, value = target.partition("=")
    text: str | None = None
    if kind == "set_sysctl":
        text = f"`sysctl {key}` prints {value}, and the setting is persisted in /etc/sysctl.d/."
    elif kind == "set_registry_value":
        path, _, name = key.rpartition("\\")
        text = f"`reg query \"{_registry_cli(path)}\" /v {name}` shows {value}."
    elif kind == "delete_registry_key":
        text = f"`reg query \"{_registry_cli(target)}\"` reports that the key can't be found."
    elif kind == "disable_service":
        text = (f"Windows: `Get-Service {target}` shows Stopped with StartType Disabled. "
                f"Linux: `systemctl is-enabled {target}` prints disabled or masked.")
    elif kind == "disable_kernel_module":
        text = (f"`lsmod | grep {target}` prints nothing, and a blacklist/install entry for {target} exists in "
                "/etc/modprobe.d/.")
    elif kind == "disable_os_feature":
        text = f"`Get-WindowsOptionalFeature -Online -FeatureName {target}` shows State Disabled."
    elif kind == "restrict_file_permission":
        text = f"`ls -l {target}` shows the reduced permissions."
    elif kind == "restrict_network_access" and target.startswith("port:"):
        port, _, proto = target.removeprefix("port:").partition("/")
        text = f"A connection attempt to {proto.upper()} port {port} from an untrusted network fails."
    elif kind in ("apply_ips_signature", "apply_waf_rule"):
        text = ("The rule appears in the device's active policy with a blocking action, and test traffic is logged "
                "as blocked.")
    elif kind == "set_config" and value:
        product, _, setting = key.partition(":")
        text = f"The effective {product} configuration shows {setting} = {value} after a reload."
    return Note(text=text, origin="derived") if text else None


def derive_rollback(action: Action) -> Note | None:
    kind, target = action.kind, action.target
    key, _, _value = target.partition("=")
    text: str | None = None
    if kind == "set_sysctl":
        text = f"Set {key} back to its previous value and remove the override from /etc/sysctl.d/."
    elif kind == "set_registry_value":
        text = "Restore the previous registry value (export it before changing it)."
    elif kind == "delete_registry_key":
        text = "Re-import the registry key from the backup taken before deleting it."
    elif kind == "disable_service":
        text = f"Set {target} back to its previous start type and start it."
    elif kind == "disable_kernel_module":
        text = f"Remove the {target} blacklist entry from /etc/modprobe.d/ and load the module again."
    elif kind == "disable_os_feature":
        text = f"Enable the {target} feature again."
    elif kind in ("set_config", "disable_app_feature"):
        text = "Restore the previous configuration value and reload the service."
    elif kind in ("apply_ips_signature", "apply_waf_rule"):
        text = "Set the rule back to its previous action (alert or disabled)."
    elif kind == "restrict_network_access":
        text = "Remove the firewall rule or ACL entry."
    return Note(text=text, origin="derived") if text else None
