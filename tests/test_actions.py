import pytest

from porygon_mitigator.models.actions import normalize_action, registry_path, vendor_key


@pytest.mark.parametrize(
    ("kind", "target", "expected"),
    [
        ("delete_registry_key", "HKEY_CLASSES_ROOT\\ms-msdt", "hkcr\\ms-msdt"),
        (
            "set_registry_value",
            "HKLM\\SYSTEM\\CurrentControlSet\\Services\\DNS\\Parameters\\TcpReceivePacketSize=0xFF00",
            "hklm\\system\\currentcontrolset\\services\\dns\\parameters\\tcpreceivepacketsize=65280",
        ),
        ("set_sysctl", "kernel/unprivileged_userns_clone = 0", "kernel.unprivileged_userns_clone=0"),
        ("disable_service", "Spooler.service", "spooler"),
        ("disable_kernel_module", "nf-tables.ko", "nf_tables"),
        ("set_config", "OpenSSH:LoginGraceTime=0", "openssh:logingracetime=0"),
        ("apply_ips_signature", "Palo Alto Networks:95187", "paloaltonetworks:95187"),
        ("apply_waf_rule", "Cloudflare:100514", "cloudflare:100514"),
        ("apply_ips_signature", "Snort:3:62541", "snort:62541"),
        ("restrict_network_access", "port:445/TCP", "port:445/tcp"),
        ("restrict_file_permission", "/usr/bin/pkexec", "/usr/bin/pkexec"),
        ("restrict_file_permission", "%WINDIR%\\System32\\config\\*.*", "%windir%\\system32\\config"),
        ("restrict_file_permission", "C:\\Program Files\\Acme\\agent.dll", "c:\\program files\\acme\\agent.dll"),
        ("set_config", "httpd:SSLCipherSuite=HIGH:!3DES:!aNULL", "httpd:sslciphersuite=high:!3des:!anull"),
        ("set_config", "openssh:Ciphers=-chacha20-poly1305@openssh.com",
         "openssh:ciphers=-chacha20-poly1305@openssh.com"),
        ("remove_component", "log4j:JndiLookup.class", "log4j:jndilookup.class"),
    ],
)
def test_normalize_action(kind: str, target: str, expected: str) -> None:
    assert normalize_action(kind, target) == (kind, expected)


def test_out_of_shape_targets_become_other() -> None:
    assert normalize_action("set_sysctl", "no equals sign") == ("other", "")
    assert normalize_action("made_up_kind", "x") == ("other", "")
    assert normalize_action("set_registry_value", "not a registry path=1") == ("other", "")


def test_known_products_anchor_spelling() -> None:
    assert normalize_action("set_config", "OpenSSH:logingracetime=0", ["openbsd:openssh"]) == (
        "set_config", "openssh:logingracetime=0")


def test_vendor_key_aliases() -> None:
    assert vendor_key("Palo Alto Networks") == "paloaltonetworks"
    assert vendor_key("F5, Inc.") == "f5"
    assert vendor_key("NetScaler") == "citrix"
    assert registry_path("HKEY_LOCAL_MACHINE\\\\Software\\X") == "hklm\\software\\x"
