from porygon_mitigator.match.affected import assess_affected
from porygon_mitigator.match.applicability import assess_mitigation
from porygon_mitigator.match.rank import decide_verdict, rank
from porygon_mitigator.models import Action, AffectednessResult, AffectedRange, AppliesTo, CveFacts, Finding

from .conftest import load_machine, make_mitigation

AFFECTED = AffectednessResult(status="affected")


def test_finding_beats_inventory() -> None:
    machine = load_machine("win2019-print-server.json")
    facts = CveFacts(cve_id="CVE-2021-34527")
    result = assess_affected(facts, machine)
    assert result.status == "affected" and "tenable" in result.reasons[0]


def test_version_range_on_appliance_os() -> None:
    machine = load_machine("pan-os-firewall.json")
    facts = CveFacts(cve_id="CVE-2024-3400", affected=[
        AffectedRange(vendor="Palo Alto Networks", product="PAN-OS", version_start_including="10.2.0",
                      version_end_excluding="10.2.9-h1")])
    assert assess_affected(facts, machine).status == "affected"


def test_distro_package_is_only_likely() -> None:
    machine = load_machine("ubuntu-ssh-bastion.json")
    facts = CveFacts(cve_id="CVE-2024-6387", affected=[
        AffectedRange(vendor="openbsd", product="openssh", version_start_including="8.5",
                      version_end_excluding="9.8")])
    result = assess_affected(facts, machine)
    assert result.status == "likely"
    assert "backport" in result.reasons[0]


def test_outside_range_is_not_affected() -> None:
    machine = load_machine("java-app-server.json")
    facts = CveFacts(cve_id="CVE-2099-0002", affected=[
        AffectedRange(vendor="apache", product="log4j", version_end_excluding="2.0")])
    assert assess_affected(facts, machine).status == "not_affected"


def test_unknown_when_no_product_matches() -> None:
    machine = load_machine("java-app-server.json")
    facts = CveFacts(cve_id="CVE-2099-0003", affected=[AffectedRange(vendor="acme", product="widget")])
    assert assess_affected(facts, machine).status == "unknown"


def test_platform_mismatch_is_not_applicable() -> None:
    machine = load_machine("ubuntu-ssh-bastion.json")
    result = assess_mitigation(make_mitigation(), machine, AFFECTED)
    assert result.status == "not_applicable" and "windows" in result.reasons[0]


def test_service_disable_already_applied() -> None:
    machine = load_machine("win2019-print-server.json")
    assert assess_mitigation(make_mitigation(), machine, AFFECTED).status == "applicable"
    assert machine.config_state is not None
    machine.config_state.services["spooler"] = "disabled"
    assert assess_mitigation(make_mitigation(), machine, AFFECTED).status == "already_applied"


def test_sysctl_and_app_setting_checks() -> None:
    machine = load_machine("ubuntu-ssh-bastion.json")
    sysctl = make_mitigation(type="CONFIGURATION", title="Block unprivileged user namespaces",
                             action=Action(kind="set_sysctl", target="kernel.unprivileged_userns_clone=0"),
                             applies_to=AppliesTo(platforms=["linux"]))
    result = assess_mitigation(sysctl, machine, AFFECTED)
    assert result.status == "applicable" and "is 1 (needs 0)" in " ".join(result.reasons)
    sshd = make_mitigation(type="CONFIGURATION", title="Set LoginGraceTime 0",
                           action=Action(kind="set_config", target="openssh:logingracetime=0"),
                           applies_to=AppliesTo(platforms=["linux"], products=["openbsd:openssh"]))
    assert assess_mitigation(sshd, machine, AFFECTED).status == "applicable"
    assert machine.config_state is not None
    machine.config_state.app_settings["openssh:logingracetime"] = "0"
    assert assess_mitigation(sshd, machine, AFFECTED).status == "already_applied"


def test_product_missing_is_not_applicable() -> None:
    machine = load_machine("java-app-server.json")
    office = make_mitigation(type="CONFIGURATION", title="Office setting", applies_to=AppliesTo(
        platforms=["linux"], products=["microsoft:office"]),
        action=Action(kind="set_config", target="office:protected_view=enabled"))
    assert assess_mitigation(office, machine, AFFECTED).status == "not_applicable"


def test_network_device_match_and_needs_device() -> None:
    bastion = load_machine("ubuntu-ssh-bastion.json")
    pan_rule = make_mitigation(type="IPS", layer="ips", title="Enable Threat Prevention signature",
                               action=Action(kind="apply_ips_signature", target="paloaltonetworks:95187"),
                               applies_to=AppliesTo(device_roles=["ips"], device_vendors=["paloaltonetworks"]))
    assert assess_mitigation(pan_rule, bastion, AFFECTED).status == "applicable"
    workstation = load_machine("win10-office-workstation.json")
    result = assess_mitigation(pan_rule, workstation, AFFECTED)
    assert result.status == "needs_device" and "fortinet" in result.reasons[0].lower()


def test_appliance_enforces_its_own_signatures() -> None:
    firewall = load_machine("pan-os-firewall.json")
    rule = make_mitigation(type="IPS", layer="ips", title="Threat IDs 95187",
                           action=Action(kind="apply_ips_signature", target="paloaltonetworks:95187"),
                           applies_to=AppliesTo(device_roles=["ips"], device_vendors=["paloaltonetworks"]))
    assert assess_mitigation(rule, firewall, AFFECTED).status == "applicable"


def test_edr_needs_tool() -> None:
    bastion = load_machine("ubuntu-ssh-bastion.json")
    asr = make_mitigation(type="EDR", layer="edr", title="ASR rule", applies_to=AppliesTo(
        security_tools=["microsoft:defender"]), action=Action(kind="enable_endpoint_protection",
                                                              target="defender:asr_office_child"))
    result = assess_mitigation(asr, bastion, AFFECTED)
    assert result.status == "needs_device" and "CrowdStrike" in result.reasons[0]


def test_withdrawn_is_never_applicable() -> None:
    machine = load_machine("win2019-print-server.json")
    gone = make_mitigation(status="withdrawn", withdrawn_reason="ineffective")
    assert assess_mitigation(gone, machine, AFFECTED).status == "not_applicable"


def test_rank_and_verdicts() -> None:
    machine = load_machine("win2019-print-server.json")
    items = rank([assess_mitigation(make_mitigation(), machine, AFFECTED)])
    assert items[0].rank == 1
    assert decide_verdict(AFFECTED, items, [])[0] == "mitigations_available"
    assert decide_verdict(AFFECTED, [], [])[0] == "no_documented_mitigation"
    assert decide_verdict(AffectednessResult(status="not_affected"), items, [])[0] == "not_affected"
    _ = Finding(cve="CVE-2021-34527")


def test_distro_package_state_gives_exact_answer() -> None:
    from porygon_mitigator.models.cve import DistroFix

    machine = load_machine("ubuntu-ssh-bastion.json")
    fixed = DistroFix(distro="ubuntu", release="22.04", package="openssh", status="fixed",
                      fixed_version="1:8.9p1-3ubuntu0.10")
    facts = CveFacts(cve_id="CVE-2024-6387", distro_fixes=[fixed])
    result = assess_affected(facts, machine)
    assert result.status == "affected" and "1:8.9p1-3ubuntu0.10" in result.reasons[0]
    machine.installed_software[0].version = "1:8.9p1-3ubuntu0.10"
    assert assess_affected(facts, machine).status == "not_affected"
    wont = DistroFix(distro="ubuntu", release="22.04", package="openssh", status="wont_fix")
    assert "won't fix" in assess_affected(CveFacts(cve_id="CVE-2099-1", distro_fixes=[wont]), machine).reasons[0]
