"""Build the flow's lab environment from a Tenable export and this folder's dataset.

    uv run python demo/tenable-lab/build_flow.py --assets assets.json --findings vulns.json --kev kev.json \\
        --identities ~/.porygon/lab-identities.json

The CVEs are the lab's own. Host names, addresses and asset ids are random replacements: `--identities` is a
private `{real: replacement}` file, never committed, applied to the export before anything else reads it.
It writes `flow/environment.json`, which holds the lab's findings and so is gitignored. `cves.jsonl` keeps only
public fields, so the findings get no flaw class and keep the plugin's severity. `flow/mitigations.json` was built
from the full plan set, which this folder no longer holds, so it is left as committed.

The rule base below is invented for the demo: the lab has no firewall in front of anything, so which services are
published was chosen so the reachable CVEs are ones with a documented mitigation. Keep that in mind when reading any
"reachable" number from this environment.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

from pydantic import TypeAdapter

from porygon_mitigator.flow.models import (
    AllowedFlow,
    Device,
    Environment,
    Finding,
    FirewallRule,
    Host,
    ObservedTraffic,
    Route,
    Zone,
)
from porygon_mitigator.flow.tenable import environment_from_tenable

HERE = Path(__file__).resolve().parent
OUT = HERE / "flow"
SEVERE = {"critical", "high"}
SEGMENT_ZONES = {"Windows servers": "windows-servers", "Workstations": "workstations", "Linux servers": "linux-servers"}
FIREWALL = "fw-1"


def _read_anonymized(path: str, identities: dict[str, str]) -> Any:
    replacements = {token.lower(): value for token, value in identities.items()}
    tokens = "|".join(re.escape(token) for token in sorted(replacements, key=len, reverse=True))
    text = re.sub(rf"(?<![\w.-])({tokens})(?![\w-])", lambda found: replacements[found.group(1).lower()],
                  Path(path).read_text(encoding="utf-8"), flags=re.IGNORECASE)
    return json.loads(text)


def _exposure_rank(finding: Finding) -> tuple[bool, int]:
    ranks = ("info", "low", "medium", "high", "critical")
    return finding.access_vector == "network", ranks.index(finding.severity) if finding.severity in ranks else 0


def _rule(name: str, from_zone: str, destination: str) -> FirewallRule:
    return FirewallRule(name=name, from_zone=[from_zone], to_zone=["transit"], destination=[destination])


def _topology(host_rows: list[dict[str, Any]]) -> Environment:
    zones = [
        Zone(id="internet", name="Internet", kind="internet"),
        Zone(id="admin", name="IT admins", kind="management"),
        Zone(id="transit", name="Firewall to router", kind="unknown"),
        Zone(id="windows-servers", name="Windows servers", kind="server"),
        Zone(id="workstations", name="Workstations", kind="corp"),
        Zone(id="linux-servers", name="Linux servers", kind="server"),
    ]
    firewall = Device(
        id=FIREWALL,
        name="Palo Alto PA-820 (placement simulated)",
        fw_type="PaloAltoNGFW",
        version="11.1.1",
        zones=["internet", "admin", "transit"],
        rules=[
            _rule("publish-dns", "internet", "dc-2c52"),
            _rule("publish-web", "internet", "ubu-8ced"),
            _rule("publish-ike", "internet", "srv-2539"),
            _rule("remote-rdp", "internet", "dc-2c52"),
            _rule("remote-sql", "internet", "sql-647e"),
            FirewallRule(name="admin-access", from_zone=["admin"], to_zone=["transit"]),
            FirewallRule(name="deny-rest", action="deny"),
        ],
    )
    router = Device(
        id="router-56",
        name="Lab router",
        fw_type="Router",
        threat_prevention=False,
        zones=["transit", "windows-servers", "workstations", "linux-servers"],
        rules=[FirewallRule(name="routes-everything")],
    )
    flows = [
        AllowedFlow(name="Admin RDP to dc-2c52", source_zone="admin", host="dc-2c52"),
        AllowedFlow(name="Public DNS", source_zone="internet", host="dc-2c52"),
        AllowedFlow(name="Public website", source_zone="internet", host="ubu-8ced"),
        AllowedFlow(name="Remote SQL access", source_zone="internet", host="sql-647e"),
    ]
    placed = [Host(id=row["name"], zone=SEGMENT_ZONES[row["segment"]]) for row in host_rows]
    return Environment(label="tenant", zones=zones, devices=[firewall, router], hosts=placed, allowed_flows=flows)


def _add_routes(environment: Environment) -> None:
    """The routes the simulated placement implies: the firewall sends the lab's subnets to the router, which knows each
    host. Declared zones still decide where a host sits; these are what the route-to-rule mapping shows."""
    firewall, router = environment.devices
    subnets = sorted({".".join(host.ips[0].split(".")[:3]) + ".0/24" for host in environment.hosts if host.ips})
    firewall.routes = [
        *(Route(destination=subnet, next_hop_device=router.id) for subnet in subnets),
        Route(destination="0.0.0.0/0", zone="internet"),
    ]
    router.routes = [
        Route(destination=f"{host.ips[0]}/32", zone=host.zone) for host in environment.hosts if host.ips and host.zone
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--assets", required=True)
    parser.add_argument("--findings", required=True)
    parser.add_argument("--kev", required=True, help="the CISA KEV catalogue JSON")
    parser.add_argument("--identities", required=True, help="private JSON: real names, ips and ids to random ones")
    args = parser.parse_args()

    identities = json.loads(Path(args.identities).expanduser().read_text(encoding="utf-8"))
    assets = _read_anonymized(args.assets, identities)
    rows = _read_anonymized(args.findings, identities)
    kev = {item["cveID"]: item for item in json.loads(Path(args.kev).read_text(encoding="utf-8"))["vulnerabilities"]}
    host_rows = json.loads((HERE / "hosts.json").read_text(encoding="utf-8"))["hosts"]
    wanted = {row["asset_id"] for row in host_rows}
    cves = [json.loads(line) for line in (HERE / "cves.jsonl").read_text(encoding="utf-8").splitlines() if line]

    environment = environment_from_tenable(
        [asset for asset in assets if asset.get("id") in wanted],
        [row for row in rows if (row.get("asset") or {}).get("uuid") in wanted],
        kev,
        _topology(host_rows),
    )
    vectors = {item["cve"]: item.get("vector") or "" for item in cves}
    for host in environment.hosts:
        for finding in host.findings:
            finding.cvss_vector = vectors.get(finding.cve, "")
        host.ips = [ip for ip in host.ips if ":" not in ip]  # the lab's IPv6 addresses embed machine MAC addresses
        kept = {}
        for finding in host.findings:
            if (finding.access_vector == "network" and finding.severity in SEVERE) or finding.kev:
                finding.solution = finding.solution if finding.kev else ""
                # A CVE can have several plugins on a host. Keep the most exposed reading, so a later plugin's lower
                # one can't hide it, and any one of them testing it over the network counts.
                earlier = kept.get(finding.cve)
                if earlier:
                    finding.remote_check = finding.remote_check or earlier.remote_check
                    if _exposure_rank(earlier) > _exposure_rank(finding):
                        finding.severity, finding.access_vector = earlier.severity, earlier.access_vector
                kept[finding.cve] = finding
        host.findings = sorted(kept.values(), key=lambda item: item.cve)

    _add_routes(environment)

    OUT.mkdir(exist_ok=True)
    environment.observed_traffic = TypeAdapter(list[ObservedTraffic]).validate_json(
        (OUT / "sources" / "traffic.json").read_text(encoding="utf-8")
    )
    (OUT / "environment.json").write_text(environment.model_dump_json(exclude_defaults=True) + "\n", encoding="utf-8")
    print(f"{len(environment.hosts)} hosts, {sum(len(host.findings) for host in environment.hosts)} findings")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
