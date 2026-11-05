"""Print what the committed snapshot holds, offline: the CVEs on the eight hosts with their public fields, the Palo Alto
threat IDs for the known-exploited CVEs the demo plans for, and the documented plans kept as examples.

The README's funnel and coverage numbers also used per-CVE scores, flaw classes and the full plan set, which aren't
published, so this checks only what the files below can show.

Run: uv run python demo/tenable-lab/reproduce.py
"""

import json
from collections import Counter
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent


def rows(name: str) -> list[dict[str, Any]]:
    return [json.loads(line) for line in (HERE / name).read_text(encoding="utf-8").splitlines() if line]


def main() -> None:
    hosts = json.loads((HERE / "hosts.json").read_text(encoding="utf-8"))["hosts"]
    cves = {row["cve"]: row for row in rows("cves.jsonl")}
    remote = {cve for cve, row in cves.items() if "AV:N" in row["vector"]}
    kev = {cve for cve, row in cves.items() if row["kev"]}
    print(f"CVEs on the {len(hosts)} hosts' open findings: {len(cves):,}, "
          f"{len(remote):,} with a network attack vector, {len(kev)} on CISA KEV")

    threat_ids: dict[str, list[str]] = json.loads((HERE / "palo_threat_ids.json").read_text(encoding="utf-8"))
    listed = set(threat_ids)
    distinct = {threat for ids in threat_ids.values() for threat in ids}
    print(f"Palo Alto threat IDs: {len(listed)} CVEs, {len(listed & kev)} on CISA KEV, {len(listed & remote)} with a "
          f"network attack vector, {len(distinct)} distinct signatures")

    plans = rows("plans.jsonl")
    by_cve: dict[str, Counter[str]] = {}
    for plan in plans:
        by_cve.setdefault(plan["cve"], Counter())[plan["type"]] += 1
    print(f"Documented plans kept as examples: {len(plans)} for {len(by_cve)} CVEs")
    for cve, types in sorted(by_cve.items()):
        print(f"  {cve:16} {', '.join(f'{kind} {count}' for kind, count in sorted(types.items()))}")


if __name__ == "__main__":
    main()
