"""`porygon` command line.

    porygon mitigate CVE-2022-30190 --machine examples/machines/win10-office-workstation.json --offline
    porygon cache list
    porygon profile validate examples/machines/win10-office-workstation.json
"""

from __future__ import annotations

import argparse
import asyncio
import json
import re
import sys
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from porygon_mitigator import __version__
from porygon_mitigator.cache.store import CacheStore, freshness, normalize_cve_id
from porygon_mitigator.config import Settings
from porygon_mitigator.funnel import DEFAULT_CHECKPOINT_SEARCHES
from porygon_mitigator.models.machine import MachineProfile
from porygon_mitigator.pipeline import Mode, NotCachedError, mitigate
from porygon_mitigator.report import render_json, render_markdown
from porygon_mitigator.text import to_ascii

EXIT_ERROR = 1
EXIT_NOT_CACHED = 3


def _err(message: str) -> None:
    print(to_ascii(message), file=sys.stderr)


def _load_json(path: str) -> object:
    with Path(path).open(encoding="utf-8") as handle:
        return json.load(handle)


def _overlay(profile: MachineProfile, path: str | None) -> MachineProfile:
    """Merge a partial profile (e.g. network_path, security_tools, config_state) over a generated one."""
    if not path:
        return profile
    extra = _load_json(path)
    if not isinstance(extra, dict):
        raise ValueError("--overlay must be a JSON object with MachineProfile fields")
    return MachineProfile.model_validate({**profile.model_dump(), **extra})


def load_machine(args: argparse.Namespace) -> MachineProfile:
    if getattr(args, "tenable_asset", None):
        from porygon_mitigator.integrations.tenable_one.mapper import profile_from_tenable

        findings = _load_json(args.tenable_findings) if getattr(args, "tenable_findings", None) else []
        asset = _load_json(args.tenable_asset)
        if not isinstance(asset, dict) or not isinstance(findings, list):
            raise ValueError("--tenable-asset must be a JSON object and --tenable-findings a JSON list")
        return _overlay(profile_from_tenable(asset, findings), getattr(args, "overlay", None))
    if not args.machine:
        raise ValueError("give --machine <profile.json> or --tenable-asset <asset.json>")
    return _overlay(MachineProfile.model_validate(_load_json(args.machine)), getattr(args, "overlay", None))


def cmd_tenable_profile(args: argparse.Namespace) -> int:
    """Build a machine profile from Tenable data: an exported asset file, or live from the tenant by asset UUID."""
    if args.asset_file:
        args.tenable_asset, args.tenable_findings = args.asset_file, args.findings_file
        profile = load_machine(args)
    else:
        from porygon_mitigator.integrations.tenable_one.client import TenableError, TenableOneClient, tenable_http
        from porygon_mitigator.integrations.tenable_one.mapper import profile_from_tenable
        from porygon_mitigator.sources.net import FetchError

        async def fetch() -> MachineProfile:
            async with tenable_http() as http:
                asset, findings = await TenableOneClient(http).asset_with_findings(args.asset)
            return profile_from_tenable(asset, findings)

        try:
            profile = _overlay(asyncio.run(fetch()), args.overlay)
        except (TenableError, FetchError) as error:
            _err(f"tenable: {error}")
            return EXIT_ERROR
    text = profile.model_dump_json(indent=2) + "\n"
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
        _err(f"wrote {args.out}")
    else:
        sys.stdout.write(text)
    return 0


def cmd_tenable_coverage(args: argparse.Namespace) -> int:
    """Report what the scanner could not see: from export files, or live from the tenant."""
    from porygon_mitigator.integrations.tenable_one.coverage import scan_coverage
    from porygon_mitigator.report.coverage import render_coverage_markdown

    if bool(args.assets_file) != bool(args.findings_file):
        _err("give both --assets-file and --findings-file, or neither to read the tenant live")
        return EXIT_ERROR
    if args.assets_file:
        assets, findings = _load_json(args.assets_file), _load_json(args.findings_file)
        if not isinstance(assets, list) or not isinstance(findings, list):
            _err("--assets-file and --findings-file must be JSON lists")
            return EXIT_ERROR
    else:
        from porygon_mitigator.integrations.tenable_one.client import TenableError, TenableOneClient, tenable_http
        from porygon_mitigator.sources.net import FetchError

        async def fetch() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
            async with tenable_http() as http:
                return await TenableOneClient(http).scan_inventory()

        try:
            assets, findings = asyncio.run(fetch())
        except (TenableError, FetchError) as error:
            _err(f"tenable: {error}")
            return EXIT_ERROR
    report = scan_coverage(assets, findings)
    json_text = report.model_dump_json(indent=2) + "\n"
    text = json_text if args.format == "json" else render_coverage_markdown(report, args.limit)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
        _err(f"wrote {args.out}")
    else:
        sys.stdout.write(text)
    return 0


def _print_json(value: object) -> None:
    sys.stdout.write(json.dumps(value, indent=2, sort_keys=True) + "\n")


def _flow_follow_up(args: argparse.Namespace, plan: Any) -> int:
    """After an approved plan on tenant data: what Tenable can record, as a dry run unless asked to write."""
    from porygon_mitigator.flow import runs
    from porygon_mitigator.flow.models import Environment
    from porygon_mitigator.flow.tenable import execute_follow_up, plan_follow_up
    from porygon_mitigator.integrations.tenable_one.client import TenableError, TenableOneClient, tenable_http

    environment = Environment.model_validate(runs.environment_state(args.run))
    if environment.label != "tenant":
        if args.tenable_execute:
            _err("--tenable-execute ignored: this run's data isn't from a Tenable tenant")
        return 0
    follow_up = plan_follow_up(environment, plan, args.rescan_scan_id)
    if args.tenable_execute:
        if not runs.verify_applied(args.run).passed:
            _err("verification failed, so nothing was written to Tenable: `porygon flow verify` shows why")
            return EXIT_ERROR

        async def run() -> Any:
            async with tenable_http() as http:
                return await execute_follow_up(TenableOneClient(http), follow_up)

        try:
            follow_up = asyncio.run(run())
        except (TenableError, ValueError) as error:
            _err(f"tenable: {error}")
            _err(f"The plan stays applied. To retry: porygon flow tenable-follow-up {plan.plan_hash} --tenable-execute")
            return EXIT_ERROR
    _err("Tenable follow-up (executed):" if args.tenable_execute else "Tenable follow-up (dry run, nothing written):")
    _print_json(follow_up.model_dump())
    return 0


def cmd_flow(args: argparse.Namespace) -> int:
    from porygon_mitigator.flow import runs
    from porygon_mitigator.flow.report import render_dashboard, render_summary

    try:
        action = args.flow_command
        if action == "load":
            print(runs.load_files(args.environment, args.mitigations, args.restart))
        elif action == "demo":
            environment, mitigations = runs.example_files()
            print(runs.load_files(environment, mitigations, args.restart))
            sys.stdout.write(render_summary(runs.dashboard_data()))
        elif action == "collect":
            for step in [args.step] if args.step else runs.COLLECT_STEPS:
                _print_json(runs.collect(step, args.sources))
        elif action == "map":
            _print_json(runs.map_routes(args.sources, args.restart))
        elif action == "recommend":
            _print_json(runs.recommendation(args.run))
        elif action == "reach":
            _print_json(runs.reachability(args.run))
        elif action == "tags":
            _print_json(runs.tags(args.run))
        elif action == "match":
            _print_json(runs.candidates(args.run))
        elif action == "plan":
            _print_json(runs.make_plan(args.mitigation, args.run, args.accept_holds))
        elif action == "apply":
            if args.rescan_scan_id and not args.rescan_scan_id.isdigit():
                raise runs.FlowError("a Tenable scan id is a number; nothing was applied")
            plan = runs.apply_approved(args.plan_hash, args.run)
            _err(f"applied plan {plan.plan_hash} to the simulated environment; no real device changed")
            for item in (runs.firewall_receipt(args.run) or {}).get("devices", []):
                _err(f"mock firewall {item['device']}: {len(item['calls'])} API calls, commit job {item['commit_job']}")
            for note in (runs.firewall_receipt(args.run) or {}).get("not_sent", []):
                _err(f"not sent to a mock firewall: {note}")
            if not (runs.firewall_receipt(args.run) or {}).get("devices"):
                _err("nothing was sent to a mock firewall: this plan's changes stay in the model")
            return _flow_follow_up(args, plan)
        elif action == "tenable-follow-up":
            applied = runs.applied_plan(args.run)
            if applied is None or applied.plan_hash != args.plan_hash:
                raise runs.FlowError(f"plan {args.plan_hash} isn't the applied plan")
            return _flow_follow_up(args, applied)
        elif action == "verify":
            result = runs.verify_applied(args.run)
            _print_json(result.model_dump(mode="json"))
            return 0 if result.passed else EXIT_ERROR
        elif action == "rollback":
            print(f"rolled back plan {runs.rollback(args.run)} in the simulation")
            for item in (runs.firewall_rollback_receipt(args.run) or {}).get("devices", []):
                state = "config restored" if item["restored"] else "config NOT restored"
                print(f"mock firewall {item['device']}: {state}, commit job {item['commit_job']}")
            _err("anything already written to Tenable stays there: remove the Porygon tag in Tenable if you added one")
        elif action == "allow-source":
            from porygon_mitigator.flow import agentic

            print(f"sources can be read from {agentic.allow_source_folder(args.folder)}")
        elif action == "firewall":
            _print_json(runs.firewall_receipt(args.run) or {"mock": True, "devices": [], "note": "no plan is applied"})
        elif action == "status":
            sys.stdout.write(render_summary(runs.dashboard_data(args.run)))
        elif action == "report":
            page = render_dashboard(runs.dashboard_data(args.run))
            Path(args.out).write_text(page, encoding="utf-8")
            _err(f"wrote {args.out}")
    except runs.FlowError as error:
        _err(f"flow: {error}")
        return EXIT_ERROR
    return 0


def _write_output(text: str, out_dir: str | None, cve_id: str, machine: str, fmt: str) -> None:
    if not out_dir:
        sys.stdout.write(text)
        return
    safe_machine = re.sub(r"[^A-Za-z0-9._-]+", "_", machine)[:80] or "machine"
    path = Path(out_dir) / f"{cve_id}__{safe_machine}.{'md' if fmt == 'md' else 'json'}"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    _err(f"wrote {path}")


def cmd_mitigate(args: argparse.Namespace) -> int:
    settings = Settings()
    machine = load_machine(args)
    mode: Mode = "offline" if args.offline else ("refresh" if args.refresh else "auto")
    if mode != "offline" and not settings.has_anthropic_credentials:
        store = CacheStore.from_settings(settings)
        if mode == "refresh" or store.get(args.cve) is None:
            _err("live research needs ANTHROPIC_API_KEY; cached CVEs work with --offline (see `porygon cache list`)")
            return EXIT_ERROR
    try:
        result = asyncio.run(
            mitigate(
                args.cve,
                machine,
                settings=settings,
                mode=mode,
                save=not args.no_save,
                max_sources=args.max_sources,
                consensus=args.consensus,
                gap_fill=not args.no_gap_fill,
                progress=None if args.quiet else _err,
            )
        )
    except NotCachedError as error:
        _err(str(error))
        return EXIT_NOT_CACHED
    text = render_json(result) if args.format == "json" else render_markdown(result)
    _write_output(text, args.out, result.cve_id, result.machine, args.format)
    return 0


def cmd_cache_list(args: argparse.Namespace) -> int:
    store = CacheStore.from_settings(Settings())
    rows = store.list()
    if args.format == "json":
        payload = [
            {
                "cve_id": item.record.cve_id,
                "computed_at": item.record.computed_at.isoformat(),
                "mitigations": len(item.record.active_mitigations()),
                "fresh": freshness(item.record)[0],
                "layer": item.layer,
            }
            for item in rows
        ]
        print(json.dumps(payload, indent=2))
        return 0
    if not rows:
        print("cache is empty")
        return 0
    print(f"{'CVE':<18} {'mitigations':>11}  {'computed':<10}  {'fresh':<5}  layer")
    for item in rows:
        record = item.record
        fresh = "yes" if freshness(record)[0] else "no"
        print(
            f"{record.cve_id:<18} {len(record.active_mitigations()):>11}  "
            f"{record.computed_at.date().isoformat():<10}  {fresh:<5}  {item.layer}"
        )
    return 0


def cmd_cache_show(args: argparse.Namespace) -> int:
    store = CacheStore.from_settings(Settings())
    cached = store.get(normalize_cve_id(args.cve))
    if cached is None:
        _err(f"{args.cve} is not cached")
        return EXIT_NOT_CACHED
    print(cached.record.model_dump_json(indent=2))
    return 0


def cmd_profile_validate(args: argparse.Namespace) -> int:
    try:
        profile = MachineProfile.model_validate(_load_json(args.file))
    except ValidationError as error:
        _err(f"{args.file} is not a valid machine profile:\n{error}")
        return EXIT_ERROR
    print(
        f"ok: {profile.name} ({profile.os.platform}, {len(profile.installed_software)} software, "
        f"{len(profile.open_ports)} ports, {len(profile.network_path)} path devices)"
    )
    return 0


def cmd_profile_schema(args: argparse.Namespace) -> int:
    text = json.dumps(MachineProfile.model_json_schema(), indent=2) + "\n"
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    return 0


def cmd_catalogs_sync(args: argparse.Namespace) -> int:
    from porygon_mitigator.catalogs.sync import DEFAULT_SOURCES, LOADERS, sync

    sources = list(args.source or (LOADERS if args.all else DEFAULT_SOURCES))
    unknown = [name for name in sources if name not in LOADERS]
    if unknown:
        _err(f"unknown catalogue(s): {', '.join(unknown)}; choose from {', '.join(LOADERS)}")
        return EXIT_ERROR
    results = asyncio.run(sync(sources, Settings(), progress=_err))
    return 0 if all(not result.note.startswith("failed") for result in results) else EXIT_ERROR


def cmd_funnel(args: argparse.Namespace) -> int:
    """Exposure funnel over Tenable findings: an export file, or live from the tenant."""
    from porygon_mitigator.funnel import render_funnel, run_funnel

    if args.findings_file:
        rows = _load_json(args.findings_file)
        if not isinstance(rows, list):
            raise ValueError("--findings-file must be a JSON list of vulnerability export rows")
    else:
        from porygon_mitigator.integrations.tenable_one.client import TenableError, TenableOneClient, tenable_http
        from porygon_mitigator.sources.net import FetchError

        async def fetch() -> list[dict[str, object]]:
            async with tenable_http() as http:
                return await TenableOneClient(http).open_findings(args.cidr)

        try:
            rows = asyncio.run(fetch())
        except (TenableError, FetchError) as error:
            _err(f"tenable: {error}")
            return EXIT_ERROR
    say = None if args.quiet else _err
    funnel = asyncio.run(run_funnel(rows, settings=Settings(), checkpoint_searches=args.checkpoint_searches,
                                    progress=say))
    text = json.dumps(funnel.to_dict(), indent=2) + "\n" if args.format == "json" else render_funnel(funnel)
    sys.stdout.write(text)
    return 0


def _cve_args(values: list[str] | None, file: str | None) -> list[str]:
    cves = [normalize_cve_id(value) for value in values or []]
    if file:
        lines = Path(file).read_text(encoding="utf-8").splitlines()
        cves += [normalize_cve_id(json.loads(line)["cve"] if line.lstrip().startswith("{") else line)
                 for line in lines if line.strip()]
    if not cves:
        raise ValueError("give CVE IDs or --cves-file")
    return list(dict.fromkeys(cves))


def cmd_panos_collect(args: argparse.Namespace) -> int:
    """Read one firewall (directly, or through Panorama with --target) into a flow firewall export."""
    from porygon_mitigator.integrations.panos.client import PanosClient, PanosError
    from porygon_mitigator.integrations.panos.collect import collect

    verify: bool | str = args.ca_bundle or not args.insecure

    async def run() -> dict[str, Any]:
        async with PanosClient(args.host, target=args.target, verify=verify) as client:
            if not args.device_group:
                return await collect(client, vsys=args.vsys, read_logs=not args.no_logs)
            async with PanosClient(args.host, verify=verify) as panorama:
                return await collect(client, vsys=args.vsys, panorama=panorama, device_group=args.device_group,
                                     read_logs=not args.no_logs)

    try:
        export = asyncio.run(run())
    except PanosError as error:
        _err(f"panos: {error}")
        return EXIT_ERROR
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(export, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    ips = export["ips"]
    _err(f"{export['hostname']}: {len(export['security_rules'])} rules, {len(export['vulnerability_profiles'])} "
         f"vulnerability profiles, {ips['signatures_installed']} signatures (content {ips['content_version']}), "
         f"{len(ips['hits'])} signatures with hits -> {out}")
    for note in export["collection"]["notes"]:
        _err(f"note: {note}")
    return 0


def cmd_panos_coverage(args: argparse.Namespace) -> int:
    from porygon_mitigator.integrations.panos.collect import cve_coverage

    export = _load_json(args.export)
    if not isinstance(export, dict) or "ips" not in export:
        raise ValueError("--export must be a file written by `porygon panos collect`")
    rows = cve_coverage(export, _cve_args(args.cve, args.cves_file))
    if args.format == "json":
        sys.stdout.write(json.dumps(rows, indent=2) + "\n")
        return 0
    print("| CVE | Signatures | Blocking profiles | Enforcing rules | Hits (blocked) |")
    print("|---|---|---|---|---|")
    for row in rows:
        print(f"| {row['cve']} | {', '.join(row['threat_ids']) or 'none installed'} | "
              f"{', '.join(row['blocking_profiles']) or '-'} | {', '.join(row['enforcing_rules']) or '-'} | "
              f"{row['hits']} ({row['blocked_hits']}) |")
    enforced = sum(row["enforced"] for row in rows)
    installed = sum(row["installed"] for row in rows)
    print(f"\n{installed} of {len(rows)} CVEs have a signature installed; {enforced} are enforced by a blocking "
          "profile on an allow rule.")
    return 0


def cmd_rules_find(args: argparse.Namespace) -> int:
    from porygon_mitigator.catalogs.open_rules import RULESETS, find_rules, render_rules

    rulesets = args.ruleset or list(RULESETS)
    unknown = [name for name in rulesets if name not in RULESETS]
    if unknown:
        _err(f"unknown ruleset(s): {', '.join(unknown)}; choose from {', '.join(RULESETS)}")
        return EXIT_ERROR
    by_cve, notes = asyncio.run(find_rules(_cve_args(args.cve, args.cves_file), settings=Settings(),
                                           rulesets=rulesets, refresh=args.refresh,
                                           progress=None if args.quiet else _err))
    if args.format == "json":
        payload = {"rules": {cve: [rule.to_dict() for rule in rules] for cve, rules in by_cve.items()},
                   "notes": notes}
        sys.stdout.write(json.dumps(payload, indent=2) + "\n")
    else:
        sys.stdout.write(render_rules(by_cve, notes) + "\n")
    return 0 if len(notes) < len(rulesets) else EXIT_ERROR


def cmd_tag(args: argparse.Namespace) -> int:
    """Normalize CVEs in bulk into a normalized.json the flow reads."""
    from porygon_mitigator.flow.models import Environment
    from porygon_mitigator.tagging import TagInput, add_public_records, inputs_from_environment, tag, write_normalized

    settings = Settings()
    if not settings.has_anthropic_credentials:
        _err("tag needs ANTHROPIC_API_KEY (or ANTHROPIC_AUTH_TOKEN)")
        return EXIT_ERROR
    inputs: dict[str, TagInput] = {}
    if args.environment:
        inputs = inputs_from_environment(Environment.model_validate(_load_json(args.environment)))
    if args.cve or args.cves_file:
        wanted = _cve_args(args.cve, args.cves_file)
        inputs = {cve: inputs.get(cve) or TagInput(cve) for cve in wanted}
    if not inputs:
        raise ValueError("give --environment, CVE IDs or --cves-file")
    if args.limit:
        inputs = dict(list(inputs.items())[: args.limit])
    say = (lambda _message: None) if args.quiet else _err
    notes = [] if args.no_fetch else asyncio.run(add_public_records(inputs, settings, say))
    result = asyncio.run(tag(inputs, settings, model=args.model, progress=say))
    result.notes[:0] = notes
    write_normalized(Path(args.out), result.profiles)
    sys.stdout.write(json.dumps(result.summary(), indent=2) + "\n")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="porygon",
        description="Verified, machine-specific compensating controls for a CVE when you can't patch yet.",
    )
    parser.add_argument("--version", action="version", version=f"porygon-mitigator {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    m = sub.add_parser("mitigate", help="find the mitigations that apply to one machine")
    m.add_argument("cve", type=normalize_cve_id, help="CVE ID, e.g. CVE-2022-30190")
    src = m.add_argument_group("machine data (one of)")
    src.add_argument("--machine", help="machine profile JSON (see `porygon profile schema`)")
    src.add_argument("--tenable-asset", help="Tenable asset export record (JSON) [experimental]")
    src.add_argument("--tenable-findings", help="Tenable vulnerability export rows for that asset (JSON list)")
    src.add_argument("--overlay", help="partial profile JSON merged on top (network_path, security_tools...)")
    when = m.add_mutually_exclusive_group()
    when.add_argument("--offline", action="store_true", help="use the cache only; never touch the network")
    when.add_argument("--refresh", action="store_true", help="research live even if the cache is fresh")
    m.add_argument("--format", choices=["md", "json"], default="md")
    m.add_argument("--out", help="write the report into this directory instead of stdout")
    m.add_argument("--max-sources", type=int, default=None, help="cap on advisory pages read per CVE")
    m.add_argument("--consensus", action="store_true", help="extract twice and keep only agreeing mitigations")
    m.add_argument("--no-save", action="store_true", help="don't write new research to the cache")
    m.add_argument("--no-gap-fill", action="store_true", help="skip the machine-specific follow-up search")
    m.add_argument("-q", "--quiet", action="store_true", help="no progress messages on stderr")
    m.set_defaults(func=cmd_mitigate)

    c = sub.add_parser("cache", help="inspect the per-CVE JSON cache")
    csub = c.add_subparsers(dest="cache_command", required=True)
    cl = csub.add_parser("list", help="list cached CVEs")
    cl.add_argument("--format", choices=["table", "json"], default="table")
    cl.set_defaults(func=cmd_cache_list)
    cs = csub.add_parser("show", help="print a cached CVE record")
    cs.add_argument("cve", type=normalize_cve_id)
    cs.set_defaults(func=cmd_cache_show)

    k = sub.add_parser("catalogs", help="vendor IPS/WAF rule catalogues")
    ksub = k.add_subparsers(dest="catalogs_command", required=True)
    ks = ksub.add_parser("sync", help="download catalogues and rebuild the CVE -> rule ID indexes")
    ks.add_argument("--source", action="append", help="one catalogue (repeatable); default: all public ones")
    ks.add_argument("--all", action="store_true", help="include the heavy NetScaler crawl and Threat Vault (key)")
    ks.set_defaults(func=cmd_catalogs_sync)

    t = sub.add_parser("tenable", help="Tenable One / Tenable VM integration (experimental)")
    tsub = t.add_subparsers(dest="tenable_command", required=True)
    tp = tsub.add_parser("profile", help="build a machine profile from Tenable data")
    which = tp.add_mutually_exclusive_group(required=True)
    which.add_argument("--asset-file", help="an asset export record (JSON)")
    which.add_argument("--asset", help="asset UUID to export live (needs TENABLE_ACCESS_KEY/SECRET_KEY)")
    tp.add_argument("--findings-file", help="vulnerability export rows for that asset (JSON list)")
    tp.add_argument("--overlay", help="partial profile JSON merged on top (network_path, security_tools...)")
    tp.add_argument("--out", help="write the profile here instead of stdout")
    tp.set_defaults(func=cmd_tenable_profile, machine=None)
    tc = tsub.add_parser("coverage", help="report what the scanner could not see, per machine")
    tc.add_argument("--assets-file", help="asset export records (JSON list); omit both files to read the tenant live")
    tc.add_argument("--findings-file", help="vulnerability export rows, including informational ones (JSON list)")
    tc.add_argument("--format", choices=["md", "json"], default="md")
    tc.add_argument("--limit", type=int, default=25, help="machines listed per section in the Markdown report")
    tc.add_argument("--out", help="write the report here instead of stdout")
    tc.set_defaults(func=cmd_tenable_coverage)

    f = sub.add_parser("funnel", help="exposure funnel: all -> high/critical -> remote -> stoppable by an IPS rule")
    which = f.add_mutually_exclusive_group(required=True)
    which.add_argument("--findings-file", help="Tenable vulnerability export rows (JSON list)")
    which.add_argument("--tenable", action="store_true",
                       help="export open findings live (needs TENABLE_ACCESS_KEY/SECRET_KEY)")
    f.add_argument("--cidr", help="with --tenable: only assets in this range, e.g. 10.0.48.0/22")
    f.add_argument("--checkpoint-searches", type=int, default=DEFAULT_CHECKPOINT_SEARCHES,
                   help="web searches of advisories.checkpoint.com for the most urgent CVEs (0 = none)")
    f.add_argument("--format", choices=["md", "json"], default="md")
    f.add_argument("-q", "--quiet", action="store_true", help="no progress messages on stderr")
    f.set_defaults(func=cmd_funnel)

    pa = sub.add_parser("panos", help="read-only collection from a Palo Alto firewall or Panorama (XML API)")
    pasub = pa.add_subparsers(dest="panos_command", required=True)
    pc = pasub.add_parser("collect", help="write a firewall export: rules, profiles, installed signatures, hits")
    pc.add_argument("--host", required=True, help="firewall or Panorama address; key in PANOS_API_KEY")
    pc.add_argument("--target", help="a managed firewall's serial: proxy every call through Panorama to it")
    pc.add_argument("--device-group", help="with Panorama: also read this device group's pre/post rules and profiles")
    pc.add_argument("--vsys", default="vsys1")
    pc.add_argument("--no-logs", action="store_true", help="skip the threat-log query")
    pc.add_argument("--ca-bundle", help="CA bundle for the device's certificate (or PANOS_CA_BUNDLE)")
    pc.add_argument("--insecure", action="store_true", help="don't verify the device's TLS certificate")
    pc.add_argument("--out", required=True, help="where to write the export, e.g. sources/firewalls/fw1.json")
    pc.set_defaults(func=cmd_panos_collect)
    pv = pasub.add_parser("coverage", help="per CVE: signature installed, blocked by a profile, enforced, hits")
    pv.add_argument("--export", required=True, help="a file written by `porygon panos collect`")
    pv.add_argument("cve", nargs="*")
    pv.add_argument("--cves-file", help="one CVE per line, or JSON lines with a `cve` field")
    pv.add_argument("--format", choices=["md", "json"], default="md")
    pv.set_defaults(func=cmd_panos_coverage)

    r = sub.add_parser("rules", help="open-source IDS/IPS rules (Snort 3 community, ET Open for Suricata)")
    rsub = r.add_subparsers(dest="rules_command", required=True)
    rf = rsub.add_parser("find", help="download the open rulesets and print each CVE's rules, with their text")
    rf.add_argument("cve", nargs="*")
    rf.add_argument("--cves-file", help="one CVE per line, or JSON lines with a `cve` field")
    rf.add_argument("--ruleset", action="append", help="one ruleset (repeatable); default: all")
    rf.add_argument("--refresh", action="store_true", help="download again even if fetched in the last day")
    rf.add_argument("--format", choices=["text", "json"], default="text")
    rf.add_argument("-q", "--quiet", action="store_true")
    rf.set_defaults(func=cmd_rules_find)

    tg = sub.add_parser("tag", help="normalize CVEs in bulk (class, processes, versions, ...) into normalized.json")
    tg.add_argument("cve", nargs="*")
    tg.add_argument("--cves-file", help="one CVE per line, or JSON lines with a `cve` field")
    tg.add_argument("--environment", help="a flow environment.json: tag its findings, with their scanner text")
    tg.add_argument("--out", required=True, help="normalized.json to write or merge into (beside environment.json)")
    tg.add_argument("--model", help="default: PORYGON_TAG_MODEL or claude-haiku-5-5")
    tg.add_argument("--limit", type=int, help="tag at most this many CVEs")
    tg.add_argument("--no-fetch", action="store_true", help="don't read CVE.org/NVD; scanner text only")
    tg.add_argument("-q", "--quiet", action="store_true")
    tg.set_defaults(func=cmd_tag)

    f = sub.add_parser("flow", help="simulated flow: reachability, CVE tags, approved changes, verification")
    fsub = f.add_subparsers(dest="flow_command", required=True)
    fl = fsub.add_parser("load", help="start a run from an environment and mitigations file")
    fl.add_argument("--environment", required=True)
    fl.add_argument("--mitigations")
    fl.add_argument("--restart", action="store_true", help="start over even if a plan is applied, undoing it")
    fd = fsub.add_parser("demo", help="start a run on the bundled synthetic network")
    fd.add_argument("--restart", action="store_true", help="start over even if a plan is applied, undoing it")
    for name, text in (("reach", "the simulated scan"), ("tags", "tag every CVE"), ("match", "rank the mitigations"),
                       ("verify", "recompute after an applied plan"), ("rollback", "undo the applied plan"),
                       ("status", "a short summary")):
        fsub.add_parser(name, help=text).add_argument("--run", help="run id (default: the latest)")
    fc = fsub.add_parser("collect", help="read the simulated firewall, router and asset sources")
    fc.add_argument("step", nargs="?", choices=("firewall", "router", "assets"))
    fc.add_argument("--sources", help="the sources folder (default: the bundled example)")
    fm = fsub.add_parser("map", help="join the collected sources into a network and map routes to rules")
    fm.add_argument("--sources", help="the sources folder (default: the bundled example)")
    fm.add_argument("--restart", action="store_true", help="start over even if a plan is applied, undoing it")
    fsub.add_parser("recommend", help="what to mitigate and why").add_argument("--run")
    fp = fsub.add_parser("plan", help="plan the selected mitigations and print the hash to approve")
    fp.add_argument("mitigation", nargs="+", help="mitigation ids")
    fp.add_argument("--run")
    fp.add_argument("--accept-holds", action="store_true", help="plan held mitigations too, with their holds recorded")
    for name, text in (("apply", "apply an approved plan to the simulated environment"),
                       ("tenable-follow-up", "tenant data: show or retry what Tenable records for the applied plan")):
        fa = fsub.add_parser(name, help=text)
        fa.add_argument("plan_hash")
        fa.add_argument("--run")
        fa.add_argument("--rescan-scan-id", help="tenant data: the Tenable scan to relaunch on the affected hosts")
        fa.add_argument("--tenable-execute", action="store_true",
                        help="tenant data: after a passing verify, really tag the assets and launch the rescan "
                        "(default: dry run)")
    fsub.add_parser("allow-source", help="let the agent read source files from a folder").add_argument("folder")
    fsub.add_parser("firewall", help="what the applied plan sent to the local mock firewall").add_argument("--run")
    fr = fsub.add_parser("report", help="write the dashboard as one HTML file")
    fr.add_argument("--out", required=True)
    fr.add_argument("--run")
    f.set_defaults(func=cmd_flow)

    p = sub.add_parser("profile", help="machine profile helpers")
    psub = p.add_subparsers(dest="profile_command", required=True)
    pv = psub.add_parser("validate", help="check a machine profile JSON file")
    pv.add_argument("file")
    pv.set_defaults(func=cmd_profile_validate)
    ps = psub.add_parser("schema", help="print the machine profile JSON Schema")
    ps.add_argument("--out")
    ps.set_defaults(func=cmd_profile_schema)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except (ValueError, ValidationError, OSError) as error:
        _err(f"error: {error}")
        return EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
