"""Build the README's pictures from a real run: one finding end to end, the funnel, and the benchmark scores.

    uv run python scripts/build_visuals.py

Needs Chrome (`CHROME` overrides where to find it). The funnel reads evals/flow/results/final-2026-11-04/impact.json.
The benchmark chart reads benchmark.json beside it. The finding comes from running the flow on the lab data in a temporary
folder: nothing touches a real device. That needs the lab's environment, which demo/tenable-lab/build_flow.py builds
locally and which is never committed; without it the finding's picture is skipped. The dashboard pictures are crops of
examples/flow/sample-report.html, the report on the whole lab, in its dark theme at 1260 px wide.
"""

import html
import json
import os
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
IMAGES = ROOT / "docs" / "images"
LAB = ROOT / "demo" / "tenable-lab" / "flow"
IMPACT = ROOT / "evals" / "flow" / "results" / "final-2026-11-04" / "impact.json"
CHROME = os.environ.get("CHROME", "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
CASE_CVE, CASE_HOST, CASE_MITIGATION = "CVE-2020-1350", "dc-2c52", "palo-cve-2020-1350"
FUNNEL_SCENARIO = "modeled firewall, scanner evidence only"
WIDTH = 1260
MAX_DROP = 0.999  # 34 of 99,726 still isn't a 100% drop
BENCHMARK = IMPACT.parent / "benchmark.json"
BENCH_AXIS_FROM = 0.95
BENCH_DEV, BENCH_HOLDOUT = "#3987e5", "#d95926"
STYLE = """
* { box-sizing: border-box; margin: 0; }
html, body { background: #0d1117; color: #e6edf3; font: 15px/1.45 -apple-system, "Segoe UI", Helvetica, Arial, sans-serif; }
body { padding: 28px; width: 1260px; }
h1 { font-size: 24px; font-weight: 650; }
.sub { color: #9198a1; margin-top: 4px; }
.card { background: #161b22; border: 1px solid #2a313a; border-radius: 12px; padding: 16px 20px; }
code { font: 13px ui-monospace, SFMono-Regular, Menlo, monospace; color: #c9d1d9; }
.steps { display: grid; gap: 10px; margin-top: 18px; }
.step { display: grid; grid-template-columns: 34px 150px 1fr; gap: 12px; align-items: start; }
.n { width: 26px; height: 26px; border-radius: 50%; background: #2a313a; text-align: center; line-height: 26px; font-size: 13px; }
.who { color: #9198a1; font-size: 13px; }
.name { font-weight: 600; }
.path { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; margin-top: 6px; }
.node { background: #1f2630; border: 1px solid #39414c; border-radius: 8px; padding: 4px 10px; font-size: 13px; }
.hot { border-color: #d9604c; background: #3a1d1a; }
.good { color: #3fb950; } .warn { color: #d4a72c; }
.stats { display: grid; grid-template-columns: repeat(5, 1fr); margin-top: 18px; }
.stat { border-left: 1px dashed #39414c; padding: 0 0 8px 12px; }
.stat:first-child { border-left: 0; padding-left: 0; }
.value { font-size: 24px; font-weight: 650; }
.label { color: #9198a1; font-size: 13px; }
.drop { color: #3fb950; font-size: 12px; }
svg { display: block; width: 100%; height: 170px; }
.foot { color: #9198a1; font-size: 13px; margin-top: 14px; }
.bench { display: grid; grid-template-columns: 1.15fr 1fr; gap: 28px; margin-top: 16px; }
h2 { font-size: 15px; margin: 0; }
.legend { color: #9198a1; font-size: 13px; margin: 4px 0 6px; }
.legend i { display: inline-block; width: 10px; height: 10px; border-radius: 50%; margin: 0 6px 0 12px; }
.legend i:first-child { margin-left: 0; }
.row { fill: #e6edf3; font-size: 14px; }
.mono { font: 13px ui-monospace, SFMono-Regular, Menlo, monospace; }
.num { fill: #c9d1d9; font-size: 13px; }
.axis { fill: #9198a1; font-size: 12px; }
"""


def _page(body: str) -> str:
    return f'<!doctype html><meta charset="utf-8"><style>{STYLE}</style><body>{body}</body>'


def _shoot(page: Path, out: Path, height: int) -> None:
    with tempfile.TemporaryDirectory() as profile:
        subprocess.run(  # noqa: S603 - our own file, a fixed browser
            [
                CHROME,
                "--headless=new",
                "--disable-gpu",
                "--hide-scrollbars",
                f"--user-data-dir={profile}",
                "--force-color-profile=srgb",
                "--force-device-scale-factor=2",
                f"--window-size={WIDTH},{height}",
                "--virtual-time-budget=4000",
                f"--screenshot={out}",
                page.as_uri(),
            ],
            check=True,
            capture_output=True,
        )


def _step(number: int, name: str, who: str, body: str) -> str:
    return (
        f'<div class="card step"><div class="n">{number}</div><div><div class="name">{name}</div>'
        f'<div class="who">{who}</div></div><div>{body}</div></div>'
    )


def case_page() -> str:
    """One finding through every step, each value read from the run."""
    from porygon_mitigator.flow import engine, runs

    runs.load_files(str(LAB / "environment.json"), str(LAB / "mitigations.json"), restart=True)
    run = runs._run_path(None)
    environment, mitigations = runs._environment(run), runs._mitigations(run)
    host = next(item for item in environment.hosts if item.id == CASE_HOST)
    finding = next(item for item in host.findings if item.cve == CASE_CVE and item.remote_check)
    tagged = next(
        item for item in engine.tag_cves(environment, mitigations) if (item.cve, item.host) == (CASE_CVE, CASE_HOST)
    )
    kev_reachable = engine.funnel(engine.tag_cves(environment, mitigations)).kev_reachable
    mitigation = next(item for item in mitigations if item.id == CASE_MITIGATION)
    hops = engine.reach(environment, "internet", host)[0][0]
    path = "".join(
        f'<span class="node">{html.escape(hop.device)}<br><code>{html.escape(hop.rule or "")}</code></span> →'
        for hop in hops
    )
    program = next((name for name in host.processes if "dns" in name.lower()), "")
    plan = runs.make_plan([CASE_MITIGATION])["plan"]
    impact = plan["impact"][0]
    before, after = plan["before"]["kev_exposed"], plan["expected_after"]["kev_exposed"]
    runs.apply_approved(plan["plan_hash"])
    check = runs.verify_applied()
    firewall = runs.firewall_receipt() or {"devices": [{"calls": [], "commit_job": ""}]}
    calls = len(firewall["devices"][0]["calls"])
    passed = [item.name for item in check.checks if item.passed and item.name.startswith("allowed traffic")]
    closed = f"no longer exposed: {CASE_CVE} on {CASE_HOST}"
    verdict = (
        "No longer exposed." if any(item.passed and item.name == closed for item in check.checks) else "Still exposed."
    )
    runs.rollback()
    restored = engine.funnel(engine.tag_cves(runs._environment(run), mitigations)).kev_exposed
    steps = [
        (
            "Scan finding",
            "Tenable",
            f"<b>{html.escape(finding.title)}</b> on <code>{CASE_HOST}</code>, a domain controller. "
            f"{finding.severity.title()}, on CISA's known-exploited list, and Tenable tested it over the network.",
        ),
        (
            "Map",
            "Code",
            f'Is there a path from the internet?<div class="path"><span class="node">Internet</span> → {path} '
            f'<span class="node hot">{CASE_HOST}</span></div>',
        ),
        (
            "Flaw class",
            "Lab data here, Haiku on a live run",
            f"A flaw in a <b>{finding.vulnerability_class}</b>, and <code>{html.escape(program)}</code> "
            "is running on the machine.",
        ),
        (
            "Tag",
            "Code",
            f"Verdict: <b>{tagged.tag}</b>, because the scanner tested it over an open path. One of only "
            f"{kev_reachable} critical known-exploited findings with that evidence.",
        ),
        (
            "Recommend",
            "Code, explained by Haiku",
            f"Block it with Palo Alto signatures <code>{', '.join(mitigation.threat_ids)}</code>, "
            "with no change on the machine.",
        ),
        (
            "Plan",
            "Code",
            f"Add the signature to rules <code>{', '.join(rule.split(': ')[1] for rule in impact['rules'])}</code>. "
            f"Critical known-exploited exposed: <b>{before} → {after}</b>. Hash <code>{plan['plan_hash']}</code>.",
        ),
        (
            "Approve",
            "A person only",
            f"<code>/porygon-mitigator:porygon-apply {plan['plan_hash']}</code> sends {calls} PAN-OS API "
            "calls to a mock firewall on this machine. The agent can't run it.",
        ),
        (
            "Verify",
            "Code, explained by Haiku",
            f'<span class="good">{verdict}</span> {len(passed)} allowed flows still pass, '
            f'and the verify {"passed" if check.passed else "failed"}. <span class="warn">{", ".join(check.unknown_dropped)} now dropped: '
            "flagged for a person to check.</span>",
        ),
        (
            "Rollback",
            "A person only",
            f"<code>/porygon-mitigator:porygon-rollback</code> restores the config. Back to {restored} exposed.",
        ),
    ]
    cards = "".join(_step(index + 1, *step) for index, step in enumerate(steps))
    return _page(
        f"<h1>One finding, end to end: SIGRed on the domain controller</h1>"
        f'<div class="sub">{CASE_CVE}. A real Tenable finding on a network we modeled. Nothing touched a real device. Who does each step is for a normal run: this picture ran the code, with no model.</div>'
        f'<div class="steps">{cards}</div>'
    )


def funnel_page() -> str:
    data = json.loads(IMPACT.read_text(encoding="utf-8"))
    row = next(item for item in data["scenarios"] if item["scenario"] == FUNNEL_SCENARIO)
    stages = [
        ("All findings", row["findings"]),
        ("High &amp; critical", row["high_critical"]),
        ("Remotely exploitable", row["remotely_exploitable"]),
        ("Exposed and known exploited", row["known_exposed"]),
        ("Unmitigated", row["unmitigated"]),
    ]
    stats = "".join(
        f'<div class="stat"><div class="value">{value:,}</div>'
        + (
            f'<div class="drop">↘ {min(1 - value / row["findings"], MAX_DROP) if value else 1:.1%}</div>'
            if index
            else '<div class="drop">&nbsp;</div>'
        )
        + f'<div class="label">{label}</div></div>'
        for index, (label, value) in enumerate(stages)
    )
    box, peak = 600, row["findings"] ** 0.5
    middle, reach = 50, 48
    tops = [(index + 0.5) * box / len(stages) for index in range(len(stages))]
    half = [value**0.5 / peak * reach for _, value in stages]

    def edge(sign: int) -> str:
        path = f"M0 {middle - sign * half[0]:.2f} L{tops[0]:.2f} {middle - sign * half[0]:.2f}"
        for index in range(1, len(stages)):
            bend = (tops[index - 1] + tops[index]) / 2
            path += (
                f" C{bend:.2f} {middle - sign * half[index - 1]:.2f} {bend:.2f} {middle - sign * half[index]:.2f}"
                f" {tops[index]:.2f} {middle - sign * half[index]:.2f}"
            )
        return f"{path} L{box} {middle - sign * half[-1]:.2f}"

    area = f"{edge(1)} L{box} {middle + half[-1]:.2f}"
    for index in range(len(stages) - 1, 0, -1):
        bend = (tops[index] + tops[index - 1]) / 2
        area += (
            f" L{tops[index]:.2f} {middle + half[index]:.2f} C{bend:.2f} {middle + half[index]:.2f} {bend:.2f}"
            f" {middle + half[index - 1]:.2f} {tops[index - 1]:.2f} {middle + half[index - 1]:.2f}"
        )
    area += f" L0 {middle + half[0]:.2f} Z"
    plot = (
        f'<svg viewBox="0 0 {box} 100" preserveAspectRatio="none"><defs><linearGradient id="f"><stop offset="0" stop-color="#d9604c" '
        f'stop-opacity=".1"/><stop offset="1" stop-color="#d9604c" stop-opacity=".75"/></linearGradient></defs>'
        f'<path d="{area}" fill="url(#f)"/><path d="{edge(1)}" fill="none" stroke="#d9604c" vector-effect="non-scaling-stroke" stroke-width="1.5"/>'
        f'<path d="{edge(-1)}" fill="none" stroke="#d9604c" vector-effect="non-scaling-stroke" stroke-width="1.5"/></svg>'
    )
    return _page(
        f'<div class="card"><h1>Exposure funnel: the whole lab</h1><div class="sub">{row["hosts"]} hosts. '
        "Each finding is one CVE on one machine. Each % is the drop from all findings. "
        "Width uses a square-root scale, so read the numbers.</div>"
        f'<div class="stats">{stats}</div>{plot}<div class="foot">Real findings from a Tenable partner lab. '
        "Severity is each CVE's own, from NVD where the dataset has it. Known exploited means on CISA's list. The firewall is modeled, and decides the last two steps. "
        "Unmitigated is simulated, assumes a signature catches the exploit, and only counts mitigations we found.</div></div>"
    )


def benchmark_page() -> str:
    data = json.loads(BENCHMARK.read_text(encoding="utf-8"))
    head, items = data["headline"], data["items"]
    low, high, left, right = BENCH_AXIS_FROM, 1.0, 130, 620
    place = lambda value: left + (value - low) / (high - low) * (right - left)  # noqa: E731
    marks = ""
    for tick in (0.95, 0.975, 1.00):
        marks += (
            f'<line x1="{place(tick):.1f}" x2="{place(tick):.1f}" y1="30" y2="222" stroke="#2a313a"/>'
            f'<text x="{place(tick):.1f}" y="242" text-anchor="middle" class="axis">{tick:g}</text>'
        )
    rows = (("Map", "map"), ("Scan", "scan"), ("Map and scan", "all"))
    for index, (name, stage) in enumerate(rows):
        middle = 66 + index * 66
        marks += f'<text x="0" y="{middle + 5}" class="row">{name}</text>'
        for split, color, offset in (("dev", BENCH_DEV, -11), ("holdout", BENCH_HOLDOUT, 11)):
            row, y = head[f"{split}/{stage}"], middle + offset
            start, end = (place(item) for item in row["ci"])
            marks += (
                f'<line x1="{start:.1f}" x2="{end:.1f}" y1="{y}" y2="{y}" stroke="{color}" stroke-width="2" stroke-linecap="round"/>'
                f'<circle cx="{place(row["score"]):.1f}" cy="{y}" r="5" fill="{color}" stroke="#161b22" stroke-width="2"/>'
                f'<text x="{start - 10:.1f}" y="{y + 4}" text-anchor="end" class="num">{row["score"]:.3f}</text>'
            )
    missed = sorted((item for item in items.items() if item[1]["rate"] < 1), key=lambda item: item[1]["rate"])
    bars = ""
    for index, (name, item) in enumerate(missed):
        y, width = 46 + index * 44, item["rate"] * 400
        bars += (
            f'<text x="0" y="{y}" class="row mono">{html.escape(name)}</text>'
            f'<rect x="0" y="{y + 8}" width="400" height="8" rx="4" fill="#2a313a"/>'
            f'<rect x="0" y="{y + 8}" width="{width:.1f}" height="8" rx="4" fill="{BENCH_DEV}"/>'
            f'<text x="412" y="{y + 16}" class="num">{item["rate"]:.0%} ({item["pass"]} of {item["total"]})</text>'
        )
    critical = [item for item in items.values() if item["critical"]]
    runs = head["dev/all"]["runs"] + head["holdout/all"]["runs"]
    return _page(
        '<div class="card"><h1>Map and scan benchmark</h1>'
        f'<div class="sub">{runs} runs on Haiku 5.5, graded by checks and an Opus 5.5 judge. We wrote both network sets.</div>'
        '<div class="bench">'
        '<div><h2>Score, with its 95% interval</h2>'
        f'<div class="legend"><i style="background:{BENCH_DEV}"></i>Dev<i style="background:{BENCH_HOLDOUT}"></i>Holdout</div>'
        f'<svg viewBox="0 0 640 250" style="height:auto">{marks}</svg></div>'
        f'<div><h2>Checks below 100%</h2><div class="legend">{len(items) - len(missed)} of {len(items)} are at 100%, '
        f"including {sum(item['rate'] == 1 for item in critical)} of {len(critical)} critical ones</div>"
        f'<svg viewBox="0 0 540 {30 + len(missed) * 44}" style="height:auto">{bars}</svg></div>'
        "</div>"
        f'<div class="foot">The score axis starts at {BENCH_AXIS_FROM:.2f}, so read the numbers. The interval resamples scenarios. '
        "Simulated networks, not a real one.</div></div>"
    )


def main() -> None:
    with tempfile.TemporaryDirectory() as work:
        folder = Path(work)
        os.environ["PORYGON_FLOW_DIR"] = str(folder / "flow")
        if (LAB / "environment.json").exists():
            (folder / "case.html").write_text(case_page(), encoding="utf-8")
            _shoot(folder / "case.html", IMAGES / "end-to-end-sigred.png", 925)
        else:
            print("skipping end-to-end-sigred.png: it runs the flow on the lab, whose environment isn't "
                  "committed (demo/tenable-lab/build_flow.py builds it)")
        (folder / "funnel.html").write_text(funnel_page(), encoding="utf-8")
        _shoot(folder / "funnel.html", IMAGES / "funnel-lab.png", 440)
        (folder / "benchmark.html").write_text(benchmark_page(), encoding="utf-8")
        _shoot(folder / "benchmark.html", IMAGES / "benchmark-scores.png", 480)


if __name__ == "__main__":
    main()
