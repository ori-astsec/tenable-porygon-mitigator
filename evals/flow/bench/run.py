"""Run the map and scan benchmark against the real porygon agent, grade every run, and report.

    uv run python -m evals.flow.bench run [--split dev|holdout|all] [--reps 3] [--label NAME] [--model ID]
    uv run python -m evals.flow.bench grade DIR        # grade saved transcripts again (after changing the grader)
    uv run python -m evals.flow.bench report DIR       # print the report of a finished run
    uv run python -m evals.flow.bench compare A B      # what changed between two runs
    uv run python -m evals.flow.bench show DIR ID      # one scenario's tool calls, answer and failed checks
    uv run python -m evals.flow.bench judge-check      # the judge against hand-labelled answers
    uv run python -m evals.flow.bench build DIR        # write every scenario's files, to look at them

Runs go through Claude on Amazon Bedrock by default (AWS_PROFILE and AWS_REGION, as for the other evals); pass
--claude-api to use ANTHROPIC_API_KEY instead. Every run is a fresh `claude -p` with the plugin loaded from
--plugin-dir, in its own working directory and flow directory. Results land in output/flow-bench/<label>/.
"""

from __future__ import annotations

import argparse
import asyncio
import atexit
import hashlib
import json
import logging
import os
import random
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from evals.flow.bench import grade, scenarios
from evals.flow.bench.scenarios import Facts, Scenario
from porygon_mitigator.mcp_server import server

ROOT = scenarios.ROOT
OUTPUT = ROOT / "output" / "flow-bench"
AGENT = "porygon-mitigator:porygon"
DEFAULT_MODEL = "global.anthropic.claude-haiku-5-5"
DEFAULT_JUDGE = "claude-opus-5-5"
DEFAULT_JUDGE_FALLBACK = "claude-sonnet-5-5"
RUN_TIMEOUT = 420
# What a run inherits from the shell: the CLI's own needs and AWS for Bedrock, and nothing that opens a real system.
ENVIRONMENT_PREFIXES = ("AWS_", "CLAUDE_", "LC_", "NODE_", "SSL_", "UV_", "XDG_")
ENVIRONMENT_NAMES = {"ANTHROPIC_BEDROCK_BASE_URL", "CURL_CA_BUNDLE", "HOME", "HTTP_PROXY", "HTTPS_PROXY", "LANG",
                     "LOGNAME", "NO_PROXY", "PATH", "REQUESTS_CA_BUNDLE", "SHELL", "TERM", "TMPDIR", "USER"}
# What to charge for a judge call that failed before it reported usage: its reply cap at Opus's rate.
JUDGE_FAILED_USD = 0.32
RETRIED = {"no_result", "error_during_execution", "timeout"}
# Files whose text the agent reads for these two steps: what to change, and what a result was measured against.
PROMPT_FILES = (
    "agents/porygon.md",
    "skills/porygon-flow/SKILL.md",
    "src/porygon_mitigator/mcp_server.py",
    "src/porygon_mitigator/flow/runs.py",
    "src/porygon_mitigator/flow/topology.py",
)
# USD per million tokens at Claude API list prices: input, output, cache read, cache write. Bedrock bills separately.
RATES = {
    "claude-opus-5-5": (4.0, 20.0, 0.20, 5.0),
    "claude-sonnet-5-5": (2.0, 10.0, 0.20, 2.5),
    "claude-haiku-5-5": (0.10, 0.50, 0.01, 0.125),
}


@dataclass
class Run:
    scenario: Scenario
    rep: int
    folder: Path
    prompt: str
    facts: Facts
    sandbox: Path | None = None  # where the agent really works: outside the repo, with nothing naming the case

    @property
    def name(self) -> str:
        return f"{self.scenario.id}#{self.rep}"

    @property
    def flow(self) -> Path:
        return self.folder / "flow"

    @property
    def agent_flow(self) -> Path:
        return (self.sandbox or self.folder) / "flow"

    @property
    def workdir(self) -> Path:
        return (self.sandbox or self.folder) / "work"


def _write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _git(*arguments: str, cwd: Path) -> str:
    try:
        done = subprocess.run(  # noqa: S603 - fixed git arguments
            ["git", *arguments], cwd=cwd, capture_output=True, text=True, timeout=30, check=False  # noqa: S607
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return done.stdout.strip()


def fingerprint(plugin: Path) -> dict[str, Any]:
    """What the agent was given, so two results can be told apart: the commit and the prompt files' hashes."""
    files = {
        name: hashlib.sha256((plugin / name).read_bytes()).hexdigest()[:12]
        for name in PROMPT_FILES
        if (plugin / name).exists()
    }
    return {
        "plugin_dir": str(plugin),
        "commit": _git("rev-parse", "--short", "HEAD", cwd=plugin),
        "branch": _git("rev-parse", "--abbrev-ref", "HEAD", cwd=plugin),
        "dirty": bool(_git("status", "--porcelain", "--", *PROMPT_FILES, cwd=plugin)),
        "files": files,
    }


def _server_tools() -> tuple[list[str], list[str]]:
    """The MCP tools a run may call, and the ones it may not: anything else reaches outside the simulated network."""
    names = sorted(tool.name for tool in asyncio.run(server.list_tools()))
    allowed = [f"{grade.TOOL_PREFIX}{name}" for name in names if name.startswith("flow_")]
    denied = [f"{grade.TOOL_PREFIX}{name}" for name in names if not name.startswith("flow_")]
    return allowed, denied


def agent_command(prompt: str, args: argparse.Namespace) -> list[str]:
    command = ["claude", "-p", prompt, "--plugin-dir", str(args.plugin_dir), "--model", args.model,
               "--setting-sources", "project", "--output-format", "stream-json", "--verbose",
               "--no-session-persistence", "--max-budget-usd", str(args.max_budget_usd)]
    allowed, denied = _server_tools()
    if args.surface == "agent":
        command += ["--agent", AGENT, "--allowedTools", *allowed, "--disallowedTools", *denied]
    else:
        # The main thread with the porygon-flow skill: the same tools, minus the ones the agent can't use either.
        command += ["--allowedTools", *allowed, "Skill",
                    "--disallowedTools", *denied, "Bash", "Write", "Edit", "NotebookEdit", "Read", "Glob", "Grep",
                    "WebFetch", "WebSearch", "Task"]
    if args.effort:
        command += ["--effort", args.effort]
    return command


def agent_environment(run: Run, args: argparse.Namespace) -> dict[str, str]:
    """Only what the CLI and Bedrock need. A shell's Tenable or Palo Alto keys would reach the MCP server otherwise."""
    environment = {name: value for name, value in os.environ.items()
                   if name in ENVIRONMENT_NAMES or name.startswith(ENVIRONMENT_PREFIXES)}
    environment["PORYGON_FLOW_DIR"] = str(run.agent_flow)
    if args.claude_api:
        environment["ANTHROPIC_API_KEY"] = os.environ.get("ANTHROPIC_API_KEY", "")
    else:
        environment["CLAUDE_CODE_USE_BEDROCK"] = "1"
    return environment


def run_agent(run: Run, args: argparse.Namespace) -> dict[str, Any]:
    """One `claude -p`, retried with backoff when the plumbing failed. Returns what happened, never a score."""
    attempts: list[str] = []
    spent = 0.0
    for attempt in range(1, args.attempts + 1):
        started = time.monotonic()
        if run.sandbox and (run.sandbox / "start").exists():
            # A discarded attempt can't leave its state behind for the one that's graded.
            for name in ("flow", "work"):
                shutil.rmtree(run.sandbox / name, ignore_errors=True)
                shutil.copytree(run.sandbox / "start" / name, run.sandbox / name)
        try:
            done = subprocess.run(  # noqa: S603 - fixed binary; the prompt is the benchmark's own
                agent_command(run.prompt, args),
                cwd=run.workdir,
                capture_output=True,
                text=True,
                timeout=args.timeout,
                env=agent_environment(run, args),
                stdin=subprocess.DEVNULL,
                check=False,
            )
            stdout, stderr = done.stdout, done.stderr
        except subprocess.TimeoutExpired as error:
            stdout = error.stdout.decode() if isinstance(error.stdout, bytes) else (error.stdout or "")
            stderr = "timeout"
        (run.folder / "stream.jsonl").write_text(stdout, encoding="utf-8")
        (run.folder / "stderr.txt").write_text(stderr, encoding="utf-8")
        transcript = grade.parse_stream(stdout)
        # A killed run never reports its cost, so it's charged its cap: an estimate on the safe side.
        spent += transcript.cost_usd if transcript.has_result else args.max_budget_usd
        failure = "timeout" if stderr == "timeout" else grade.failure_class(transcript, args.model)
        attempts.append(failure or "ok")
        if failure not in RETRIED or attempt == args.attempts:
            if run.sandbox:
                shutil.copytree(run.agent_flow, run.flow, dirs_exist_ok=True)
            return {"failure": failure, "attempts": attempts, "cost_usd": spent,
                    "seconds": round(time.monotonic() - started, 1)}
        time.sleep(10 * attempt + random.uniform(0, 5))  # jitter, so retries don't line up
    return {"failure": "no_attempt", "attempts": attempts, "cost_usd": spent, "seconds": 0.0}


def latest_run(flow: Path) -> tuple[str | None, bool]:
    latest = flow / "latest"
    if not latest.exists():
        return None, False
    run_id = latest.read_text(encoding="utf-8").strip()
    return run_id, (flow / run_id / "applied.json").exists()


def grade_run(run: Run, judge: grade.Judge | None, model: str) -> tuple[grade.Grade | None, dict[str, Any]]:
    """Checks, then the judge (reused when its exact request was already answered). None when there's no answer."""
    stream = run.folder / "stream.jsonl"
    transcript = grade.parse_stream(stream.read_text(encoding="utf-8") if stream.exists() else "")
    meta = {
        "cost_usd": transcript.cost_usd,
        "input_tokens": transcript.input_tokens,
        "output_tokens": transcript.output_tokens,
        "cache_read_tokens": transcript.cache_read_tokens,
        "cache_write_tokens": transcript.cache_write_tokens,
        "turns": transcript.turns,
        "duration_ms": transcript.duration_ms,
        "tool_calls": len(transcript.calls),
        "tools": [call.tool for call in transcript.calls],
    }
    failure = grade.failure_class(transcript, model)
    if failure:
        return None, {**meta, "failure": failure}
    latest, applied = latest_run(run.flow)
    context = grade.Context(run.scenario, run.facts, transcript, run.prompt, latest, applied)
    checks = grade.run_checks(context)
    judged = None
    if judge is not None and run.scenario.criteria:
        system, user = grade.judge_request(run.scenario, run.facts, run.prompt, transcript.final)
        key = grade.request_key(judge.api_model(), judge.effort, system, user)
        saved = run.folder / "judge.json"
        if saved.exists() and _read_json(saved).get("key") == key and not _read_json(saved).get("error"):
            judged = grade.JudgeResult(**_read_json(saved))
        else:
            try:
                judged = judge.grade(run.scenario, run.facts, run.prompt, transcript.final)
            except Exception as error:  # a grader failure is a grader error, never a crash of the whole batch
                judged = grade.JudgeResult(key, judge.api_model(), error=f"judge failed: {type(error).__name__}")
            _write_json(saved, judged.__dict__)
    result = grade.combine(run.scenario, run.rep, checks, judged)
    _write_json(run.folder / "grade.json", result.as_json())
    return result, meta


# ---------------------------------------------------------------------------------------------------- set up


def plan_runs(args: argparse.Namespace, out: Path) -> list[Run]:
    chosen = scenarios.select(args.split, args.only)
    skipped = [scenario.id for scenario in chosen if not scenarios.runnable(scenario)]
    if skipped:
        print(f"skipping {', '.join(skipped)}: they run on the lab, whose environment isn't built here "
              "(demo/tenable-lab/build_flow.py)", file=sys.stderr)
        chosen = [scenario for scenario in chosen if scenarios.runnable(scenario)]
    if not chosen:
        raise SystemExit(f"no scenarios match split={args.split!r} only={args.only!r}")
    # Outside the repo, so the agent doesn't pick up its files, and with no name that says what the case tests.
    workspace = Path(tempfile.mkdtemp(prefix="flow-"))
    atexit.register(shutil.rmtree, workspace, ignore_errors=True)
    file_sets = scenarios.write_file_sets(workspace / "inputs")
    scratch = Path(tempfile.mkdtemp(prefix="facts-", dir=out))
    planned: list[Run] = []
    for scenario in chosen:
        files = file_sets[scenario.network]
        base_facts = scenarios.compute_facts(scenario, files, scratch)
        for rep in range(args.reps):
            folder = out / "runs" / scenario.id / f"r{rep}"
            if folder.exists():
                shutil.rmtree(folder)
            folder.mkdir(parents=True)
            sandbox = workspace / hashlib.sha256(f"{scenario.id}/{rep}".encode()).hexdigest()[:12]
            (sandbox / "work").mkdir(parents=True)
            (sandbox / "flow").mkdir()
            facts = Facts(**{**base_facts.as_json()})
            if scenario.hand == "relative":
                copy = sandbox / "work" / scenario.relative_dir
                copy.mkdir()
                shutil.copy(files.environment, copy / "environment.json")
                facts.environment = str(copy / "environment.json")
                if files.mitigations:
                    shutil.copy(files.mitigations, copy / "mitigations.json")
                    facts.mitigations = str(copy / "mitigations.json")
            before, _ = scenarios.prepare(scenario, files, sandbox / "flow")
            if before != base_facts.before_run_id:
                raise RuntimeError(f"{scenario.id}: preparing gave run {before}, facts expect {facts.before_run_id}")
            for name in ("flow", "work"):
                shutil.copytree(sandbox / name, sandbox / "start" / name)
            prompt = scenario.render(files, sandbox / "work")
            (folder / "prompt.txt").write_text(prompt + "\n", encoding="utf-8")
            _write_json(folder / "facts.json", facts.as_json())
            planned.append(Run(scenario, rep, folder, prompt, facts, sandbox))
    shutil.rmtree(scratch, ignore_errors=True)
    return planned


def load_runs(out: Path) -> list[Run]:
    """The runs of a finished benchmark, from what it saved: grading again needs nothing else."""
    found = []
    by_id = {item.id: item for item in scenarios.SCENARIOS}
    for facts_file in sorted(out.glob("runs/*/r*/facts.json")):
        folder = facts_file.parent
        scenario = by_id.get(folder.parent.name)
        if scenario is None:
            continue
        facts = Facts(**_read_json(facts_file))
        prompt = (folder / "prompt.txt").read_text(encoding="utf-8").rstrip("\n")
        found.append(Run(scenario, int(folder.name[1:]), folder, prompt, facts))
    return found


def preflight(args: argparse.Namespace, out: Path) -> None:
    """One trivial turn before any real run: credentials work, and the model that answers is the one asked for."""
    folder = Path(tempfile.mkdtemp(prefix="preflight-", dir=out))
    (folder / "work").mkdir()
    (folder / "flow").mkdir()
    probe = Run(scenarios.SCENARIOS[0], 0, folder, "Reply with the single word ready.", Facts(None, None, None, None,
                                                                                               None))
    outcome = run_agent(probe, argparse.Namespace(**{**vars(args), "attempts": 1}))
    if outcome["failure"]:
        tail = (folder / "stderr.txt").read_text(encoding="utf-8")[-600:]
        raise SystemExit(f"preflight failed ({outcome['failure']}): {tail or 'no output'}\n"
                         "On Bedrock, check AWS_PROFILE and AWS_REGION, and log in again if the token expired.")
    shutil.rmtree(folder, ignore_errors=True)


# ---------------------------------------------------------------------------------------------------- summarize


def _rates(model: str) -> tuple[float, float, float, float]:
    short = model.split("anthropic.", 1)[-1]
    return RATES.get(short, RATES["claude-opus-5-5"])


def judge_cost(row: dict[str, Any], model: str) -> float:
    rate = _rates(model)
    return (row.get("input_tokens", 0) * rate[0] + row.get("output_tokens", 0) * rate[1]
            + row.get("cache_read_tokens", 0) * rate[2]) / 1_000_000


def bootstrap(groups: list[list[float]], draws: int = 2000, seed: int = 7) -> tuple[float, float, float]:
    """Mean of per-scenario means, with a 95% interval from resampling scenarios: reps of one case move together."""
    means = [sum(group) / len(group) for group in groups if group]
    if not means:
        return 0.0, 0.0, 0.0
    rng = random.Random(seed)
    samples = sorted(sum(rng.choice(means) for _ in means) / len(means) for _ in range(draws))
    return sum(means) / len(means), samples[int(0.025 * draws)], samples[int(0.975 * draws) - 1]


def summarize(rows: list[dict[str, Any]], errors: list[dict[str, Any]], config: dict[str, Any]) -> dict[str, Any]:
    graded = [row for row in rows if "grade" in row]
    summary: dict[str, Any] = {"config": config, "runs": len(rows) + len(errors), "graded": len(graded),
                               "errors": len(errors), "headline": {}, "scenarios": {}, "items": {}, "families": {},
                               "judged_by": dict(Counter(row.get("judged_by", "") for row in graded
                                                         if row.get("judged_by"))),
                               "judge_errors": [f"{row['grade']['scenario']}#{row['grade']['rep']}: "
                                                f"{row['grade']['judge_error']}" for row in graded
                                                if row["grade"].get("judge_error")]}
    for split in ("dev", "holdout"):
        for stage in ("map", "scan", "all"):
            selected = [row for row in graded if row["grade"]["split"] == split
                        and (stage == "all" or row["grade"]["stage"] == stage)]
            if not selected:
                continue
            by_case: dict[str, list[float]] = defaultdict(list)
            critical: dict[str, list[float]] = defaultdict(list)
            for row in selected:
                by_case[row["grade"]["scenario"]].append(row["grade"]["score"])
                critical[row["grade"]["scenario"]].append(float(row["grade"]["critical_ok"]))
            mean, low, high = bootstrap(list(by_case.values()))
            crit, crit_low, crit_high = bootstrap(list(critical.values()))
            summary["headline"][f"{split}/{stage}"] = {
                "score": round(mean, 3), "ci": [round(low, 3), round(high, 3)],
                "critical_ok": round(crit, 3), "critical_ci": [round(crit_low, 3), round(crit_high, 3)],
                "scenarios": len(by_case), "runs": len(selected),
            }
    by_scenario: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in graded:
        by_scenario[row["grade"]["scenario"]].append(row)
    for name, items in sorted(by_scenario.items()):
        summary["scenarios"][name] = {
            "split": items[0]["grade"]["split"], "stage": items[0]["grade"]["stage"],
            "family": items[0]["grade"]["family"],
            "score": round(sum(row["grade"]["score"] for row in items) / len(items), 3),
            "critical_ok": round(sum(row["grade"]["critical_ok"] for row in items) / len(items), 3),
            "runs": len(items),
        }
    tally: dict[str, dict[str, Any]] = {}
    for row in graded:
        for kind in ("checks", "criteria"):
            for name, result in row["grade"][kind].items():
                if result["status"] == "na":
                    continue
                item = tally.setdefault(name, {"kind": "check" if kind == "checks" else "judge", "pass": 0,
                                               "total": 0, "critical": result["critical"] == "true", "failures": []})
                item["total"] += 1
                item["pass"] += result["status"] == "pass"
                if result["status"] == "fail":
                    detail = result.get("detail") or f"{result.get('reason', '')} | {result.get('quote', '')}"
                    item["failures"].append(f"{row['grade']['scenario']}#{row['grade']['rep']}: {detail}"[:400])
    for item in tally.values():
        item["rate"] = round(item["pass"] / item["total"], 3)
    summary["items"] = dict(sorted(tally.items(), key=lambda pair: (pair[1]["rate"], pair[0])))
    families: dict[str, list[float]] = defaultdict(list)
    for row in graded:
        families[f"{row['grade']['family']} ({row['grade']['stage']})"].append(row["grade"]["score"])
    summary["families"] = {name: round(sum(values) / len(values), 3) for name, values in sorted(families.items())}
    judge_model = config.get("judge_model") or DEFAULT_JUDGE
    summary["cost"] = {
        "agent_usd": round(sum(row.get("cost_usd", 0.0) for row in [*rows, *errors]), 4),
        "judge_usd_at_list_price": round(sum(judge_cost(row.get("judge_usage", {}), judge_model) for row in rows), 4),
        "agent_input_tokens": sum(row.get("input_tokens", 0) for row in rows),
        "agent_output_tokens": sum(row.get("output_tokens", 0) for row in rows),
        "agent_cache_read_tokens": sum(row.get("cache_read_tokens", 0) for row in rows),
        "mean_tool_calls": round(sum(row.get("tool_calls", 0) for row in graded) / max(1, len(graded)), 2),
        "mean_seconds": round(sum(row.get("duration_ms", 0) for row in graded) / max(1, len(graded)) / 1000, 1),
    }
    summary["error_classes"] = {
        name: sum(row["failure"] == name for row in errors) for name in sorted({row["failure"] for row in errors})
    }
    return summary


def render_report(summary: dict[str, Any]) -> str:
    config = summary["config"]

    def critical(item: dict[str, Any]) -> str:
        return f"{item['critical_ok']:.2f}" if config.get("judge_model") else "n/a"

    config = summary["config"]
    plugin = config["fingerprint"]
    lines = [
        f"# Flow benchmark: map and scan ({config.get('label', '')})",
        "",
        f"Model `{config.get('model')}` on the `{config.get('surface')}` surface, {config.get('reps')} reps, judge "
        f"`{config.get('judge_model')}`. Plugin {plugin.get('branch')}@{plugin.get('commit')}"
        f"{' with uncommitted prompt changes' if plugin.get('dirty') else ''}.",
        f"{summary['graded']} runs graded, {summary['errors']} errors {summary.get('error_classes') or ''}. "
        f"{len(summary.get('judge_errors', []))} runs graded on checks only, the judge having failed on them, being "
        "turned off or past the budget, so they can't pass the critical criteria: "
        f"{summary.get('judge_errors') or 'none'}. Verdicts by judge model: {summary.get('judged_by') or 'none'}.",
        "",
        "| Split / stage | Score | 95% CI | All critical checks pass | Scenarios | Runs |",
        "|---|---:|---|---:|---:|---:|",
    ]
    for name, item in summary["headline"].items():
        lines.append(f"| {name} | {item['score']:.3f} | {item['ci'][0]:.2f} to {item['ci'][1]:.2f} | "
                     f"{critical(item)} | {item['scenarios']} | {item['runs']} |")
    lines += ["", "Score: share of applicable checks and judge criteria passed, averaged per scenario, then over "
              "scenarios. The interval resamples scenarios.", "", "## Checks and criteria, worst first", "",
              "| Item | Kind | Critical | Pass rate | Runs |", "|---|---|---|---:|---:|"]
    for name, item in summary["items"].items():
        lines.append(f"| `{name}` | {item['kind']} | {'yes' if item['critical'] else ''} | {item['rate']:.2f} | "
                     f"{item['total']} |")
    lines += ["", "## Scenarios", "", "| Scenario | Split | Stage | Score | All critical pass |",
              "|---|---|---|---:|---:|"]
    for name, item in summary["scenarios"].items():
        lines.append(f"| {name} | {item['split']} | {item['stage']} | {item['score']:.2f} | "
                     f"{critical(item)} |")
    failing = [(name, item) for name, item in summary["items"].items() if item["failures"]]
    if failing:
        lines += ["", "## Failures", ""]
        for name, item in failing:
            lines.append(f"**{name}** ({item['pass']}/{item['total']})")
            lines += [f"- {text}" for text in item["failures"][:8]]
            lines.append("")
    cost = summary["cost"]
    lines += ["## Cost", "",
              f"Agent ${cost['agent_usd']:.3f} as reported by Claude Code; judge "
              f"${cost['judge_usd_at_list_price']:.3f} at Claude API list prices. Mean {cost['mean_tool_calls']} "
              f"tool calls and {cost['mean_seconds']}s per run."]
    return "\n".join(lines) + "\n"


def finish(out: Path, runs: list[Run], outcomes: dict[str, dict[str, Any]], judge: grade.Judge | None,
           config: dict[str, Any], workers: int, budget: float = float("inf"), spent: float = 0.0) -> dict[str, Any]:
    lock = threading.Lock()
    total = [spent]

    def one(run: Run) -> tuple[Run, grade.Grade | None, dict[str, Any]]:
        # Past the budget it grades on checks only. Those runs can't count as passing the critical criteria.
        with lock:
            over = total[0] > budget
        result, meta = grade_run(run, None if over else judge, config["model"])
        saved = run.folder / "judge.json"
        if not over and saved.exists():
            usage = _read_json(saved)
            with lock:
                failed = usage.get("error") and not usage.get("output_tokens")
                total[0] += JUDGE_FAILED_USD if failed else judge_cost(usage, str(config.get("judge_model") or ""))
        return run, result, meta

    rows, errors = [], []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for run, result, meta in pool.map(one, runs):
            base = {"scenario": run.scenario.id, "rep": run.rep, **meta, **outcomes.get(run.name, {})}
            saved = run.folder / "judge.json"
            if saved.exists():
                usage = _read_json(saved)
                base["judge_usage"] = {key: usage.get(key, 0) for key in
                                       ("input_tokens", "output_tokens", "cache_read_tokens")}
                base["judged_by"] = usage.get("model", "")
            if result is None:
                errors.append(base)
            else:
                rows.append({**base, "grade": result.as_json()})
    with (out / "results.jsonl").open("w", encoding="utf-8") as handle:
        handle.writelines(json.dumps(row, sort_keys=True) + "\n" for row in rows)
    with (out / "errors.jsonl").open("w", encoding="utf-8") as handle:
        handle.writelines(json.dumps(row, sort_keys=True) + "\n" for row in errors)
    summary = summarize(rows, errors, config)
    _write_json(out / "summary.json", summary)
    (out / "report.md").write_text(render_report(summary), encoding="utf-8")
    return summary


# ---------------------------------------------------------------------------------------------------- commands


def make_judge(args: argparse.Namespace) -> grade.Judge | None:
    if args.no_judge:
        return None
    return grade.Judge(args.judge_model, args.judge_effort, bedrock=not args.claude_api,
                       fallback=args.judge_fallback or None)


def command_run(args: argparse.Namespace) -> int:
    args.plugin_dir = Path(args.plugin_dir).resolve()
    label = args.label or datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    out = (Path(args.out) if args.out else OUTPUT).resolve() / label
    out.mkdir(parents=True, exist_ok=True)
    config = {
        "label": label, "model": args.model, "surface": args.surface, "reps": args.reps, "split": args.split,
        "only": args.only, "effort": args.effort, "judge_model": None if args.no_judge else args.judge_model,
        "judge_effort": args.judge_effort, "bedrock": not args.claude_api, "fingerprint": fingerprint(args.plugin_dir),
        "started": datetime.now(UTC).isoformat(timespec="seconds"),
    }
    _write_json(out / "config.json", config)
    if not args.skip_preflight:
        preflight(args, out)
    runs = plan_runs(args, out)
    print(f"{len(runs)} runs ({len({run.scenario.id for run in runs})} scenarios x {args.reps}) -> {out}", flush=True)
    outcomes: dict[str, dict[str, Any]] = {}
    spent = [0.0]
    lock = threading.Lock()

    def one(run: Run) -> tuple[Run, dict[str, Any]]:
        # Checked as each run starts, not as results come back in order, so a slow early run can't hide the spend.
        with lock:
            over = spent[0] > args.budget
        if over:
            return run, {"failure": "skipped_budget", "attempts": [], "cost_usd": 0.0, "seconds": 0.0}
        outcome = run_agent(run, args)
        with lock:
            spent[0] += outcome["cost_usd"]
        return run, outcome

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        for run, outcome in pool.map(one, runs):
            outcomes[run.name] = outcome
            transcript = grade.parse_stream((run.folder / "stream.jsonl").read_text(encoding="utf-8")
                                            if (run.folder / "stream.jsonl").exists() else "")
            status = outcome["failure"] or "ok"
            print(f"  {run.name:30} {status:22} ${outcome['cost_usd']:.4f} {len(transcript.calls)} calls "
                  f"{outcome['seconds']}s", flush=True)
    summary = finish(out, runs, outcomes, make_judge(args), config, args.judge_workers, args.budget, spent[0])
    print((out / "report.md").read_text(encoding="utf-8"))
    print(f"agent ${summary['cost']['agent_usd']:.3f}, judge ${summary['cost']['judge_usd_at_list_price']:.3f} "
          f"(list price); wrote {out}")
    return 0


def command_grade(args: argparse.Namespace) -> int:
    out = Path(args.dir)
    config = _read_json(out / "config.json")
    if not args.no_judge:
        config["judge_model"], config["judge_effort"] = args.judge_model, args.judge_effort
    runs = load_runs(out)
    finish(out, runs, {}, make_judge(args), config, args.judge_workers)
    print((out / "report.md").read_text(encoding="utf-8"))
    return 0


def command_report(args: argparse.Namespace) -> int:
    print((Path(args.dir) / "report.md").read_text(encoding="utf-8"))
    return 0


def _size(value: Any) -> int:
    return value if isinstance(value, int) else len(value)


def command_compare(args: argparse.Namespace) -> int:
    before, after = (_read_json(Path(name) / "summary.json") for name in (args.before, args.after))
    print(f"before: {before['config']['label']} {before['config']['fingerprint']}")
    print(f"after:  {after['config']['label']} {after['config']['fingerprint']}\n")
    print(f"{'split/stage':16} {'before':>16} {'after':>16} {'delta':>7}")
    for name in sorted(set(before["headline"]) | set(after["headline"])):
        left, right = before["headline"].get(name), after["headline"].get(name)
        if not left or not right:
            continue
        print(f"{name:16} {left['score']:.3f} [{left['ci'][0]:.2f},{left['ci'][1]:.2f}] "
              f"{right['score']:.3f} [{right['ci'][0]:.2f},{right['ci'][1]:.2f}] {right['score'] - left['score']:+.3f}")
    print(f"\n{'':16} {'before':>16} {'after':>16}")
    for name, key in (("graded runs", "graded"), ("runs not graded", "errors"), ("scenarios", "scenarios")):
        print(f"{name:16} {_size(before[key]):>16} {_size(after[key]):>16}")
    if _size(before["errors"]) != _size(after["errors"]) or set(before["scenarios"]) != set(after["scenarios"]):
        print("Not the same runs: a case that dropped out raises a score without getting better.")
    print(f"\n{'item':28} {'before':>8} {'after':>8} {'delta':>7}")
    for name in sorted(set(before["items"]) | set(after["items"])):
        left = before["items"].get(name, {}).get("rate")
        right = after["items"].get(name, {}).get("rate")
        if left is None or right is None:
            print(f"{name:28} {left!s:>8} {right!s:>8}")
        elif abs(right - left) >= 0.001:
            print(f"{name:28} {left:8.2f} {right:8.2f} {right - left:+7.2f}")
    print(f"\n{'scenario':28} {'before':>8} {'after':>8} {'delta':>7}")
    for name in sorted(set(before["scenarios"]) & set(after["scenarios"])):
        left, right = before["scenarios"][name]["score"], after["scenarios"][name]["score"]
        if abs(right - left) >= 0.001:
            print(f"{name:28} {left:8.2f} {right:8.2f} {right - left:+7.2f}")
    runs = min(before["graded"], after["graded"])
    print(f"\nA pass rate over {runs} runs moves about +/-{1 / max(1, runs) ** 0.5:.2f} by chance: read small deltas "
          "as noise, and confirm a change on holdout before trusting it.")
    return 0


def command_show(args: argparse.Namespace) -> int:
    for folder in sorted(Path(args.dir).glob(f"runs/{args.scenario}/r*")):
        transcript = grade.parse_stream((folder / "stream.jsonl").read_text(encoding="utf-8")
                                        if (folder / "stream.jsonl").exists() else "")
        print(f"=== {args.scenario} {folder.name}\nPROMPT: {(folder / 'prompt.txt').read_text(encoding='utf-8')}")
        for call in transcript.calls:
            outcome = "error" if call.data and "error" in call.data else ("ok" if call.data else "")
            print(f"  -> {call.tool} {json.dumps(call.input)[:200]}  [{outcome}] {call.result[:160]!r}")
        print(f"ANSWER:\n{transcript.final}\n")
        if (folder / "grade.json").exists():
            result = _read_json(folder / "grade.json")
            for kind in ("checks", "criteria"):
                for name, item in result[kind].items():
                    if item["status"] == "fail":
                        print(f"  FAIL {name}: {item.get('detail') or item.get('reason')} {item.get('quote', '')!r}")
            print(f"  score {result['score']:.2f}, critical ok {result['critical_ok']}\n")
    return 0


def command_build(args: argparse.Namespace) -> int:
    out = Path(args.dir)
    sets = scenarios.write_file_sets(out)
    for name, files in sorted(sets.items()):
        print(f"{name:20} {files.environment}")
    return 0


def command_judge_check(args: argparse.Namespace) -> int:
    """Grade hand-labelled answers and report how often the judge agrees with the labels."""
    import yaml

    labelled = yaml.safe_load(Path(__file__).with_name("judge_calibration.yaml").read_text(encoding="utf-8"))
    judge = grade.Judge(args.judge_model, args.judge_effort, bedrock=not args.claude_api,
                        fallback=args.judge_fallback or None)
    scratch = Path(tempfile.mkdtemp(prefix="judge-check-"))
    sets = scenarios.write_file_sets(scratch / "data")
    by_id = {item.id: item for item in scenarios.SCENARIOS}
    agree = total = 0
    misses: list[str] = []
    for case in labelled["cases"]:
        scenario = by_id[case["scenario"]]
        wanted = case["labels"]
        narrowed = Scenario(**{**scenario.__dict__, "criteria": tuple(wanted)})
        facts = scenarios.compute_facts(narrowed, sets[scenario.network], scratch)
        prompt = scenario.render(sets[scenario.network], scratch)
        result = judge.grade(narrowed, facts, prompt, case["answer"])
        if result.error:
            misses.append(f"{case['id']}: judge error {result.error}")
            continue
        for name, label in wanted.items():
            total += 1
            got = result.verdicts[name]["verdict"]
            if got == label:
                agree += 1
            else:
                misses.append(f"{case['id']} {name}: judge {got}, label {label} ({result.verdicts[name]['reason']})")
    shutil.rmtree(scratch, ignore_errors=True)
    print(f"judge {judge.api_model()} agrees with {agree} of {total} labels ({agree / max(1, total):.0%})")
    for line in misses:
        print(f"  - {line}")
    return 0 if total and agree == total else 1


def main(argv: list[str] | None = None) -> int:
    for noisy in ("httpx", "httpx2", "botocore", "anthropic"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    parser = argparse.ArgumentParser(prog="python -m evals.flow.bench", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    def judge_options(command: argparse.ArgumentParser) -> None:
        command.add_argument("--judge-model", default=DEFAULT_JUDGE)
        command.add_argument("--judge-effort", default="high", choices=["low", "medium", "high", "xhigh", "max"])
        command.add_argument("--judge-fallback", default=DEFAULT_JUDGE_FALLBACK,
                             help="the judge for a run the main judge declines ('' for none)")
        command.add_argument("--judge-workers", type=int, default=4)
        command.add_argument("--no-judge", action="store_true", help="deterministic checks only")
        command.add_argument("--claude-api", action="store_true", help="use ANTHROPIC_API_KEY instead of Bedrock")

    run = sub.add_parser("run", help="run the agent on the scenarios and grade it")
    run.add_argument("--split", default="dev", choices=["dev", "holdout", "all"])
    run.add_argument("--only", help="comma-separated scenario ids or families (overrides --split)")
    run.add_argument("--reps", type=int, default=3)
    run.add_argument("--model", default=DEFAULT_MODEL, help="the model the agent runs on, as Claude Code takes it")
    run.add_argument("--effort", choices=["low", "medium", "high", "xhigh", "max"])
    run.add_argument("--surface", default="agent", choices=["agent", "main"],
                     help="agent: the porygon agent; main: the main thread with the porygon-flow skill")
    run.add_argument("--plugin-dir", default=str(ROOT), help="the plugin to test, e.g. a worktree with a prompt change")
    run.add_argument("--label", help="results folder name (default: a timestamp)")
    run.add_argument("--out", help=f"parent folder for results (default: {OUTPUT.relative_to(ROOT)})")
    run.add_argument("--workers", type=int, default=4)
    run.add_argument("--timeout", type=int, default=RUN_TIMEOUT)
    run.add_argument("--attempts", type=int, default=3, help="tries per run when the plumbing fails")
    run.add_argument("--max-budget-usd", type=float, default=0.5, help="cap per run, passed to claude")
    run.add_argument("--budget", type=float, default=10.0, help="stop runs and judging past this total, in USD")
    run.add_argument("--skip-preflight", action="store_true")
    judge_options(run)
    regrade = sub.add_parser("grade", help="grade the saved transcripts of a run again")
    regrade.add_argument("dir")
    judge_options(regrade)
    report = sub.add_parser("report", help="print a run's report")
    report.add_argument("dir")
    compare = sub.add_parser("compare", help="compare two runs")
    compare.add_argument("before")
    compare.add_argument("after")
    show = sub.add_parser("show", help="one scenario's transcripts and failures")
    show.add_argument("dir")
    show.add_argument("scenario")
    build = sub.add_parser("build", help="write every scenario's files")
    build.add_argument("dir")
    check = sub.add_parser("judge-check", help="the judge against hand-labelled answers")
    judge_options(check)
    args = parser.parse_args(argv)
    commands = {"run": command_run, "grade": command_grade, "report": command_report, "compare": command_compare,
                "show": command_show, "build": command_build, "judge-check": command_judge_check}
    if not shutil.which("claude") and args.command == "run":
        raise SystemExit("the claude CLI isn't on PATH")
    return commands[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
