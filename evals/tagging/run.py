"""Eval for `porygon tag`: the real tagging path on frozen public text, graded against hand labels (gold.yaml).

    uv run python -m evals.tagging.run freeze                       # fetch CVE.org/NVD text once (free)
    AWS_PROFILE=... AWS_REGION=eu-west-1 \\
        uv run python -m evals.tagging.run run --variant v0 --split train --bedrock [--reps 3]
    uv run python -m evals.tagging.run report

Each run writes its per-case output to evals/tagging/results/<variant>-<split>.json and a line to the ledger. The
texts stay in the gitignored .cache/eval-tagging/ and every load checks them against sources.json.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import statistics
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from evals.bedrock import close_llm, judge_llm
from porygon_mitigator.config import Settings
from porygon_mitigator.flow.models import Environment, VulnerabilityProfile
from porygon_mitigator.intel.facts import gather_facts
from porygon_mitigator.sources.net import Http
from porygon_mitigator.tagging import (
    DEFAULT_TAG_EFFORT,
    DEFAULT_TAG_MODEL,
    TagInput,
    inputs_from_environment,
    record_text,
    tag,
)

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
FROZEN = ROOT / ".cache" / "eval-tagging"
SOURCES = HERE / "sources.json"
PROMPTS = HERE / "prompts"
RESULTS = HERE / "results"
LEDGER = HERE / "ledger.jsonl"
LAB_ENVIRONMENT = ROOT / "demo" / "tenable-lab" / "flow" / "environment.json"
WRONG_CLASS_WEIGHT = 2  # a wrong class misleads a reader; an empty one only tells them less


@dataclass
class Case:
    cve: str
    split: str
    classes: list[str]
    processes: list[str]
    protocols: list[str]


def load_gold() -> list[Case]:
    rows = yaml.safe_load((HERE / "gold.yaml").read_text(encoding="utf-8"))["cases"]
    return [Case(row["cve"], row["split"], row["class"], row["processes"], row["protocols"]) for row in rows]


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


async def freeze(cases: list[Case]) -> None:
    FROZEN.mkdir(parents=True, exist_ok=True)
    hashes: dict[str, str] = {}
    async with Http() as http:
        for case in cases:
            facts = await gather_facts(case.cve, http, Settings())
            frozen = {"text": record_text(facts), "vector": facts.cvss.vector if facts.cvss and facts.cvss.vector
                      else ""}
            body = json.dumps(frozen, sort_keys=True)
            (FROZEN / f"{case.cve}.json").write_text(body, encoding="utf-8")
            hashes[case.cve] = _sha(body)
            print(f"{case.cve}: {len(frozen['text'])} chars", file=sys.stderr)
    SOURCES.write_text(json.dumps(dict(sorted(hashes.items())), indent=1) + "\n", encoding="utf-8")


def inputs_for(cases: list[Case]) -> dict[str, TagInput]:
    """The frozen public record, plus the lab's scanner text for CVEs the lab has, as `porygon tag` would build.
    Without the lab's environment, which is built locally and never committed, each case gets its public record only."""
    hashes = json.loads(SOURCES.read_text(encoding="utf-8"))
    lab: dict[str, TagInput] = {}
    if LAB_ENVIRONMENT.exists():
        lab = inputs_from_environment(Environment.model_validate_json(LAB_ENVIRONMENT.read_text(encoding="utf-8")))
    else:
        print("no lab environment here, so each case gets its public record only", file=sys.stderr)
    inputs: dict[str, TagInput] = {}
    for case in cases:
        body = (FROZEN / f"{case.cve}.json").read_text(encoding="utf-8")
        if _sha(body) != hashes.get(case.cve):
            raise SystemExit(f"{case.cve}: frozen text changed or missing; run `freeze` again")
        frozen = json.loads(body)
        item = lab.get(case.cve) or TagInput(case.cve)
        item.texts.insert(0, frozen["text"])
        item.vector = item.vector or frozen["vector"]
        inputs[case.cve] = item
    return inputs


def _names(values: list[str]) -> set[str]:
    return {value.strip().lower().removesuffix(".exe") for value in values if value.strip()}


def grade_case(case: Case, profile: VulnerabilityProfile | None, item: TagInput) -> dict[str, Any]:
    produced = profile.vulnerability_class if profile else ""
    processes = profile.processes if profile else []
    protocols = profile.protocols if profile else []
    return {
        "cve": case.cve,
        "class": produced,
        "class_ok": bool(produced) and produced in case.classes,
        "class_wrong": bool(produced) and produced not in case.classes,
        "process_hit": bool(_names(processes) & _names(case.processes)) if case.processes else None,
        "protocol_hit": bool(_names(protocols) & _names(case.protocols)) if case.protocols else None,
        "processes": processes,
        "protocols": protocols,
        "missing": profile is None,
    }


def _rate(rows: list[dict[str, Any]], key: str) -> float | None:
    scored = [row[key] for row in rows if row[key] is not None]
    return round(sum(scored) / len(scored), 3) if scored else None


def summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    n = len(rows)
    correct = sum(row["class_ok"] for row in rows)
    wrong = sum(row["class_wrong"] for row in rows)
    return {
        "cases": n,
        "score": round((correct - WRONG_CLASS_WEIGHT * wrong) / n, 3) if n else 0.0,
        "class_correct": round(correct / n, 3) if n else 0.0,
        "class_wrong": round(wrong / n, 3) if n else 0.0,
        "class_empty": round(sum(not row["class"] for row in rows) / n, 3) if n else 0.0,
        "process_recall": _rate(rows, "process_hit"),
        "protocol_recall": _rate(rows, "protocol_hit"),
        "missing": sum(row["missing"] for row in rows),
    }


async def run_variant(variant: str, split: str, model: str, bedrock: bool, reps: int,
                      effort: str = DEFAULT_TAG_EFFORT, label: str = "") -> dict[str, Any]:
    system = (PROMPTS / f"{variant}.md").read_text(encoding="utf-8").strip()
    cases = [case for case in load_gold() if split == "all" or case.split == split]
    reps_out = []
    cost = 0.0
    for rep in range(reps):
        inputs = inputs_for(cases)
        llm = judge_llm(Settings(), bedrock)
        try:
            result = await tag(inputs, Settings(), model=model, llm=llm, system=system, effort=effort)
        finally:
            await close_llm(llm)
        cost += result.cost_usd
        rows = [grade_case(case, result.profiles.get(case.cve), inputs[case.cve]) for case in cases]
        reps_out.append({"rep": rep, "summary": summarize(rows), "rows": rows, "notes": result.notes,
                         "rejected": result.rejected})
    scores = [rep["summary"]["score"] for rep in reps_out]
    report = {
        "variant": variant, "split": split, "model": model, "effort": effort, "reps": reps,
        "score_mean": round(statistics.mean(scores), 3),
        "score_stdev": round(statistics.stdev(scores), 3) if len(scores) > 1 else 0.0,
        "summaries": [rep["summary"] for rep in reps_out],
        "cost_usd": round(cost, 4),
        "at": datetime.now(UTC).isoformat(timespec="seconds"),
        "runs": reps_out,
    }
    RESULTS.mkdir(exist_ok=True)
    (RESULTS / f"{label or variant}-{split}.json").write_text(json.dumps(report, indent=1) + "\n", encoding="utf-8")
    with LEDGER.open("a", encoding="utf-8") as ledger:
        ledger.write(json.dumps({key: report[key] for key in report if key != "runs"}) + "\n")
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="evals.tagging.run")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("freeze")
    run = sub.add_parser("run")
    run.add_argument("--variant", required=True, help="a prompt in evals/tagging/prompts/")
    run.add_argument("--split", choices=["train", "test", "all"], default="train")
    run.add_argument("--model", default=DEFAULT_TAG_MODEL)
    run.add_argument("--reps", type=int, default=1)
    run.add_argument("--bedrock", action="store_true")
    run.add_argument("--effort", default=DEFAULT_TAG_EFFORT, choices=["low", "medium", "high", "max"])
    run.add_argument("--label", default="", help="results file name (default: the variant)")
    sub.add_parser("report")
    args = parser.parse_args(argv)
    if args.command == "freeze":
        asyncio.run(freeze(load_gold()))
    elif args.command == "run":
        report = asyncio.run(run_variant(args.variant, args.split, args.model, args.bedrock, args.reps,
                                         args.effort, args.label))
        print(json.dumps({key: report[key] for key in report if key != "runs"}, indent=1))
    elif not LEDGER.exists():
        print("no runs recorded yet: each `run` adds a line to evals/tagging/ledger.jsonl")
    else:
        for line in LEDGER.read_text(encoding="utf-8").splitlines():
            row = json.loads(line)
            print(f"{row['variant']:12} {row.get('model', '')[7:]:10} {row.get('effort', 'low'):6} {row['split']:5} "
                  f"reps={row['reps']} score={row['score_mean']:+.3f}"
                  f"±{row['score_stdev']:.3f} {row['summaries'][0]} ${row['cost_usd']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
