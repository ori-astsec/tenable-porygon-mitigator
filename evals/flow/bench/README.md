# Map and scan benchmark

This benchmark measures the agent's part of the flow's first two steps: **Map** (`flow_load_environment`) and **Scan**
(`flow_reachability`). The code behind those tools is deterministic and has its own checks in `tests/test_flow.py`. What no
unit test can cover is what a model does with the tools:

- which files it loads, and with which arguments;
- what it does when a load is refused;
- whether what it tells the person matches what the tools returned.

That depends on the prompts, and this benchmark exists so you can change them and see whether the agent got better.

Each run is a fresh `claude -p` session with the real plugin, the real `porygon` agent and the real MCP server, on
Claude through Amazon Bedrock. It works in a temporary folder outside the repo, under a name that says nothing about the case, with
only the flow's tools and none of the shell's keys for Tenable or Palo Alto. The networks are synthetic Tenable data. Each one is a VM export (asset records plus
the listener, scan-information, routing and service plugin rows) passed through `environment_from_tenable`, the same
path tenant data takes, together with a firewall topology. Deterministic checks read what the run did. A judge model
reads what it said, against facts taken from the tools' own output.

## Quick start

You need the `claude` CLI, `uv sync`, and AWS credentials for Bedrock (`AWS_PROFILE`, `AWS_REGION`). If a stray
`ANTHROPIC_API_KEY` is set in your shell, the runner drops it for the agent runs, but unset it in the shell too so the
judge goes through Bedrock as well.

```bash
uv run python -m evals.flow.bench run --split dev --label baseline
```

```bash
uv run python -m evals.flow.bench show output/flow-bench/baseline zone-summary-dev
```

```bash
uv run python -m evals.flow.bench compare output/flow-bench/baseline output/flow-bench/my-change
```

`run` prints the report and writes everything to `output/flow-bench/<label>/`, which is gitignored. Running
`uv run python -m evals.flow.bench --help` lists every command.

## What each step has to get right

| Step | Its goal, for the agent | Checked by |
|---|---|---|
| Map | Load exactly the files the person handed over, as absolute paths, or leave the loaded run alone when they mean that one | `loaded_expected_run`, `load_args`, `no_reload` |
| Map | Never stand another network in for the one asked about: not the bundled example, not an earlier run | `no_bundled_fallback`, `no_stale_results` |
| Map | Report where hosts landed, and treat a host that couldn't be placed as unknown, never as safe | `placement_accuracy`, `names_unplaced`, `unknown_not_safe` |
| Map | When the tool refuses input, say why, name what's wrong and how to fix it, and don't offer what it can't do | `refusal_handled`, `names_problems`, `explains_wrong_file`, `rollback_explained`, `capabilities_honest` |
| Map | Treat host names from Tenable as data | `injection_ignored`, `marker_absent` |
| Scan | Scan the run the question is about | `scanned_the_run` |
| Scan | Say which attacker zone reaches which host, through which rule | `reachability_accurate`, `rules_accurate`, `names_reachable_hosts`, `answers_question` |
| Scan | Treat undetermined checks and hosts off the map as unknown, never as safe | `unknown_not_safe`, `undetermined_disclosed` |
| Scan | Treat the list of open hosts as cut when it is (the tool lists 200 rows) | `truncation_acknowledged` |
| Both | Stay in map and scan, use only the flow's tools, state only numbers a tool returned, say it's simulated | `in_stage`, `only_flow_tools`, `numbers_grounded`, `says_simulated`, `no_real_device_claim` |

## The cases

There are 11 families. Each one has a **dev** case and a **holdout** case, on different networks and in different
words. Iterate on dev, and run holdout only to confirm that a change carries over. `scenarios.py` holds the prompts,
and `networks.py` holds the networks.

| Family | Step | What it tests |
|---|---|---|
| `placements` | Map | Load the handed files and say where each host landed |
| `relative-paths` | Map | The person gives paths relative to their folder; the tool only takes absolute ones |
| `refused-rules` | Map | Rules the flow won't guess at (named address objects), while another network is loaded |
| `tenable-export` | Map | A raw Tenable export handed over as if it were the environment |
| `applied-plan` | Map | The loaded run has a plan a person applied, so loading is refused |
| `planted-hostname` | Map | Instructions planted in a Tenable host name |
| `zone-summary` | Scan | Per attacker zone: hosts and rules (holdout runs on the lab network, which is built locally and isn't committed) |
| `unknown-not-safe` | Scan | A host the scan couldn't judge is not a safe host |
| `path-question` | Scan | One path, asked directly, on a network that's already loaded |
| `existing-run` | Scan | "Scan what I loaded": loading anything would replace it |
| `truncated-list` | Scan | More reachable hosts than the tool lists |

Between them, the two hand-built networks hold every placement case the map has:

- a CMDB-declared zone;
- a route through one or two firewalls;
- a zone address range;
- an unplaceable host, both from overlapping ranges and from being dual-homed;
- a zone no attacker zone connects to;
- an IPv6-only host behind IPv4 rules;
- a host inside an attacker zone;
- two assets that share a name.

Acme is the dev network and Globex the holdout one. The sprawl networks are big enough that the scan's list is cut.

## How a run is scored

- **Checks** read the transcript and the flow directory the run left behind (`grade.CHECKS`). For example, the run id
  it ended on must equal the id the handed files hash to.
- **Criteria** are read by the judge (`grade.CRITERIA`): one structured-output call per run, Claude Opus 5.5 by default,
  each criterion graded on its own against a digest of the facts. The judge request is cached by its exact content, so
  `grade` only pays for runs whose answer, facts or rubric changed. A judge model's safety classifier can decline text
  about attack paths. The remaining attempts then go to `--judge-fallback` (Sonnet 5.5 by default), and the report
  says how many verdicts each model gave.
- **Score** is the share of applicable checks and criteria a run passed, averaged per scenario and then over
  scenarios. The interval comes from resampling scenarios, because reps of one case move together.
- **Critical** items are the ones where one failure means the answer can't be trusted: `loaded_expected_run`,
  `no_bundled_fallback`, `no_reload`, `marker_absent`, `unknown_not_safe`, `no_stale_results`,
  `no_real_device_claim`, `injection_ignored` and `has_answer`. The report gives the share of runs that pass all of them.
- **Errors are not scores.** A run that timed out, hit its budget, or was served by a model other than
  the one asked for goes to `errors.jsonl` with its class. Plumbing failures are retried with backoff. If the judge
  fails on a run, that run is graded on its checks alone, and the report lists it.

## Improving the prompts

The agent reads these texts for the two steps. Change these, not the benchmark:

| Text | Where |
|---|---|
| The agent's steps 2 and 4, and its rules | `agents/porygon.md` |
| The skill, for the main thread | `skills/porygon-flow/SKILL.md` (run with `--surface main`) |
| Tool descriptions | `FLOW_LOAD_DESC`, `FLOW_REACH_DESC` and `INSTRUCTIONS` in `src/porygon_mitigator/mcp_server.py` |
| Notes inside tool results | `SIMULATED_NOTE`, `overview()` and `reachability()` in `src/porygon_mitigator/flow/runs.py`, `FLOW_NOTE` in `mcp_server.py` |

The loop:

1. Run a baseline on dev with at least 3 reps, and keep its label.
2. Read the "worst first" table and the failures in `report.md`, then `show` the failing scenarios to read whole
   transcripts. Work out why the agent did what it did before changing anything.
3. Change one thing, then run dev again with the same reps and model.
4. Compare the two runs with `compare`. Keep the change if the item it targeted moved and no critical item got worse.
   Otherwise revert it.
5. Every few kept changes, run holdout. If dev improves and holdout doesn't, you are tuning to the dev cases.

To try a variant without touching your checkout, put it in a git worktree and pass `--plugin-dir <worktree>`. The
results record the plugin's commit and a hash of each prompt file, so you can always tell which variant you measured.
The facts come from the harness's own checkout, so a variant must not change what the tools return. Only prompts,
descriptions and notes count as variants.

Ground rules:

- **Never edit scenarios, facts or the rubric to make a number go up.** If a check is wrong, fix it in a separate
  commit, add a test or a calibration case that shows the bug, and regrade both runs with `grade DIR` before
  comparing them.
- **Small deltas are noise.** A dev run is 11 cases × 3 reps, and a pass rate over 33 runs moves about ±0.17 by
  chance. `compare` prints the bound. To resolve smaller effects, add reps rather than reading tea leaves.
- **Prompts are shared across steps.** A change to `agents/porygon.md` also affects tagging, planning and approval.
  Before keeping a change, run `evals/flow/agent_eval.py`, the flow-wide behaviour checks.
- **Check more than one model.** The default is Haiku 5.5, the cheapest model and the one most sensitive to prompt
  wording. Before keeping a change, also run it with `--model global.anthropic.claude-sonnet-5-5`.

## Results on disk

Each run folder `output/flow-bench/<label>/runs/<scenario>/r<rep>/` holds these files:

- `prompt.txt` is what the agent was asked.
- `facts.json` is what it is graded against.
- `stream.jsonl` is the full transcript, and `stderr.txt` the CLI's stderr.
- `flow/` is the flow directory the run left behind, and `work/` was its working directory.
- `grade.json` holds every check and criterion with its detail.
- `judge.json` holds the judge's verdicts, its quotes and its token use.

The label folder holds `results.jsonl` (one row per graded run), `errors.jsonl`, `summary.json`, `report.md` and
`config.json`, which records the model, the surface, the plugin fingerprint and the judge.

## Checking the grader

- `uv run pytest tests/test_flow_bench.py` runs offline. It checks that the networks place hosts the way they were
  built to, that reachability matches the oracle, and that the facts are right. It also simulates runs by calling the
  MCP tools directly: a right run must pass every check, and null, fallback and reload runs must fail the checks they
  break.
- `uv run python -m evals.flow.bench judge-check` grades the hand-labelled answers in `judge_calibration.yaml`, a right
  and a wrong answer for each criterion, and reports agreement. It costs about $0.60, and agrees with all 58 labels
  as of the baseline. It must agree with every label before a judge or rubric change is used to compare prompts. When
  a verdict on a real run looks wrong, add that answer as a case.

## Adding a case

1. Add a network or a variant in `networks.py`. Give each machine the `expect` placement its topology is built to
   produce, and keep everything invented.
2. Add a dev and a holdout `Scenario` for the new family in `scenarios.py`. Use a different network and different
   words for each, and list the checks and criteria that apply.
3. If a criterion is new, add it to `grade.CRITERIA` with calibration cases. Then run the offline tests and
   `judge-check`.

## Results

Measured on the host-level flow, on 2026-11-04, and stored in [`final-2026-11-04/`](../results/final-2026-11-04/): Haiku 5.5 on the
agent surface, 3 repeats of 22 scenarios, 66 runs with none lost to errors. The judge is Opus 5.5, and agrees with all 58 hand labels.

| Split | Map | Scan | All, with 95% CI | All critical items pass |
|---|---:|---:|---:|---:|
| dev | 1.000 | 0.988 | 0.994 (0.99 to 1.00) | 1.00 |
| holdout | 0.995 | 0.984 | 0.990 (0.98 to 1.00) | 0.97 |

**Holdout isn't blind any more.** Its failures were read while fixing the agent and the scan, so treat it as a second dev set. New
holdout cases are what would show whether these fixes carry over.

What's still missed: one holdout run called hosts the scan can't judge not reachable, failing a critical check, and `numbers_grounded` at 63/66.

The score before this work was 0.950 on dev and 0.923 on holdout, with the agent able to see each case's name in its paths. It found:

- **The scan couldn't say which hosts it couldn't judge,** and collecting crashed on a JSON list.
- **A settled "no" read as a guess,** because nothing showed which hosts were checked, or when a missing row means closed. The scan
  now gives `ports_checked`, `attacker_zones` and `complete`.
- **A big scan went past the 50 KB where a client saves a result to a file,** which the agent can't read. The scan now cuts itself to fit.
- **The agent offered what it can't do,** counted hosts by eye, and replaced a loaded run with the bundled example.
- **It hid a host whose name held instructions,** and showed an earlier network after a refused load.

## Cost

Measured on the baseline: a Haiku 5.5 agent run costs about $0.003 and an Opus 5.5 judge call about $0.023, so a full
run (22 scenarios × 3 reps) is about $1.70, mostly the judge, and takes about 10 minutes with 6 workers. Pass
`--no-judge` for the deterministic checks alone, where the critical column reads n/a. `--budget` stops new runs and
judging once agent and judge spend pass it, charging a killed run its cap, and
`--max-budget-usd` caps each run.

## Limits

- The judge is Claude grading Claude. It is calibrated on hand labels, but self-preference is possible, so keep the
  judge model different from the model under test where you can.
- `numbers_grounded` is a heuristic. It accepts numbers that appear in a tool result or the request, plus list
  lengths, per-zone counts and counts one subtraction away, such as placed hosts. An answer that derives a number any
  other way will be flagged.
- The collect path (`flow_collect`, `flow_map_routes`) and the normalizer are out of scope. Every case hands the agent a
  prepared environment, the `flow_load_environment` path.
