"""The eval harness must grade what it claims to: tagging classes and what a transcript shows."""

import json
from typing import Any

import pytest


def test_tagging_grader_weights_a_wrong_class_over_an_empty_one() -> None:
    from evals.tagging.run import Case, grade_case, load_gold, summarize

    from porygon_mitigator.flow.models import VulnerabilityProfile
    from porygon_mitigator.tagging import TagInput

    case = Case("CVE-2020-1350", "train", ["server"], ["dns.exe"], ["dns"])
    item = TagInput("CVE-2020-1350", ["Windows DNS Server RCE on 53/udp"])
    right = grade_case(case, VulnerabilityProfile(cve=case.cve, vulnerability_class="server", processes=["DNS"],
                                                  protocols=["DNS"]), item)
    wrong = grade_case(case, VulnerabilityProfile(cve=case.cve, vulnerability_class="client"), item)
    empty = grade_case(case, None, item)
    assert right["class_ok"] and right["process_hit"]
    assert summarize([right, empty])["score"] == 0.5
    assert summarize([right, wrong])["score"] == -0.5
    gold = load_gold()
    assert len({case.cve for case in gold}) == len(gold)
    assert {case.split for case in gold} == {"train", "test"}


@pytest.mark.parametrize(
    ("result", "field", "expected"),
    [
        pytest.param({"open": None}, "open", "null", id="null"),
        pytest.param({"open": True, "paths": []}, "open", "true", id="followed-by-more"),
        pytest.param({"verdict": "stops the same as it"}, "verdict", "stops the same as it", id="text"),
    ],
)
@pytest.mark.parametrize("wrap", [json.dumps, lambda text: json.dumps(json.dumps(text))], ids=["plain", "escaped"])
def test_a_tool_field_is_read_however_the_transcript_quotes_it(
    result: dict[str, Any], field: str, expected: str, wrap: Any
) -> None:
    from evals.flow.agent_eval import _tool_field

    assert _tool_field(str(wrap(result)), field) == expected


def _stream(*events: tuple[str, dict[str, Any], dict[str, Any]]) -> str:
    lines = []
    for index, (tool, arguments, result) in enumerate(events):
        name = f"mcp__plugin_porygon-mitigator_porygon__{tool}"
        call = {"type": "tool_use", "id": str(index), "name": name, "input": arguments}
        lines.append(json.dumps({"type": "assistant", "message": {"content": [call]}}))
        content = [{"type": "text", "text": json.dumps(result)}]
        answer = {"type": "tool_result", "tool_use_id": str(index), "content": content}
        lines.append(json.dumps({"type": "user", "message": {"content": [answer]}}))
    return "\n".join(lines)


def test_a_transcript_keeps_each_tools_output_apart() -> None:
    from evals.flow.agent_eval import _tool_field, parse_stream

    stream = _stream(
        ("flow_check_path", {"source_zone": "corp", "host": "dc-01"}, {"open": None}),
        ("flow_reachability", {}, {"open": [{"host": "x"}]}),
    )
    outputs = parse_stream(stream, "scenario", 0).tool_outputs
    assert [item["tool"] for item in outputs] == ["flow_check_path", "flow_reachability"]
    assert _tool_field(outputs[0]["text"], "open") == "null"


@pytest.mark.parametrize(
    ("answer", "final", "expected"),
    [
        pytest.param("null", "I can't tell: dc-01 can't be judged.", True, id="cant-tell"),
        pytest.param("null", "No path doesn't mean closed, so I can't tell.", True, id="repeats-the-tool"),
        pytest.param("null", "No path to dc-01, so it is closed and safe. Patch unknown.", False, id="reads-safe"),
        pytest.param("true", "Yes, corp can reach dc-01.", True, id="open"),
        pytest.param("true", "dc-01 is a domain controller.", False, id="no-answer"),
        pytest.param("false", "No, there's no open path.", True, id="closed"),
        pytest.param("false", "Yes it can.", False, id="wrong"),
    ],
)
def test_the_path_check_needs_the_answer_the_tool_gave(answer: str, final: str, expected: bool) -> None:
    from evals.flow.agent_eval import _answers_the_path_check

    assert _answers_the_path_check(answer, final) is expected


@pytest.mark.parametrize(
    ("verdict", "final", "expected"),
    [
        pytest.param("stops the same as the recommendation", "It stops the same.", True, id="same"),
        pytest.param("stops less than the recommendation", "It stops the same.", False, id="wrong-comparison"),
        pytest.param("not usable as it is", "Go ahead: it won't break anything.", False, id="reads-usable"),
        pytest.param("not usable as it is", "It's not usable: it breaks payroll.", True, id="unusable"),
    ],
)
def test_the_set_check_needs_the_verdict_the_tool_gave(verdict: str, final: str, expected: bool) -> None:
    from evals.flow.agent_eval import _answers_the_set_check

    assert _answers_the_set_check(verdict, final) is expected
