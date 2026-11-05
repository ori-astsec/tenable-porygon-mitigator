"""LLM arbiter for the few duplicates that action keys and wording can't settle (records whose action stayed
'other'). One call per CVE at most; any answer that doesn't cover the candidates exactly is ignored."""

from __future__ import annotations

import json

from pydantic import BaseModel, Field

from porygon_mitigator.extract.dedupe import merge_group
from porygon_mitigator.extract.llm import Llm
from porygon_mitigator.extract.prompts import ARBITER_SYSTEM
from porygon_mitigator.models.mitigation import Mitigation


class DuplicateGroups(BaseModel):
    groups: list[list[str]] = Field(description="Each inner list holds the ids of records that are the same action.")


async def arbitrate(llm: Llm, cve_id: str, items: list[Mitigation], ambiguous: list[list[Mitigation]]) -> list[
        Mitigation]:
    if not ambiguous:
        return items
    involved = {item.id: item for pair in ambiguous for item in pair}
    payload = [
        {"id": item.id, "type": item.type, "title": item.title, "summary": item.summary,
         "steps": [step.text for step in item.steps][:6]}
        for item in involved.values()
    ]
    user = (f"Mitigation records for {cve_id}. Group the ids that describe the same action; every id must appear in "
            f"exactly one group (a group may have one id).\n\n{json.dumps(payload, indent=1)}")
    result = await llm.parse(system=ARBITER_SYSTEM, user=user, output_format=DuplicateGroups, effort="low",
                             max_tokens=4000)
    if result.parsed is None:
        return items
    groups = [[mid for mid in group if mid in involved] for group in result.parsed.groups]
    flat = [mid for group in groups for mid in group]
    if sorted(flat) != sorted(involved) or len(flat) != len(set(flat)):
        return items  # incomplete or invented ids: keep everything
    merged_ids: set[str] = set()
    merged: list[Mitigation] = []
    for group in groups:
        if len(group) > 1:
            merged.append(merge_group([involved[mid] for mid in group]))
            merged_ids.update(group)
    return [item for item in items if item.id not in merged_ids] + merged
