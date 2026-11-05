"""Renderers for assessments: Markdown for people, JSON for machines."""

from porygon_mitigator.models.assessment import MachineAssessment
from porygon_mitigator.report.markdown import render_markdown


def render_json(assessment: MachineAssessment) -> str:
    return assessment.model_dump_json(indent=2) + "\n"


__all__ = ["render_json", "render_markdown"]
