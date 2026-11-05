"""What the extractor reads: one normalised text document per source, plus a status record per attempt."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Literal

from porygon_mitigator.models.common import SourceStatusValue
from porygon_mitigator.models.cve import SourceRecord
from porygon_mitigator.models.mitigation import SourceKind

Origin = Literal["structured_api", "template", "reference", "search", "catalog", "gap_fill"]


@dataclass
class SourceDoc:
    url: str  # what a person opens to check the evidence
    publisher: str
    origin: Origin
    source_kind: SourceKind
    text: str  # normalised; the extractor reads exactly this and the verifier searches exactly this
    fetched_url: str = ""
    fetched_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    priority: int = 50

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.text.encode("utf-8")).hexdigest()


@dataclass
class SourceAttempt:
    url: str
    publisher: str
    origin: Origin
    source_kind: SourceKind
    status: SourceStatusValue
    note: str | None = None
    fetched_at: datetime | None = None
    content_sha256: str | None = None
    mitigations: int = 0

    def record(self) -> SourceRecord:
        return SourceRecord(
            url=self.url,
            publisher=self.publisher,
            origin=self.origin,
            source_kind=self.source_kind,
            status=self.status,
            fetched_at=self.fetched_at,
            content_sha256=self.content_sha256,
            mitigations=self.mitigations,
            note=self.note,
        )


def error_status(status_code: int | None, reason: str = "") -> SourceStatusValue:
    """How a failed fetch is recorded: a 404 means the source has no entry; policy skips are 'skipped'."""
    if status_code == 404:
        return "not_listed"
    if any(word in reason for word in ("registry", "binary", "large")):
        return "skipped"
    return "unreachable"


def attempt_for(doc: SourceDoc, status: SourceStatusValue = "ok", note: str | None = None) -> SourceAttempt:
    return SourceAttempt(
        url=doc.url,
        publisher=doc.publisher,
        origin=doc.origin,
        source_kind=doc.source_kind,
        status=status,
        note=note,
        fetched_at=doc.fetched_at,
        content_sha256=doc.sha256,
    )
