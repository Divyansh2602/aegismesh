"""Data model for provenance-tagged context.

A ContextTrace is the proxy's record of exactly what the model saw on one request, split
into segments with a provenance class and a byte span. Phase 2's attribution engine
ablates these segments, so the spans must be exact.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, Field

from aegis.common.hashing import hash_text
from aegis.common.ids import segment_id, trace_id
from aegis.provenance.classes import ProvenanceClass, min_trust

SourceKind = Literal[
    "user_input",
    "system",
    "tool_response",
    "tool_description",
    "memory_recall",
    "agent_message",
]


def _now() -> datetime:
    return datetime.now(UTC)


class SegmentSource(BaseModel):
    """Where a segment came from, in enough detail to audit it later."""

    kind: SourceKind
    origin: str | None = None
    """Stable identifier of the producer, e.g. ``mcp://vendor.example/invoice_reader``."""

    retrieved_at: datetime = Field(default_factory=_now)
    content_hash: str


class Span(BaseModel):
    """Byte offsets into the assembled context string."""

    start: int
    end: int

    @property
    def length(self) -> int:
        return self.end - self.start


class MessageLocator(BaseModel):
    """Where a segment lives inside the original request, so it can be removed.

    Ablation has to reconstruct a *request*, not a flattened string -- the model's
    behaviour depends on message structure, so ablating by rewriting a concatenated blob
    would measure the wrong thing.

    ``start``/``end`` are character offsets into that message's content. ``whole_message``
    marks segments that were synthesised from a message rather than sliced out of it (a
    tool result, an assistant turn with tool calls), where the only faithful ablation is
    to drop the message entirely.
    """

    kind: Literal["message"] = "message"
    message_index: int
    start: int = 0
    end: int = 0
    whole_message: bool = False


class ToolLocator(BaseModel):
    """A segment that came from a tool *declaration* rather than a message."""

    kind: Literal["tool"] = "tool"
    tool_name: str


Locator = MessageLocator | ToolLocator


class Segment(BaseModel):
    """One provenance-classified piece of the model's context."""

    segment_id: str = Field(default_factory=segment_id)
    cls: ProvenanceClass = Field(alias="class")
    source: SegmentSource
    span: Span
    text: str
    locator: Locator | None = None
    """How to remove this segment from the original request. Required for ablation."""

    parent_segments: list[str] = Field(default_factory=list)
    """For agent-generated segments: the segments that causally influenced this one."""

    classification_reason: str = ""
    """Why this class was assigned. Auditors need this; so do we when debugging."""

    model_config = {"populate_by_name": True}

    def redacted(self) -> dict:
        """Serializable form with content replaced by its hash.

        Warrants cross organizational boundaries, so they must never carry the text of
        documents the agent read. See SPEC.md section 4.1.
        """
        data = self.model_dump(by_alias=True, mode="json")
        data.pop("text", None)
        data["text_hash"] = hash_text(self.text)
        return data


class ContextTrace(BaseModel):
    """Everything the proxy observed for a single model request."""

    trace_id: str = Field(default_factory=trace_id)
    created_at: datetime = Field(default_factory=_now)
    mandate_id: str | None = None
    principal: str | None = None
    model: str = ""
    segments: list[Segment] = Field(default_factory=list)
    assembled_context: str = ""
    upstream_response: dict | None = None

    def segment_by_id(self, sid: str) -> Segment | None:
        return next((s for s in self.segments if s.segment_id == sid), None)

    def classes_present(self) -> set[ProvenanceClass]:
        return {s.cls for s in self.segments}

    def bytes_by_class(self) -> dict[ProvenanceClass, int]:
        """Context bytes attributable to each class.

        A crude exposure measure, but a useful one: an agent whose context is 80 percent
        untrusted external content is a different risk profile from one at 5 percent,
        before any attribution runs.
        """
        totals: dict[ProvenanceClass, int] = {}
        for seg in self.segments:
            totals[seg.cls] = totals.get(seg.cls, 0) + seg.span.length
        return totals

    def derive_agent_class(self, parent_ids: list[str]) -> ProvenanceClass:
        """Apply the monotonicity rule to an agent-generated segment.

        Parent ids that do not resolve are ignored rather than defaulted, because
        ``min_trust`` already fails safe on an empty list -- but an unresolvable parent is
        a bug worth surfacing, so it is recorded by the caller.
        """
        parent_classes = [
            seg.cls for pid in parent_ids if (seg := self.segment_by_id(pid)) is not None
        ]
        return min_trust(parent_classes)
