"""Turn an OpenAI-style chat request into provenance-classified segments.

Classification rules (docs/SPEC.md section 2):

    system role      -> P1  system-policy
    user role        -> P0  only the span matching the authenticated mandate; rest P3
    assistant role   -> P4  class derived from causal parents via the monotonicity rule
    tool role        -> P2  if the tool is pinned, else P3
    tool declaration -> P2  if pinned and description hash matches, else P3

The user-role rule is the one that matters and the one that is easy to get wrong. Agent
frameworks routinely paste retrieved documents into user messages, so ``role == "user"``
does not mean "a human said this". Only text the integrator declared as the mandate gets
P0. Everything else defaults to untrusted (classes.DEFAULT_CLASS).
"""

from __future__ import annotations

from aegis.common.hashing import hash_text
from aegis.provenance.classes import DEFAULT_CLASS, ProvenanceClass, min_trust
from aegis.provenance.models import (
    ContextTrace,
    Locator,
    MessageLocator,
    Segment,
    SegmentSource,
    Span,
    ToolLocator,
)
from aegis.provenance.registry import MandateContext, ToolRegistry

_SEPARATOR = "\n"


class ContextClassifier:
    """Builds a ContextTrace from a chat-completions request body."""

    def __init__(
        self,
        registry: ToolRegistry | None = None,
        mandate: MandateContext | None = None,
    ) -> None:
        self.registry = registry or ToolRegistry()
        self.mandate = mandate

    # ---------------------------------------------------------------- public

    def classify(self, body: dict) -> ContextTrace:
        trace = ContextTrace(
            model=body.get("model", ""),
            mandate_id=self.mandate.mandate_id if self.mandate else None,
            principal=self.mandate.principal if self.mandate else None,
        )
        cursor = 0
        parts: list[str] = []

        for segment, text in self._tool_declaration_segments(body):
            cursor = self._append(trace, parts, segment, text, cursor)

        for index, message in enumerate(body.get("messages", [])):
            for segment, text in self._message_segments(message, index, trace):
                cursor = self._append(trace, parts, segment, text, cursor)

        trace.assembled_context = _SEPARATOR.join(parts)
        return trace

    # --------------------------------------------------------------- helpers

    def _append(
        self,
        trace: ContextTrace,
        parts: list[str],
        segment: Segment,
        text: str,
        cursor: int,
    ) -> int:
        """Place a segment at the current byte offset and advance the cursor."""
        start = cursor
        end = start + len(text.encode("utf-8"))
        segment.span = Span(start=start, end=end)
        segment.text = text
        trace.segments.append(segment)
        parts.append(text)
        return end + len(_SEPARATOR.encode("utf-8"))

    def _tool_declaration_segments(self, body: dict):
        """Tool descriptions are context too, and are a known injection vector (ASI02)."""
        declared: dict[str, str] = {}
        for tool in body.get("tools", []) or []:
            fn = tool.get("function", {})
            name = fn.get("name", "")
            description = fn.get("description", "") or ""
            if not name:
                continue
            declared[name] = description

        drift = self.registry.check_declarations(declared)
        drifted = {event.tool_name for event in drift}

        for name, description in declared.items():
            trusted = self.registry.is_trusted(name, description) and name not in drifted
            tool = self.registry.get(name)
            if trusted:
                cls = ProvenanceClass.TRUSTED_TOOL
                reason = f"tool '{name}' is pinned and its description matches the pin"
            elif tool is not None:
                cls = DEFAULT_CLASS
                reason = (
                    f"tool '{name}' is pinned but its description changed "
                    f"(drift detected); downgraded to {DEFAULT_CLASS.value}"
                )
            else:
                cls = DEFAULT_CLASS
                reason = f"tool '{name}' is not pinned in the registry"

            text = f"[tool:{name}] {description}"
            yield (
                Segment(
                    **{"class": cls},
                    source=SegmentSource(
                        kind="tool_description",
                        origin=tool.origin if tool else None,
                        content_hash=hash_text(text),
                    ),
                    span=Span(start=0, end=0),
                    text="",
                    locator=ToolLocator(tool_name=name),
                    classification_reason=reason,
                ),
                text,
            )

    def _message_segments(self, message: dict, index: int, trace: ContextTrace):
        role = message.get("role", "")
        content = _as_text(message.get("content"))

        if role == "system":
            segment = self._simple(
                content,
                ProvenanceClass.SYSTEM_POLICY,
                "system",
                "system role",
                MessageLocator(message_index=index, start=0, end=len(content)),
            )
            yield segment, content

        elif role == "user":
            yield from self._user_segments(content, message_index=index)

        elif role == "assistant":
            yield from self._assistant_segments(message, content, index, trace)

        elif role == "tool":
            yield from self._tool_response_segments(message, content, index)

        elif content:
            yield (
                self._simple(
                    content,
                    DEFAULT_CLASS,
                    "user_input",
                    f"unrecognised role '{role}'; failing safe to {DEFAULT_CLASS.value}",
                    MessageLocator(message_index=index, start=0, end=len(content)),
                ),
                content,
            )

    def _user_segments(self, content: str, message_index: int):
        """Split a user turn into the declared mandate and everything else.

        Substring matching is deliberately strict: the mandate text must appear verbatim.
        A fuzzy match here would be a privilege-escalation primitive -- an attacker who can
        get near-mandate text classified P0 defeats the whole chain (THREAT_MODEL.md
        residual risk 1).
        """
        if not content:
            return

        instruction = self.mandate.instruction.strip() if self.mandate else ""
        index = content.find(instruction) if instruction else -1

        if index < 0:
            yield (
                self._simple(
                    content,
                    DEFAULT_CLASS,
                    "user_input",
                    "user-role text does not contain the declared mandate; "
                    "role alone does not establish human intent",
                    MessageLocator(message_index=message_index, start=0, end=len(content)),
                ),
                content,
            )
            return

        mandate_end = index + len(instruction)
        before = content[:index]
        after = content[mandate_end:]

        if before.strip():
            yield (
                self._simple(
                    before,
                    DEFAULT_CLASS,
                    "user_input",
                    "text preceding the declared mandate inside a user turn",
                    MessageLocator(message_index=message_index, start=0, end=index),
                ),
                before,
            )

        yield (
            self._simple(
                instruction,
                ProvenanceClass.HUMAN_MANDATE,
                "user_input",
                f"verbatim match against mandate {self.mandate.mandate_id}",
                MessageLocator(message_index=message_index, start=index, end=mandate_end),
            ),
            instruction,
        )

        if after.strip():
            yield (
                self._simple(
                    after,
                    DEFAULT_CLASS,
                    "user_input",
                    "text following the declared mandate inside a user turn",
                    MessageLocator(
                        message_index=message_index, start=mandate_end, end=len(content)
                    ),
                ),
                after,
            )

    def _assistant_segments(
        self, message: dict, content: str, message_index: int, trace: ContextTrace
    ):
        """Agent output inherits the least trust among its causal parents (control C-9).

        Phase 1 approximates causal parents as *every preceding segment*, which is the
        conservative choice: it can only over-restrict, never over-trust. Phase 2 replaces
        this with measured causal parents from the ablation engine, at which point a
        summary of trusted material stops being dragged down by unrelated untrusted
        context sitting elsewhere in the window.
        """
        rendered = content
        for call in message.get("tool_calls", []) or []:
            fn = call.get("function", {})
            rendered += f"\n[tool_call:{fn.get('name', '')}] {fn.get('arguments', '')}"

        if not rendered.strip():
            return

        parent_ids = [s.segment_id for s in trace.segments]
        derived = min_trust([s.cls for s in trace.segments])

        segment = self._simple(
            rendered,
            derived,
            "agent_message",
            f"agent output; monotonicity rule over {len(parent_ids)} preceding segment(s) "
            f"yields {derived.value}",
            MessageLocator(message_index=message_index, whole_message=True),
        )
        segment.parent_segments = parent_ids
        yield segment, rendered

    def _tool_response_segments(self, message: dict, content: str, message_index: int):
        """Classify a tool result.

        Pinning is necessary but not sufficient for P2. A pinned *conduit* tool -- one that
        relays content from outside the trust boundary, like a PDF reader or web fetcher --
        returns attacker-influenced data by design, so its responses stay P3. Only
        closed-world tools returning operator-controlled data earn P2.
        """
        name = message.get("name") or message.get("tool_call_id") or "unknown"
        tool = self.registry.get(name)
        trusted = self.registry.response_is_trusted(name)
        cls = ProvenanceClass.TRUSTED_TOOL if trusted else DEFAULT_CLASS

        if trusted:
            reason = f"response from pinned closed-world tool '{name}'"
        elif tool is not None:
            reason = (
                f"tool '{name}' is pinned but relays external content; "
                f"its payload is attacker-influenced by design, so it stays "
                f"{DEFAULT_CLASS.value}"
            )
        else:
            reason = f"response from unpinned tool '{name}'; treated as untrusted external"
        text = f"[tool_result:{name}] {content}"
        segment = self._simple(
            text,
            cls,
            "tool_response",
            reason,
            MessageLocator(message_index=message_index, whole_message=True),
        )
        segment.source.origin = tool.origin if tool else None
        yield segment, text

    @staticmethod
    def _simple(
        text: str,
        cls: ProvenanceClass,
        kind: str,
        reason: str,
        locator: Locator | None = None,
    ) -> Segment:
        return Segment(
            **{"class": cls},
            source=SegmentSource(kind=kind, content_hash=hash_text(text)),
            span=Span(start=0, end=0),
            text="",
            locator=locator,
            classification_reason=reason,
        )


def _as_text(content) -> str:
    """Flatten OpenAI content, which may be a string or a list of typed parts."""
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(
            part.get("text", "")
            for part in content
            if isinstance(part, dict) and part.get("type") == "text"
        )
    return str(content)
