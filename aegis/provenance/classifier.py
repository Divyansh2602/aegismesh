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
from aegis.provenance.classes import DEFAULT_CLASS, ProvenanceClass
from aegis.provenance.content import content_text
from aegis.provenance.models import (
    ContextTrace,
    Locator,
    MessageLocator,
    Segment,
    SegmentSource,
    Span,
    ToolLocator,
)
from aegis.provenance.monotonicity import (
    DEFAULT_THETA,
    ParentInfluence,
    all_parents,
    derive_class,
)
from aegis.provenance.registry import MandateContext, ToolRegistry

_SEPARATOR = "\n"


class _IssuedCalls:
    """The tool calls the agent has actually made, so far, in this conversation.

    Exists because trust in a tool response used to rest on the response's own claim about
    its name. In the OpenAI protocol a tool message answers a specific ``tool_call``; a
    result nobody asked for is not a result, it is an assertion, and it should carry no
    more weight than any other untrusted text that arrived in the context.

    Matching prefers ``tool_call_id`` — the strong form, since the id is minted by the
    agent — and falls back to the tool name where no id is supplied, which some frameworks
    omit. The fallback is weaker on purpose and is still strictly better than the previous
    behaviour of trusting a name with no corresponding call at all.
    """

    __slots__ = ("_by_id", "_names")

    def __init__(self) -> None:
        self._by_id: dict[str, str] = {}
        self._names: set[str] = set()

    def record(self, message: dict) -> None:
        if message.get("role") != "assistant":
            return
        for call in message.get("tool_calls", []) or []:
            name = call.get("function", {}).get("name", "")
            if not name:
                continue
            self._names.add(name)
            if call_id := call.get("id"):
                self._by_id[str(call_id)] = name

    def binds(self, message: dict, name: str) -> bool:
        call_id = message.get("tool_call_id")
        if call_id is not None:
            # An id that was never issued is a forgery; an id issued for a *different*
            # tool is a swap, and both are refused rather than falling back to the name.
            return self._by_id.get(str(call_id)) == name
        return name in self._names


class ContextClassifier:
    """Builds a ContextTrace from a chat-completions request body."""

    def __init__(
        self,
        registry: ToolRegistry | None = None,
        mandate: MandateContext | None = None,
        theta: float = DEFAULT_THETA,
        parent_influence: ParentInfluence = all_parents,
    ) -> None:
        self.registry = registry or ToolRegistry()
        self.mandate = mandate
        self.theta = theta
        self.parent_influence = parent_influence
        """How much a preceding segment must have shaped an agent's output to count as its
        causal parent (SPEC.md section 2.2).

        Defaults to ``all_parents``, under which every preceding segment counts and theta
        has no effect -- Phase 1's conservative approximation, unchanged. Passing
        ``lexical_overlap`` makes theta live. See ``provenance/monotonicity.py`` for why
        the specification's causal quantity is not what either estimator computes.
        """

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

        # Calls the agent has actually issued *so far*. Built as we walk rather than
        # up front, so a tool result can only bind to a call that precedes it -- a
        # transcript where the answer arrives before the question is not one to trust.
        issued: _IssuedCalls = _IssuedCalls()

        for index, message in enumerate(body.get("messages", [])):
            for segment, text in self._message_segments(message, index, trace, issued):
                cursor = self._append(trace, parts, segment, text, cursor)
            issued.record(message)

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

    def _message_segments(
        self, message: dict, index: int, trace: ContextTrace, issued: _IssuedCalls
    ):
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
            yield from self._tool_response_segments(message, content, index, issued)

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
        occurrences = content.count(instruction) if instruction else 0

        if occurrences > 1:
            # Fail closed on ambiguity (THREAT_MODEL section 6, finding F3). `str.find`
            # returns the earliest match, so a document quoting the mandate above the
            # human's own typing takes the P0 span -- and the two copies are byte-identical,
            # so nothing in the text can tell them apart. Rather than pick one and be
            # confidently wrong about where human intent came from, grant P0 to neither.
            #
            # A human does not repeat their instruction verbatim in one turn, so this
            # costs approximately nothing in practice and refuses in the safe direction:
            # the action loses its authorisation rather than gaining a forged one.
            yield (
                self._simple(
                    content,
                    DEFAULT_CLASS,
                    "user_input",
                    f"the declared mandate appears {occurrences} times in one user turn; "
                    "which copy the human wrote cannot be determined from the text, so no "
                    f"span is granted {ProvenanceClass.HUMAN_MANDATE.value}",
                    MessageLocator(message_index=message_index, start=0, end=len(content)),
                ),
                content,
            )
            return

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

        Which preceding segments count as parents is decided by ``parent_influence`` and
        ``theta``. Under the default estimator every one of them does, which is Phase 1's
        approximation and is conservative by construction: it can only over-restrict. Under
        a real estimate, a summary of trusted material stops being dragged down by
        unrelated untrusted context sitting elsewhere in the window -- and starts being
        able to miss laundering it cannot see. ``provenance/monotonicity.py`` sets out that
        trade and ``evaluation/theta.py`` measures it.

        Only the surviving parents are recorded. A segment listing every preceding id
        cannot answer "which untrusted thing reached this?", which is the question an
        investigator actually has.
        """
        rendered = content
        for call in message.get("tool_calls", []) or []:
            fn = call.get("function", {})
            rendered += f"\n[tool_call:{fn.get('name', '')}] {fn.get('arguments', '')}"

        if not rendered.strip():
            return

        candidates = [(s.cls, s.text) for s in trace.segments]
        derived, surviving = derive_class(
            candidates, rendered, theta=self.theta, influence=self.parent_influence
        )
        parent_ids = [trace.segments[index].segment_id for index in surviving]

        segment = self._simple(
            rendered,
            derived,
            "agent_message",
            f"agent output; monotonicity rule over {len(parent_ids)} causal parent(s) of "
            f"{len(candidates)} candidate(s) at theta={self.theta} yields {derived.value}",
            MessageLocator(message_index=message_index, whole_message=True),
        )
        segment.parent_segments = parent_ids
        yield segment, rendered

    def _tool_response_segments(
        self, message: dict, content: str, message_index: int, issued: _IssuedCalls
    ):
        """Classify a tool result.

        Pinning is necessary but not sufficient for P2. A pinned *conduit* tool -- one that
        relays content from outside the trust boundary, like a PDF reader or web fetcher --
        returns attacker-influenced data by design, so its responses stay P3. Only
        closed-world tools returning operator-controlled data earn P2.

        **Nor is the name sufficient.** Trust used to be resolved from ``message["name"]``
        alone, with nothing checking that the call had ever been made, so anything able to
        append a message could mint P2 by claiming to be the ledger (THREAT_MODEL.md
        section 6, finding F2). A response now has to bind to a call the agent actually
        issued earlier in the same conversation. This is C-19's lesson one level down:
        pinning proves the *tool* is authentic, binding proves *this payload came from it*.
        """
        name = message.get("name") or message.get("tool_call_id") or "unknown"
        tool = self.registry.get(name)
        bound = issued.binds(message, name)
        trusted = self.registry.response_is_trusted(name) and bound
        cls = ProvenanceClass.TRUSTED_TOOL if trusted else DEFAULT_CLASS

        if trusted:
            reason = f"response from pinned closed-world tool '{name}', bound to its call"
        elif not bound and self.registry.response_is_trusted(name):
            reason = (
                f"tool '{name}' is pinned and closed-world, but this response binds to no "
                f"call the agent issued; unrequested results are not evidence, so it stays "
                f"{DEFAULT_CLASS.value}"
            )
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


#: Kept as a name because the whole module reads in terms of it, but the rule now lives in
#: ``provenance/content.py`` and is shared with ``attribution/ablation.py``. It used to be a
#: second, independent copy, and the two silently disagreed: both kept only parts typed
#: exactly ``"text"``, so a part typed ``input_text`` was classified by neither and ablatable
#: by neither. See THREAT_MODEL section 6, finding F1.
_as_text = content_text
