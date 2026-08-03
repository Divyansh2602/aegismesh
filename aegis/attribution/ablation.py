"""Request reconstruction for counterfactual ablation.

Ablation removes one piece of context and re-runs the decision. Doing that faithfully
means rebuilding the *request* -- message structure and roles included -- rather than
editing a flattened string, because message boundaries change how a model reads its input.
"""

from __future__ import annotations

import copy
import re
from typing import Literal

from aegis.provenance.models import MessageLocator, Segment, ToolLocator

AblationMode = Literal["placeholder", "delete"]

_PLACEHOLDER_FILLER = "[redacted] "

#: Sentence boundaries. Deliberately simple: a heavier NLP dependency would buy little
#: here, since over-splitting costs extra model calls but never corrupts the measurement --
#: each fragment is still ablated and scored on its own.
_SENTENCE_SPLIT = re.compile(r"(?<=[.!?])\s+|\n+")


def neutral_placeholder(length: int) -> str:
    """Filler of approximately ``length`` characters carrying no instruction.

    Length is preserved because deletion changes every downstream position, and position
    is itself a cause of model behaviour. If a segment were simply deleted, some of the
    measured "influence" would be the shift, not the content -- see SPEC.md section 9,
    open question 5, which this lets the evaluation harness answer empirically.
    """
    if length <= 0:
        return ""
    repeats = (length // len(_PLACEHOLDER_FILLER)) + 1
    return (_PLACEHOLDER_FILLER * repeats)[:length]


def message_text(message: dict) -> str:
    content = message.get("content")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(
            part.get("text", "")
            for part in content
            if isinstance(part, dict) and part.get("type") == "text"
        )
    return "" if content is None else str(content)


def ablate(body: dict, segment: Segment, mode: AblationMode = "placeholder") -> dict | None:
    """Return ``body`` with ``segment`` removed. None if the segment has no locator."""
    if segment.locator is None:
        return None
    if isinstance(segment.locator, ToolLocator):
        return _ablate_tool(body, segment.locator)
    return _ablate_message_range(
        body,
        segment.locator.message_index,
        segment.locator.start,
        segment.locator.end,
        whole_message=segment.locator.whole_message,
        mode=mode,
    )


def ablate_range(
    body: dict,
    message_index: int,
    start: int,
    end: int,
    mode: AblationMode = "placeholder",
) -> dict:
    """Ablate an arbitrary character range -- used for sentence-level drill-down."""
    return _ablate_message_range(body, message_index, start, end, False, mode)


def sentence_ranges(text: str, offset: int = 0) -> list[tuple[int, int, str]]:
    """Split ``text`` into ``(start, end, sentence)`` triples, offsets shifted by ``offset``.

    Whitespace-only fragments are dropped: ablating them measures nothing and still costs
    a model call.
    """
    ranges: list[tuple[int, int, str]] = []
    cursor = 0
    for piece in _SENTENCE_SPLIT.split(text):
        if piece == "":
            continue
        found = text.find(piece, cursor)
        if found < 0:
            continue
        cursor = found + len(piece)
        if piece.strip():
            ranges.append((offset + found, offset + cursor, piece))
    return ranges


def segment_sentences(body: dict, segment: Segment) -> list[tuple[int, int, str]]:
    """Sentence ranges inside a segment, in that message's character space.

    For a segment sliced out of a user turn, only its own range is split. For a segment
    synthesised from a whole message (a tool result), the whole content is split -- the
    synthesised wrapper text is a display artifact and is not present in the request.
    """
    if not isinstance(segment.locator, MessageLocator):
        return []

    messages = body.get("messages", [])
    if not 0 <= segment.locator.message_index < len(messages):
        return []

    content = message_text(messages[segment.locator.message_index])
    if segment.locator.whole_message:
        return sentence_ranges(content)

    start, end = segment.locator.start, segment.locator.end
    return sentence_ranges(content[start:end], offset=start)


def _ablate_tool(body: dict, locator: ToolLocator) -> dict:
    ablated = copy.deepcopy(body)
    ablated["tools"] = [
        tool
        for tool in ablated.get("tools", []) or []
        if tool.get("function", {}).get("name") != locator.tool_name
    ]
    return ablated


def _ablate_message_range(
    body: dict,
    message_index: int,
    start: int,
    end: int,
    whole_message: bool,
    mode: AblationMode,
) -> dict:
    ablated = copy.deepcopy(body)
    messages = ablated.get("messages", [])
    if not 0 <= message_index < len(messages):
        return ablated

    if whole_message:
        if mode == "delete":
            messages.pop(message_index)
        else:
            content = message_text(messages[message_index])
            messages[message_index]["content"] = neutral_placeholder(len(content))
            messages[message_index].pop("tool_calls", None)
        return ablated

    content = message_text(messages[message_index])
    start = max(0, min(start, len(content)))
    end = max(start, min(end, len(content)))
    replacement = "" if mode == "delete" else neutral_placeholder(end - start)
    messages[message_index]["content"] = content[:start] + replacement + content[end:]
    return ablated
