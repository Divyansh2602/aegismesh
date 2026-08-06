"""Request reconstruction for counterfactual ablation.

Ablation removes one piece of context and re-runs the decision. Doing that faithfully
means rebuilding the *request* -- message structure and roles included -- rather than
editing a flattened string, because message boundaries change how a model reads its input.
"""

from __future__ import annotations

import copy
import re
from collections.abc import Iterable
from decimal import Decimal, InvalidOperation
from typing import Any, Literal

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


def value_spans(text: str, value: Any) -> list[tuple[int, int, str]]:
    """Every occurrence of ``value`` in ``text``, in that text's character space.

    "Span" here means *the occurrence of a proposed argument's value*, not an arbitrary
    substring. That choice is what makes span-level ablation affordable: instead of
    sweeping every window in the context, it ablates only the places a value the model
    actually emitted appears, which is at most a handful of positions per segment.

    A value is matched in several surface forms because the model emits a parsed value
    while the context carries a written one -- ``2000000.0`` in the tool call is
    ``USD 2,000,000`` in the mandate. Missing that correspondence would report no span for
    the one field span-level ablation exists to reach.
    """
    spans: list[tuple[int, int, str]] = []
    for form in _value_forms(value):
        cursor = 0
        while (found := text.find(form, cursor)) >= 0:
            spans.append((found, found + len(form), form))
            cursor = found + len(form)
    return _longest_non_overlapping(spans)


def segment_value_spans(
    body: dict, segment: Segment, values: Iterable[Any]
) -> list[tuple[int, int, str]]:
    """Spans inside a segment carrying one of ``values``, in that message's character space.

    Mirrors ``segment_sentences``: a segment sliced out of a user turn is searched only
    within its own range, while a segment synthesised from a whole message is searched
    across the whole content, because the synthesised wrapper text (``[tool_result:...]``)
    is a display artifact that is not present in the request being ablated.
    """
    if not isinstance(segment.locator, MessageLocator):
        return []

    messages = body.get("messages", [])
    if not 0 <= segment.locator.message_index < len(messages):
        return []

    content = message_text(messages[segment.locator.message_index])
    if segment.locator.whole_message:
        window, offset = content, 0
    else:
        start, end = segment.locator.start, segment.locator.end
        window, offset = content[start:end], start

    found: list[tuple[int, int, str]] = []
    for value in values:
        found += [(s + offset, e + offset, text) for s, e, text in value_spans(window, value)]
    return _longest_non_overlapping(found)


def ablate_segments(
    body: dict, segments: Iterable[Segment], mode: AblationMode = "placeholder"
) -> dict | None:
    """Remove several segments in a single reconstruction -- used for class-level ablation.

    Not the same as ablating each segment in turn: the point is to remove *all* of a
    provenance class at once, so a value planted redundantly across several segments of
    one class disappears together rather than surviving every individual removal.

    Edits are applied to one copy, character ranges first (descending by start within each
    message, so an earlier edit cannot invalidate a later offset), then whole-message
    deletions descending by index. Doing it in the other order would shift the indices the
    range edits were computed against.
    """
    edits: list[tuple[int, int, int, bool]] = []
    tool_names: set[str] = set()

    for segment in segments:
        if isinstance(segment.locator, ToolLocator):
            tool_names.add(segment.locator.tool_name)
        elif isinstance(segment.locator, MessageLocator):
            locator = segment.locator
            edits.append(
                (
                    locator.message_index,
                    locator.start,
                    locator.end,
                    locator.whole_message,
                )
            )

    if not edits and not tool_names:
        return None

    ablated = copy.deepcopy(body)
    if tool_names:
        ablated["tools"] = [
            tool
            for tool in ablated.get("tools", []) or []
            if tool.get("function", {}).get("name") not in tool_names
        ]

    messages = ablated.get("messages", [])
    ranges = sorted(
        (e for e in edits if not e[3]),
        key=lambda e: (e[0], e[1]),
        reverse=True,
    )
    for index, start, end, _ in ranges:
        if 0 <= index < len(messages):
            _apply_range(messages[index], start, end, mode)

    whole = sorted({e[0] for e in edits if e[3]}, reverse=True)
    for index in whole:
        if not 0 <= index < len(messages):
            continue
        if mode == "delete":
            messages.pop(index)
        else:
            _blank_message(messages[index])

    return ablated


def _value_forms(value: Any) -> list[str]:
    """The written forms a proposed argument value may take in the context.

    Ordered longest-first so ``2,000,000`` is preferred over the bare ``2000000`` it
    contains, which keeps the ablated span tight around the whole written number instead of
    leaving a stray separator behind.
    """
    forms: set[str] = set()
    text = str(value)
    if text.strip():
        forms.add(text)

    if isinstance(value, bool):
        return sorted(forms, key=len, reverse=True)

    try:
        number = Decimal(text)
    except (InvalidOperation, ValueError):
        return sorted(forms, key=len, reverse=True)

    plain = format(number.normalize(), "f")
    forms.add(plain)
    if number == number.to_integral_value():
        plain = format(number.to_integral_value(), "f")
        forms.add(plain)
    else:
        forms.add(f"{number:.2f}")

    for form in list(forms):
        grouped = _group_thousands(form)
        if grouped is not None:
            forms.add(grouped)

    return sorted(forms, key=len, reverse=True)


def _group_thousands(number: str) -> str | None:
    whole, _, fraction = number.partition(".")
    sign, digits = ("-", whole[1:]) if whole.startswith("-") else ("", whole)
    if not digits.isdigit() or len(digits) <= 3:
        return None
    grouped = f"{int(digits):,}"
    return f"{sign}{grouped}.{fraction}" if fraction else f"{sign}{grouped}"


def _longest_non_overlapping(
    spans: list[tuple[int, int, str]],
) -> list[tuple[int, int, str]]:
    """Drop spans contained in or overlapping a longer one, keeping document order.

    Two forms of the same value can match at overlapping positions. Ablating both would
    charge two model calls to measure one occurrence, and the second ablation would run
    against text the first had already blanked.
    """
    kept: list[tuple[int, int, str]] = []
    for span in sorted(spans, key=lambda s: (s[1] - s[0], -s[0]), reverse=True):
        if any(span[0] < other[1] and other[0] < span[1] for other in kept):
            continue
        kept.append(span)
    return sorted(kept)


def _apply_range(message: dict, start: int, end: int, mode: AblationMode) -> None:
    content = message_text(message)
    start = max(0, min(start, len(content)))
    end = max(start, min(end, len(content)))
    replacement = "" if mode == "delete" else neutral_placeholder(end - start)
    message["content"] = content[:start] + replacement + content[end:]


def _blank_message(message: dict) -> None:
    content = message_text(message)
    message["content"] = neutral_placeholder(len(content))
    message.pop("tool_calls", None)


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
            _blank_message(messages[message_index])
        return ablated

    _apply_range(messages[message_index], start, end, mode)
    return ablated
