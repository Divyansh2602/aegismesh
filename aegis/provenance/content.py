"""Extracting the text a model will actually read from a message.

**One definition, imported by everyone who needs it.** This function used to exist twice —
once in `provenance/classifier.py` as `_as_text` and once in `attribution/ablation.py` as
`message_text` — and the two had to agree for the system to be sound: classification
decides what carries a provenance class, ablation decides what a counterfactual removes,
and a byte in one but not the other is a byte outside the measurement.

They agreed for as long as anyone checked, and then Phase 8's classifier evaluation found
they were both wrong in the same way, which duplication had made easy to miss. Keeping two
copies of a rule that must match is the bug; this module is the fix, and the divergence
cannot recur because there is no longer anything to diverge from.

## The rule, and why it is permissive about `type`

OpenAI-style content is either a plain string or a list of typed parts. The old rule kept
only parts whose type was exactly ``"text"``. That is the Chat Completions spelling; the
Responses API uses ``"input_text"``, and assistant turns use ``"output_text"``. A part
typed anything else was silently dropped — never classified, therefore never ablatable,
therefore able to influence an action with no provenance at all and no counterfactual able
to test it (THREAT_MODEL.md section 6, finding F1).

So the rule is now: **any part carrying a ``text`` field contributes its text.** That is
deliberately permissive. The failure mode of being too permissive is that something gets
classified which the model might not read, which over-restricts and is visible. The failure
mode of being too strict is content the model reads and provenance never saw, which is
invisible and is the one that was actually exploitable.

Parts carrying no text at all — images, audio — contribute nothing here, and that remains a
real limitation rather than a solved problem: this system classifies *text* provenance, and
an image the model can read is outside what it can measure. That is stated in the threat
model rather than papered over.
"""

from __future__ import annotations

from typing import Any


def message_text(message: dict) -> str:
    """The text of one message, exactly as classification and ablation both see it."""
    return content_text(message.get("content"))


def content_text(content: Any) -> str:
    """Flatten OpenAI content, which may be a string or a list of typed parts."""
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(_part_text(part) for part in content if _has_text(part))
    return str(content)


def untyped_part_kinds(content: Any) -> list[str]:
    """Part types that carry no text, so this system cannot classify them.

    Reported rather than ignored. An image the model can read is content whose provenance
    is genuinely unknown to a text classifier, and the honest response is to name it.
    """
    if not isinstance(content, list):
        return []
    return sorted(
        {
            str(part.get("type", "unknown"))
            for part in content
            if isinstance(part, dict) and not _has_text(part)
        }
    )


def _has_text(part: Any) -> bool:
    return isinstance(part, dict) and isinstance(part.get("text"), str)


def _part_text(part: dict) -> str:
    return part["text"]
