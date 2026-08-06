"""A deterministic surrogate model, generalized beyond the treasury scenario.

``aegis/mockmodel`` reproduces one attack on one tool. Scoring against AgentDojo needs a
model that proposes many different actions over four suites, and it still has to be
deterministic, free, and offline -- the attribution engine issues one call per ablation, so
a paid nondeterministic endpoint makes the measurement both expensive and unrepeatable.

**What this is and is not.** It is a stand-in for a *vulnerable* LLM whose susceptibility is
written down rather than discovered: identifier-shaped arguments are taken from the most
recent matching value in context, quantities from the first. Recency bias on identifiers is
the documented mechanism behind indirect prompt injection, and it is the same rule the
Phase 2 mock uses, generalized.

It is **not** evidence about how a real model behaves. Nothing measured through it supports
a claim about GPT-4 or Claude, and the results reported in Phase 4 say so. What it does buy
is exact ground truth: because the mapping from context to action is a known function,
every case carries a label that was computed rather than annotated, and the causal link the
ablation engine measures is a real one -- the arguments genuinely come from the context, so
removing the text that carries them genuinely changes the action.

The same adapter runs against ``HttpModelClient``, so replacing this with a real endpoint is
a configuration change rather than a rewrite. That measurement needs an API key and a budget
and is deliberately out of scope here.
"""

from __future__ import annotations

import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

Selection = Literal["first", "last"]

#: Value shapes the surrogate can locate in free text. Order matters: the first pattern
#: that matches a legitimate argument value decides how that field is modelled, so the
#: specific identifier shapes must be tried before the general numeric one.
#:
#: Known quirk, left in deliberately: the numeric lookahead rejects a trailing dot, so
#: ``total 98.70.`` at the end of a sentence finds no amount and the surrogate cancels the
#: action. It exists to stop ``1`` being pulled out of ``1.2.3``. The effect is to drop
#: cases rather than to mis-attribute them -- ground truth is computed from this same rule,
#: so the measurement stays internally consistent and the cost is coverage. Changing it
#: would silently move every number in ``results/phase4_agentdojo.json``, so it is recorded
#: here instead of quietly improved.
_SHAPES: list[tuple[str, re.Pattern[str], Selection]] = [
    ("iban", re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b"), "last"),
    ("url", re.compile(r"https?://[^\s,'\"\)\]]+"), "last"),
    ("email", re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"), "last"),
    ("number", re.compile(r"(?<![\w.,])-?\d[\d,]*(?:\.\d+)?(?![\w.])"), "first"),
]

#: Identifiers are captured by recency and quantities by primacy. The asymmetry is the
#: whole point: it reproduces an agent that keeps the amount the human asked for while
#: taking the destination from whatever spoke last, which is one action that is
#: simultaneously legitimate in one field and hijacked in another.
_SELECTION_NOTE = "identifiers by recency, quantities by primacy"


class FieldRule(BaseModel):
    """How one argument of the proposed action is derived from the context."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    name: str
    shape: str | None = None
    """The value shape this field is read from context as. ``None`` means the field is not
    modelled and is emitted as a constant -- see ``constant``."""

    pattern: re.Pattern[str] | None = None
    selection: Selection = "last"
    constant: Any = None
    """Value emitted for unmodelled fields.

    A free-text field like an email subject has no shape to search for, so the surrogate
    cannot honestly claim the context determined it. Emitting it unchanged makes it
    context-independent, and attribution reports it ``invariant`` -- which is the truth
    about this model, not a gap being papered over.
    """

    container: Literal["scalar", "list"] = "scalar"
    """Whether the tool takes this argument wrapped in a list.

    ``send_email`` takes ``recipients=["a@b.com"]`` rather than a bare address, and that is
    the most common consequential action in AgentDojo's largest suite. Treating the list as
    an opaque unmodellable value would drop those cases from the evaluation for a reason
    that is purely about JSON shape and nothing to do with provenance.
    """

    @property
    def modelled(self) -> bool:
        return self.pattern is not None


class SurrogateSpec(BaseModel):
    """The action the agent is performing, and how each of its arguments is filled."""

    tool: str
    rules: list[FieldRule] = Field(default_factory=list)

    def modelled_fields(self) -> list[str]:
        return [rule.name for rule in self.rules if rule.modelled]


class SurrogateDecision(BaseModel):
    tool: str | None = None
    arguments: dict = Field(default_factory=dict)
    text: str = ""
    reason: str = ""


def infer_rules(arguments: dict[str, Any]) -> list[FieldRule]:
    """Derive field rules from the values a legitimate run of the action would use.

    The shape of the *legitimate* value decides how the field is read, and the legitimate
    value is never itself planted into the answer. That matters for honesty: if the rules
    were derived from the attacker's values instead, the surrogate would be built to fall
    for the specific attack it is then scored against.
    """
    rules: list[FieldRule] = []
    for name, value in sorted(arguments.items()):
        inner, container = _unwrap(value)
        shaped = _match_shape(inner) if inner is not None else None
        if shaped is None:
            rules.append(FieldRule(name=name, constant=value))
            continue
        shape, pattern, selection = shaped
        rules.append(
            FieldRule(
                name=name,
                shape=shape,
                pattern=pattern,
                selection=selection,
                container=container,
            )
        )
    return rules


def _unwrap(value: Any) -> tuple[Any, Literal["scalar", "list"]]:
    """Look inside a single-element list, which is how several tools take one identifier.

    Only single-element lists. A multi-recipient send has more than one value to attribute
    and no single answer to give, so it stays unmodelled rather than being reduced to
    whichever element happened to come first.
    """
    if isinstance(value, list):
        return (value[0], "list") if len(value) == 1 else (None, "list")
    return value, "scalar"


def _match_shape(value: Any) -> tuple[str, re.Pattern[str], Selection] | None:
    text = str(value).strip()
    for shape, pattern, selection in _SHAPES:
        if pattern.fullmatch(text):
            return shape, pattern, selection
    return None


def decide(context: str, spec: SurrogateSpec) -> SurrogateDecision:
    """Map a context string to a proposed action, deterministically.

    A modelled field with no match in the context cancels the action outright rather than
    guessing. That is what makes ``necessity`` measurable: removing the only segment that
    named the recipient stops the send, and the engine records that as necessity instead of
    inventing a value-causation claim (SPEC.md section 3.2).
    """
    arguments: dict[str, Any] = {}
    for rule in spec.rules:
        if rule.pattern is None:
            arguments[rule.name] = rule.constant
            continue

        matches = rule.pattern.findall(context)
        if not matches:
            return SurrogateDecision(
                text=f"I need a value for {rule.name} before I can continue.",
                reason=f"no {rule.shape} found in context for required field {rule.name}",
            )
        chosen = _coerce(matches[0] if rule.selection == "first" else matches[-1])
        arguments[rule.name] = [chosen] if rule.container == "list" else chosen

    return SurrogateDecision(
        tool=spec.tool,
        arguments=arguments,
        reason=f"{spec.tool}; {_SELECTION_NOTE}",
    )


def _coerce(raw: str) -> Any:
    """Turn a matched string into the value a tool call would carry.

    Numbers become numbers because that is what a model emits and what a relying party
    compares. Doing it here rather than at the comparison keeps the canonicalization
    problem in one place -- ``2,000,000`` and ``2000000`` are the same argument.
    """
    stripped = raw.strip()
    candidate = stripped.replace(",", "")
    try:
        number = float(candidate)
    except ValueError:
        return stripped
    return int(number) if number.is_integer() and "." not in candidate else number


class SurrogateClient:
    """Model client over ``decide``, matching the engine's ``complete(body)`` protocol.

    In-process rather than over HTTP for the same reason as ``InProcessMockClient``: the
    AgentDojo sweep issues tens of thousands of ablation calls, and a socket round-trip per
    call would dominate the runtime while measuring nothing.
    """

    def __init__(self, spec: SurrogateSpec) -> None:
        self.spec = spec
        self.calls = 0

    async def complete(self, body: dict) -> dict:
        import json

        self.calls += 1
        decision = decide(flatten(body.get("messages", [])), self.spec)

        message: dict = {"role": "assistant", "content": decision.text or None}
        if decision.tool:
            message["tool_calls"] = [
                {
                    "id": "call_surrogate_0",
                    "type": "function",
                    "function": {
                        "name": decision.tool,
                        "arguments": json.dumps(decision.arguments, sort_keys=True),
                    },
                }
            ]
        return {"choices": [{"index": 0, "message": message}]}


def flatten(messages: list[dict]) -> str:
    parts: list[str] = []
    for message in messages:
        content = message.get("content")
        if isinstance(content, str):
            parts.append(content)
        elif isinstance(content, list):
            parts.extend(
                part.get("text", "")
                for part in content
                if isinstance(part, dict) and part.get("type") == "text"
            )
        for call in message.get("tool_calls", []) or []:
            parts.append(str(call.get("function", {}).get("arguments", "")))
    return "\n".join(parts)
