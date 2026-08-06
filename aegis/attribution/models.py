"""Attribution data model."""

from __future__ import annotations

import json
import math
from typing import Literal

from pydantic import BaseModel, Field

from aegis.provenance.classes import ProvenanceClass

#: Influence below this is treated as measurement noise rather than causation.
NOISE_FLOOR = 1e-9


class ActionSignature(BaseModel):
    """The action a model proposed, reduced to what we compare across ablations."""

    tool: str | None = None
    arguments: dict = Field(default_factory=dict)

    @classmethod
    def from_response(cls, response: dict) -> ActionSignature:
        """The first tool call in an OpenAI-shaped completion.

        Retained for callers that know the response carries one call. **Do not use it to
        decide what to attribute** -- see :meth:`all_from_response`.
        """
        calls = cls.all_from_response(response)
        return calls[0] if calls else cls()

    @classmethod
    def all_from_response(cls, response: dict) -> list[ActionSignature]:
        """Every tool call the model proposed, in order.

        This exists because taking only the first one was a complete bypass of the
        consequential-action gate, found in Phase 4 while attacking it (SPEC.md open
        question 3). Parallel tool calls are ordinary in the OpenAI API: a model can emit
        ``get_balance`` and ``execute_transfer`` in a single message. The gate saw
        ``get_balance``, correctly called it read-only, and the transfer was never
        attributed, never warranted, and never enforced.

        Nothing about that requires an attacker to be clever. An injection that says "check
        the balance first" is enough, and it costs nothing to try.
        """
        choices = response.get("choices") or []
        if not choices:
            return []
        message = choices[0].get("message") or {}

        signatures: list[ActionSignature] = []
        for call in message.get("tool_calls") or []:
            fn = call.get("function", {})
            raw = fn.get("arguments", "{}")
            try:
                arguments = json.loads(raw) if isinstance(raw, str) else dict(raw)
            except (json.JSONDecodeError, TypeError, ValueError):
                # A model that emits unparseable arguments is a finding, not a crash. Keep
                # the raw text so the disagreement still registers as influence.
                arguments = {"__unparsed__": raw}
            signatures.append(cls(tool=fn.get("name"), arguments=arguments))
        return signatures

    @classmethod
    def select(cls, response: dict, tool: str | None) -> ActionSignature:
        """The proposed call for ``tool``, or an empty signature if it was not proposed.

        Ablations are scored by comparing like with like. Once a response can carry several
        calls, comparing position 0 against position 0 would record a cancellation whenever
        the model merely reordered them, inventing necessity for a segment that changed
        nothing.
        """
        for signature in cls.all_from_response(response):
            if signature.tool == tool:
                return signature
        return cls()

    def fields(self) -> set[str]:
        return set(self.arguments)

    def agrees_on(self, other: ActionSignature, field: str) -> bool:
        return self.arguments.get(field) == other.arguments.get(field)

    def same_tool(self, other: ActionSignature) -> bool:
        return self.tool == other.tool

    def is_empty(self) -> bool:
        return self.tool is None


class Contributor(BaseModel):
    """One segment's measured influence on an action."""

    segment_id: str
    cls: ProvenanceClass = Field(alias="class")
    origin: str | None = None
    excerpt_hash: str
    influence: float
    necessity: float = 0.0
    """Fraction of ablations where removing this segment cancelled the action outright.

    Necessity is not value-causation. A mandate whose removal stops the payment happening
    was necessary for it, which says nothing about where the money was sent -- so this is
    reported separately and never folded into per-field influence.
    """

    per_field: dict[str, float] = Field(default_factory=dict)
    comparable: bool = False
    """Whether at least one ablation of this segment left the same tool being called.

    Without a comparable run there is nothing to compare field values against, so a
    ``per_field`` of all zeros means two completely different things depending on this
    flag: "removing it changed no value" versus "removing it cancelled the action, so no
    value existed to change". Collapsing those two into the same number is what made a
    legitimate payment indistinguishable from an unattributable one.
    """

    granularity: str = "segment"
    sentence: str | None = None
    """Set for sentence-level contributors: the hash of the sentence, never its text."""

    field_hint: str | None = None
    """For span-level contributors: which argument's value this span carried.

    A span is located by searching for a value the model emitted, so unlike a segment or a
    sentence it is already tied to one field. Recording that lets an investigator read
    "this span set the destination" straight off the contributor rather than inferring it
    from the per-field scores.
    """

    model_config = {"populate_by_name": True}


#: What the measurement was able to say about one argument field.
#:
#: The three cases are genuinely different claims and policy must be able to tell them
#: apart. ``attributed`` -- some class measurably set this value. ``invariant`` -- runs
#: that could have shown a change happened, and none did; the value is overdetermined or
#: context-independent, and no class was pivotal. ``unknown`` -- every ablation cancelled
#: the action, so no comparable run exists and nothing at all was measured.
#:
#: Only ``unknown`` is grounds to fail closed. Treating ``invariant`` as unknown denies
#: every legitimate action whose fields are corroborated by more than one source, which is
#: most of them.
ArgumentStatus = Literal["attributed", "invariant", "unknown"]


#: Why a field resisted single-segment ablation. Only meaningful once class-level ablation
#: has run; without it every ``invariant`` field reports ``unmeasured``.
#:
#: ``invariant`` says no single segment was pivotal, and that has two causes with opposite
#: security meanings. A legitimate payment's destination is named by both the human's
#: mandate and the operator's ledger, so removing either leaves the other -- benign
#: corroboration, and the normal case for real work. An attacker who plants the same value
#: in two retrieved documents produces the *identical* segment-level signature while
#: controlling the value outright. Segment-level ablation cannot separate them, which is
#: THREAT_MODEL.md residual risk 2 (ADV-5) and SPEC.md open question 6.
#:
#: Removing a whole provenance class at once does separate them:
#:
#: ``cross_class``   -- no single class's removal changed the value either. Several classes
#:                      independently name it; no one source is in control. Benign.
#: ``within_class``  -- removing one class as a whole changed the value, though no single
#:                      segment of it did. That class controls the field by redundant
#:                      encoding. When the class is P3, this is the ADV-5 evasion landing.
#: ``unmeasured``    -- class-level ablation did not run, or every class ablation cancelled
#:                      the action. Nothing was established.
Redundancy = Literal["cross_class", "within_class", "unmeasured"]


class InfluenceDistribution(BaseModel):
    """Normalized influence over provenance classes."""

    weights: dict[ProvenanceClass, float] = Field(default_factory=dict)

    @classmethod
    def from_totals(cls, totals: dict[ProvenanceClass, float]) -> InfluenceDistribution:
        """Normalize raw influence sums into a distribution.

        When nothing measurably influenced the action, the result is uniform rather than
        empty. That is the honest encoding of "we could not attribute this", and it drives
        confidence to zero, which makes policy fail closed (control C-16).
        """
        total = sum(totals.values())
        if total <= NOISE_FLOOR:
            share = 1.0 / len(ProvenanceClass)
            return cls(weights={c: share for c in ProvenanceClass})
        return cls(weights={c: v / total for c, v in totals.items() if v > NOISE_FLOOR})

    def get(self, cls_: ProvenanceClass) -> float:
        return self.weights.get(cls_, 0.0)

    def entropy(self) -> float:
        return -sum(p * math.log(p) for p in self.weights.values() if p > NOISE_FLOOR)

    def confidence(self) -> float:
        """1 - normalized entropy: 1.0 when one class explains everything, 0.0 when uniform."""
        max_entropy = math.log(len(ProvenanceClass))
        if max_entropy <= 0:
            return 0.0
        return max(0.0, min(1.0, 1.0 - self.entropy() / max_entropy))

    def dominant(self) -> ProvenanceClass | None:
        if not self.weights:
            return None
        return max(self.weights, key=lambda c: self.weights[c])

    def as_dict(self) -> dict[str, float]:
        return {c.value: round(v, 4) for c, v in sorted(self.weights.items())}


class AttributionResult(BaseModel):
    """What aegis-causa concluded about one proposed action."""

    method: str = "loo-ablation"
    method_version: str = "0.1.0"
    granularity: list[str] = Field(default_factory=lambda: ["segment"])
    resamples: int = 1
    model_ref: str = ""

    mode: str = "placeholder"
    """How segments were removed: ``placeholder`` or ``delete``.

    Recorded on the result, not only on the engine, because it travels into ``replay_ref``
    and therefore under a signature. The two modes build different counterfactuals, so an
    auditor replaying under the other one measures a different quantity -- and would either
    contradict an honest issuer or fail to contradict a dishonest one who picked the
    flattering setting and never had to declare it.
    """

    drilldown_threshold: float = 0.15
    """Share of total influence a segment needs before its sentences are scored.

    Carried for the same reason as ``mode``: it changes which measurements exist.
    """

    action: ActionSignature
    consequential: bool = True
    gate_reason: str = ""

    influence: InfluenceDistribution = Field(default_factory=InfluenceDistribution)
    necessity: InfluenceDistribution = Field(default_factory=InfluenceDistribution)
    """Which classes the action *required*, as distinct from which set its field values."""

    per_argument: dict[str, InfluenceDistribution] = Field(default_factory=dict)

    argument_status: dict[str, ArgumentStatus] = Field(default_factory=dict)
    """Whether each field was attributed, found invariant, or could not be measured.

    Carried alongside ``per_argument`` rather than folded into it because a distribution
    cannot express "nothing was pivotal" and "we learned nothing" as different states --
    both come out as an absence of weight.
    """

    per_argument_confidence: dict[str, float] = Field(default_factory=dict)
    """Confidence in the *field-level* attribution, which is the unit that matters.

    An action-level number averages away the case this project exists for: one action
    simultaneously legitimate in one field and hijacked in another. A destination account
    attributed entirely to one class is a high-confidence finding even when the action as a
    whole splits evenly between the human and the attacker.
    """

    per_argument_redundancy: dict[str, Redundancy] = Field(default_factory=dict)
    """Why each field resisted single-segment ablation, from class-level ablation.

    Empty when class-level ablation was not run. Kept separate from ``argument_status``
    rather than added to it as a fourth status, because the two answer different questions
    and a relying party may want either: ``argument_status`` says whether anything was
    established about the value, ``per_argument_redundancy`` says whether one class held it
    on its own. Folding them together would force a policy that cares about only one of
    them to reason about both.
    """

    per_argument_class_influence: dict[str, InfluenceDistribution] = Field(default_factory=dict)
    """Field-level influence measured by removing whole provenance classes at once.

    Not a replacement for ``per_argument``: it is coarser, and a class that scores here
    while scoring zero per-segment is precisely the redundant-encoding case. Reported
    alongside rather than merged, so the two granularities can disagree visibly.
    """

    top_contributors: list[Contributor] = Field(default_factory=list)
    confidence: float = 0.0

    model_calls: int = 0
    """Cost, in upstream model invocations. The number that decides deployability."""

    def summary(self) -> dict:
        return {
            "method": self.method,
            "granularity": self.granularity,
            "resamples": self.resamples,
            "consequential": self.consequential,
            "influence": self.influence.as_dict(),
            "necessity": self.necessity.as_dict(),
            "per_argument": {k: v.as_dict() for k, v in self.per_argument.items()},
            "per_argument_class_influence": {
                k: v.as_dict() for k, v in sorted(self.per_argument_class_influence.items())
            },
            "argument_status": dict(sorted(self.argument_status.items())),
            "per_argument_redundancy": dict(sorted(self.per_argument_redundancy.items())),
            "per_argument_confidence": {
                k: round(v, 4) for k, v in sorted(self.per_argument_confidence.items())
            },
            "confidence": round(self.confidence, 4),
            "model_calls": self.model_calls,
        }
