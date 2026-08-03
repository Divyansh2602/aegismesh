"""Attribution data model."""

from __future__ import annotations

import json
import math

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
        """Extract the first tool call from an OpenAI-shaped completion."""
        choices = response.get("choices") or []
        if not choices:
            return cls()
        message = choices[0].get("message") or {}
        calls = message.get("tool_calls") or []
        if not calls:
            return cls()

        fn = calls[0].get("function", {})
        raw = fn.get("arguments", "{}")
        try:
            arguments = json.loads(raw) if isinstance(raw, str) else dict(raw)
        except (json.JSONDecodeError, TypeError, ValueError):
            # A model that emits unparseable arguments is a finding, not a crash. Keep
            # the raw text so the disagreement still registers as influence.
            arguments = {"__unparsed__": raw}

        return cls(tool=fn.get("name"), arguments=arguments)

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
    granularity: str = "segment"
    sentence: str | None = None
    """Set for sentence-level contributors: the hash of the sentence, never its text."""

    model_config = {"populate_by_name": True}


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

    action: ActionSignature
    consequential: bool = True
    gate_reason: str = ""

    influence: InfluenceDistribution = Field(default_factory=InfluenceDistribution)
    necessity: InfluenceDistribution = Field(default_factory=InfluenceDistribution)
    """Which classes the action *required*, as distinct from which set its field values."""

    per_argument: dict[str, InfluenceDistribution] = Field(default_factory=dict)
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
            "confidence": round(self.confidence, 4),
            "model_calls": self.model_calls,
        }
