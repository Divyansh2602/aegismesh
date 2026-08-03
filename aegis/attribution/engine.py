"""aegis-causa — the attribution engine.

Given the request an agent made, the provenance-tagged trace of it, and the action the
model proposed, measure which provenance classes actually *caused* that action.

Method: leave-one-out counterfactual ablation (SPEC.md section 3). Remove one segment,
re-run the decision, and see whether the action survives. Influence is disagreement.

Two properties matter more than the numbers:

  * Attribution runs per *argument*, not just per action. "The transfer was 87% caused by
    untrusted content" is weaker and less actionable than "the *destination account* was".
  * Failure to attribute drives confidence to zero rather than producing a clean-looking
    result, so an attacker who defeats the measurement gets a denial, not a bypass.
"""

from __future__ import annotations

from typing import Protocol

from aegis.attribution import ablation
from aegis.attribution.gate import ConsequenceGate
from aegis.attribution.models import (
    NOISE_FLOOR,
    ActionSignature,
    ArgumentStatus,
    AttributionResult,
    Contributor,
    InfluenceDistribution,
)
from aegis.common.hashing import hash_text
from aegis.provenance.classes import ProvenanceClass
from aegis.provenance.models import ContextTrace, MessageLocator

#: A segment must reach this share of total segment-level influence before its sentences
#: are worth the extra model calls.
DEFAULT_DRILLDOWN_THRESHOLD = 0.15


class ModelClient(Protocol):
    """Whatever can execute a chat-completions request."""

    async def complete(self, body: dict) -> dict: ...


class AttributionEngine:
    def __init__(
        self,
        client: ModelClient,
        gate: ConsequenceGate | None = None,
        resamples: int = 1,
        mode: ablation.AblationMode = "placeholder",
        drilldown_threshold: float = DEFAULT_DRILLDOWN_THRESHOLD,
        sentence_drilldown: bool = True,
        max_model_calls: int = 400,
    ) -> None:
        self.client = client
        self.gate = gate or ConsequenceGate()
        self.resamples = max(1, resamples)
        self.mode = mode
        self.drilldown_threshold = drilldown_threshold
        self.sentence_drilldown = sentence_drilldown
        self.max_model_calls = max_model_calls

    async def attribute(
        self,
        body: dict,
        trace: ContextTrace,
        baseline: ActionSignature | None = None,
    ) -> AttributionResult:
        baseline = baseline or ActionSignature.from_response(trace.upstream_response or {})
        decision = self.gate.evaluate(baseline)

        result = AttributionResult(
            action=baseline,
            consequential=decision.consequential,
            gate_reason=decision.reason,
            resamples=self.resamples,
            model_ref=trace.model,
            granularity=["segment", "sentence"] if self.sentence_drilldown else ["segment"],
        )

        if not decision.consequential:
            # Not a free pass -- an unattributed action carries zero confidence, so policy
            # still sees it as unproven rather than as approved.
            result.granularity = []
            return result

        fields = sorted(baseline.fields())
        budget = _Budget(self.max_model_calls)

        segment_scores = await self._score_segments(body, trace, baseline, fields, budget)
        contributors = list(segment_scores)

        if self.sentence_drilldown:
            contributors += await self._drill_down(
                body, trace, baseline, fields, segment_scores, budget
            )

        result.model_calls = budget.spent
        # Rank by value-causation first, necessity second. Ranking by raw influence puts
        # the human mandate at the top of every poisoned case -- removing it cancels the
        # action, so it scores 1.0 -- which buries the segment that actually set the
        # hijacked field. An investigator asking "what did this?" wants the cause of the
        # value, and necessity is reported separately for those who want the other answer.
        result.top_contributors = sorted(
            contributors,
            key=lambda c: (max(c.per_field.values(), default=0.0), c.influence),
            reverse=True,
        )[:10]

        result.influence = _aggregate(segment_scores, field=None)
        result.necessity = _aggregate(segment_scores, field=None, use_necessity=True)
        result.argument_status = {f: _field_status(segment_scores, f) for f in fields}
        result.per_argument = {
            f: _aggregate_field(segment_scores, f, result.argument_status[f]) for f in fields
        }
        result.per_argument_confidence = {
            f: (result.per_argument[f].confidence() if status == "attributed" else 0.0)
            for f, status in result.argument_status.items()
        }
        result.confidence = result.influence.confidence()
        return result

    # ------------------------------------------------------------------ internals

    async def _score_segments(
        self,
        body: dict,
        trace: ContextTrace,
        baseline: ActionSignature,
        fields: list[str],
        budget: _Budget,
    ) -> list[Contributor]:
        contributors: list[Contributor] = []

        for segment in trace.segments:
            ablated = ablation.ablate(body, segment, mode=self.mode)
            if ablated is None:
                continue

            measured = await self._measure(ablated, baseline, fields, budget)
            contributors.append(
                Contributor(
                    segment_id=segment.segment_id,
                    **{"class": segment.cls},
                    origin=segment.source.origin,
                    excerpt_hash=segment.source.content_hash,
                    influence=measured.influence,
                    necessity=measured.necessity,
                    per_field=measured.per_field,
                    comparable=measured.comparable,
                    granularity="segment",
                )
            )
        return contributors

    async def _drill_down(
        self,
        body: dict,
        trace: ContextTrace,
        baseline: ActionSignature,
        fields: list[str],
        segment_scores: list[Contributor],
        budget: _Budget,
    ) -> list[Contributor]:
        """Split influential segments into sentences and score each one.

        Only segments that already showed influence are drilled. A long document that
        caused nothing does not become cheaper to ignore by being long.
        """
        total = sum(c.influence for c in segment_scores)
        if total <= NOISE_FLOOR:
            return []

        results: list[Contributor] = []
        for scored in segment_scores:
            if scored.influence / total < self.drilldown_threshold:
                continue
            segment = trace.segment_by_id(scored.segment_id)
            if segment is None or not isinstance(segment.locator, MessageLocator):
                # Tool declarations have no interior to drill into.
                continue

            ranges = ablation.segment_sentences(body, segment)
            if len(ranges) < 2:
                # A single-sentence segment is already at sentence granularity.
                continue

            for start, end, sentence in ranges:
                if budget.exhausted:
                    return results
                ablated = ablation.ablate_range(
                    body, segment.locator.message_index, start, end, mode=self.mode
                )
                measured = await self._measure(ablated, baseline, fields, budget)
                if measured.influence <= NOISE_FLOOR:
                    continue
                results.append(
                    Contributor(
                        segment_id=segment.segment_id,
                        **{"class": segment.cls},
                        origin=segment.source.origin,
                        excerpt_hash=hash_text(sentence),
                        influence=measured.influence,
                        necessity=measured.necessity,
                        per_field=measured.per_field,
                        comparable=measured.comparable,
                        granularity="sentence",
                        sentence=hash_text(sentence),
                    )
                )
        return results

    async def _measure(
        self,
        ablated_body: dict,
        baseline: ActionSignature,
        fields: list[str],
        budget: _Budget,
    ) -> _Measurement:
        """Run the ablated request and score disagreement against the baseline.

        The important subtlety: **necessity and value-causation are different claims and
        must not be summed.**

        Removing the human's mandate typically cancels the action outright -- no tool call
        at all. That proves the mandate was *necessary* for the action to occur. It proves
        nothing about which account the money went to, because in the counterfactual there
        was no account to compare. Scoring cancellation as field-level influence made the
        human mandate look like the cause of an attacker-supplied destination, which is
        precisely backwards.

        So per-field influence is measured **only over runs where the same tool was still
        called**, i.e. conditioned on the action surviving. Cancellations are recorded
        separately as necessity. A segment whose ablation always cancels the action yields
        no field-level evidence at all -- an honest "undefined" rather than a fabricated
        cause.
        """
        cancellations = 0
        field_disagreements = dict.fromkeys(fields, 0)
        comparable_runs = 0
        runs = 0

        for _ in range(self.resamples):
            if budget.exhausted:
                break
            response = await self.client.complete(ablated_body)
            budget.spend()
            runs += 1

            observed = ActionSignature.from_response(response)
            if not observed.same_tool(baseline):
                cancellations += 1
                continue

            comparable_runs += 1
            for field in fields:
                if not observed.agrees_on(baseline, field):
                    field_disagreements[field] += 1

        if runs == 0:
            return _Measurement(0.0, 0.0, dict.fromkeys(fields, 0.0), False)

        per_field = {
            f: (field_disagreements[f] / comparable_runs if comparable_runs else 0.0)
            for f in fields
        }
        necessity = cancellations / runs

        # Action-level influence legitimately includes cancellation: a segment whose
        # removal stops the action entirely certainly influenced the action.
        influence = max([necessity, *per_field.values()]) if per_field else necessity
        return _Measurement(influence, necessity, per_field, comparable_runs > 0)


def _field_status(contributors: list[Contributor], field: str) -> ArgumentStatus:
    """Classify what the measurement established about one field.

    The distinction this draws was missing until Phase 3 tried to enforce on the evidence,
    and its absence produced a false denial of a perfectly legitimate payment.

    In the clean invoice case the destination account appears in both the human's mandate
    and the operator's own ledger. Removing either one leaves the other, so no single
    ablation changes the value and every class scores zero. The old code normalized that
    all-zero total into a *uniform* distribution -- which asserts that untrusted external
    content holds a 0.2 share of causing the destination, a claim no measurement supports
    and one that trips a policy forbidding any untrusted influence on that field.

    Zero measured influence after a comparable run is evidence of *invariance*. Zero
    measured influence because every run cancelled the action is an absence of evidence.
    Only the second is grounds to fail closed.
    """
    for contributor in contributors:
        if contributor.per_field.get(field, 0.0) > NOISE_FLOOR:
            return "attributed"
    if any(contributor.comparable for contributor in contributors):
        return "invariant"
    return "unknown"


def _aggregate_field(
    contributors: list[Contributor],
    field: str,
    status: ArgumentStatus,
) -> InfluenceDistribution:
    """Per-field influence, with the all-zero case resolved by ``status``.

    ``invariant`` yields an empty distribution -- every class measurably zero -- rather
    than the uniform fallback, which would fabricate influence for classes shown to have
    none. ``unknown`` keeps the uniform fallback, because there the fallback says the true
    thing: we do not know, and policy should fail closed (control C-16).
    """
    if status == "invariant":
        return InfluenceDistribution(weights={})
    return _aggregate(contributors, field=field)


def _aggregate(
    contributors: list[Contributor],
    field: str | None,
    use_necessity: bool = False,
) -> InfluenceDistribution:
    totals: dict[ProvenanceClass, float] = {}
    for contributor in contributors:
        if use_necessity:
            value = contributor.necessity
        elif field is None:
            value = contributor.influence
        else:
            value = contributor.per_field.get(field, 0.0)
        if value > NOISE_FLOOR:
            totals[contributor.cls] = totals.get(contributor.cls, 0.0) + value
    return InfluenceDistribution.from_totals(totals)


class _Measurement:
    """One ablation's result, keeping necessity and value-causation separate."""

    __slots__ = ("influence", "necessity", "per_field", "comparable")

    def __init__(
        self,
        influence: float,
        necessity: float,
        per_field: dict[str, float],
        comparable: bool,
    ) -> None:
        self.influence = influence
        self.necessity = necessity
        self.per_field = per_field
        self.comparable = comparable


class _Budget:
    """Hard ceiling on model calls per attribution (control C-18)."""

    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.spent = 0

    def spend(self) -> None:
        self.spent += 1

    @property
    def exhausted(self) -> bool:
        return self.spent >= self.limit
