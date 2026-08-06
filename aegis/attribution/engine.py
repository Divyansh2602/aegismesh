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
    Redundancy,
)
from aegis.common.hashing import hash_text
from aegis.provenance.classes import ProvenanceClass
from aegis.provenance.models import ContextTrace, MessageLocator, Segment

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
        span_ablation: bool = False,
        class_ablation: bool = False,
        max_model_calls: int = 400,
    ) -> None:
        self.client = client
        self.gate = gate or ConsequenceGate()
        self.resamples = max(1, resamples)
        self.mode = mode
        self.drilldown_threshold = drilldown_threshold
        self.sentence_drilldown = sentence_drilldown
        self.span_ablation = span_ablation
        """Ablate the individual occurrences of a proposed value (control C-15).

        Off by default so the cost baseline measured in Phase 2 stays comparable, and
        because it is only worth paying for on fields segment ablation could not reach.
        ``demo/phase4_eval.py`` reports both settings side by side rather than asserting
        which is right.
        """

        self.class_ablation = class_ablation
        """Ablate each provenance class as a whole, in addition to each segment.

        Costs at most one call per class present. Off by default for the same reason as
        ``span_ablation``: the question of whether it earns those calls is a measurement,
        not a default.
        """

        self.max_model_calls = max_model_calls

    async def attribute(
        self,
        body: dict,
        trace: ContextTrace,
        baseline: ActionSignature | None = None,
    ) -> AttributionResult:
        baseline = baseline or self._select_action(trace.upstream_response or {})
        decision = self.gate.evaluate(baseline)

        result = AttributionResult(
            action=baseline,
            consequential=decision.consequential,
            gate_reason=decision.reason,
            resamples=self.resamples,
            model_ref=trace.model,
            granularity=self._granularity(),
            mode=self.mode,
            drilldown_threshold=self.drilldown_threshold,
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

        span_scores: list[Contributor] = []
        if self.span_ablation:
            span_scores = await self._score_spans(body, trace, baseline, fields, budget)
            contributors += span_scores

        class_scores: list[Contributor] = []
        if self.class_ablation:
            class_scores = await self._score_classes(body, trace, baseline, fields, budget)

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

        for field in fields:
            status, distribution = _resolve_field(segment_scores, span_scores, field)
            result.argument_status[field] = status
            result.per_argument[field] = distribution

        if self.class_ablation:
            result.per_argument_redundancy = {f: _redundancy(class_scores, f) for f in fields}
            result.per_argument_class_influence = {
                f: _aggregate_field(class_scores, f, _REDUNDANCY_STATUS[redundancy])
                for f, redundancy in result.per_argument_redundancy.items()
            }

        result.per_argument_confidence = {
            f: (result.per_argument[f].confidence() if status == "attributed" else 0.0)
            for f, status in result.argument_status.items()
        }
        result.confidence = result.influence.confidence()
        return result

    # ------------------------------------------------------------------ internals

    def _select_action(self, response: dict) -> ActionSignature:
        """Pick which of the proposed calls to attribute.

        **The first consequential one, not the first one.** Reading position 0 and stopping
        was a complete bypass of the gate: a model emitting ``get_balance`` alongside
        ``execute_transfer`` had the read classified read-only and the transfer never
        measured at all. Found in Phase 4 by attacking the gate on purpose, which is what
        SPEC.md open question 3 asked for.

        Falling back to the first call when none is consequential keeps the gate's reason
        string about a real operation rather than an empty one, so a genuinely read-only
        turn still explains itself.
        """
        proposed = ActionSignature.all_from_response(response)
        for signature in proposed:
            if self.gate.evaluate(signature).consequential:
                return signature
        return proposed[0] if proposed else ActionSignature()

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

    async def _score_spans(
        self,
        body: dict,
        trace: ContextTrace,
        baseline: ActionSignature,
        fields: list[str],
        budget: _Budget,
    ) -> list[Contributor]:
        """Ablate each written occurrence of a proposed value (control C-15).

        This is the answer to the limitation SPEC.md section 3.3 records against itself.
        Per-field influence is measured only over ablations where the action survived, and
        a field whose sole source is the segment that also carries the transfer intent can
        therefore never be attributed: removing that segment removes the intent, the action
        cancels, and no comparable run exists. The ``amount`` in the invoice scenario is the
        worked example -- it appears only in the human's mandate.

        Ablating the number alone leaves the instruction to pay standing. The action
        survives, the run is comparable, and the amount is attributed to the class that
        actually wrote it. The intent and the value lived in one segment; they do not live
        in one span.

        Cost is bounded by the number of places the model's own output appears in the
        context, so it scales with how much of the action is quoted back rather than with
        the size of the context.
        """
        contributors: list[Contributor] = []
        values = {f: baseline.arguments.get(f) for f in fields}

        for segment in trace.segments:
            if not isinstance(segment.locator, MessageLocator):
                continue
            for field in fields:
                value = values[field]
                if value is None or not str(value).strip():
                    continue
                for start, end, text in ablation.segment_value_spans(body, segment, [value]):
                    if budget.exhausted:
                        return contributors
                    ablated = ablation.ablate_range(
                        body, segment.locator.message_index, start, end, mode=self.mode
                    )
                    measured = await self._measure(ablated, baseline, fields, budget)
                    contributors.append(
                        Contributor(
                            segment_id=segment.segment_id,
                            **{"class": segment.cls},
                            origin=segment.source.origin,
                            excerpt_hash=hash_text(text),
                            influence=measured.influence,
                            necessity=measured.necessity,
                            per_field=measured.per_field,
                            comparable=measured.comparable,
                            granularity="span",
                            field_hint=field,
                        )
                    )
        return contributors

    async def _score_classes(
        self,
        body: dict,
        trace: ContextTrace,
        baseline: ActionSignature,
        fields: list[str],
        budget: _Budget,
    ) -> list[Contributor]:
        """Remove each provenance class as a whole and re-run the decision.

        Leave-one-out cannot see redundancy. An attacker who writes the destination account
        into two retrieved documents survives every single-segment ablation -- remove
        either copy and the other still determines the value -- so the field reports
        ``invariant`` and looks exactly like a legitimately corroborated one. That is
        THREAT_MODEL.md residual risk 2, and it was the most likely home for an ADV-5
        evasion.

        Removing all of P3 at once removes both copies together. If the value moves, one
        class held the field on its own; if it does not, the value is genuinely
        overdetermined across classes and no attacker controls it.

        Classes with a single ablatable segment are skipped: their class-level result is
        their segment-level result, already measured, and paying a second call for the same
        counterfactual buys nothing.
        """
        by_class: dict[ProvenanceClass, list[Segment]] = {}
        for segment in trace.segments:
            if segment.locator is not None:
                by_class.setdefault(segment.cls, []).append(segment)

        contributors: list[Contributor] = []
        for cls, segments in sorted(by_class.items()):
            if len(segments) < 2:
                continue
            if budget.exhausted:
                break
            ablated = ablation.ablate_segments(body, segments, mode=self.mode)
            if ablated is None:
                continue

            measured = await self._measure(ablated, baseline, fields, budget)
            contributors.append(
                Contributor(
                    segment_id=f"class:{cls.value}",
                    **{"class": cls},
                    origin=None,
                    excerpt_hash=hash_text("|".join(s.source.content_hash for s in segments)),
                    influence=measured.influence,
                    necessity=measured.necessity,
                    per_field=measured.per_field,
                    comparable=measured.comparable,
                    granularity="class",
                )
            )
        return contributors

    def _granularity(self) -> list[str]:
        levels = ["segment"]
        if self.sentence_drilldown:
            levels.append("sentence")
        if self.span_ablation:
            levels.append("span")
        if self.class_ablation:
            levels.append("class")
        return levels

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

            # Look for the baseline's own operation among everything proposed, rather than
            # at whichever call came first. A model that reorders its parallel calls has
            # not cancelled anything, and scoring it as a cancellation would fabricate
            # necessity for a segment that changed nothing.
            observed = ActionSignature.select(response, baseline.tool)
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


def _resolve_field(
    segment_scores: list[Contributor],
    span_scores: list[Contributor],
    field: str,
) -> tuple[ArgumentStatus, InfluenceDistribution]:
    """Settle one field's status and distribution across the granularities that ran.

    Span-level results are consulted **only for fields segment-level ablation could not
    attribute**, and they replace rather than supplement the segment numbers. Both halves
    of that matter. A span sits inside a segment, so adding its influence to its parent's
    would count one cause twice and inflate whichever class happened to be quoted back most
    often. And a field already attributed at segment granularity has its answer; re-deriving
    it from a finer measurement would change published numbers for no gain.

    Sentence-level results are deliberately still excluded (SPEC.md open question 8). A
    sentence is a slice with no field association -- it double-counts its parent segment
    exactly as a span does, without a span's saving grace of being bound to one field.
    """
    status = _field_status(segment_scores, field)
    if status == "attributed" or not span_scores:
        return status, _aggregate_field(segment_scores, field, status)

    for_field = [c for c in span_scores if c.field_hint == field]
    span_status = _field_status(for_field, field)
    if span_status == "attributed":
        return span_status, _aggregate(for_field, field=field)
    return status, _aggregate_field(segment_scores, field, status)


#: Class-level ablation carries exactly the same all-zero ambiguity as segment-level, so it
#: is resolved the same way rather than a second way. The first version of this code called
#: ``_aggregate`` directly and reproduced design decision 6 one layer up: a field measured
#: to have no class-level influence came back as the uniform fallback, asserting a 0.2
#: untrusted share of a value class-level ablation had just shown no class controls. The
#: bug that denied a legitimate payment in Phase 3 is easy to write twice.
_REDUNDANCY_STATUS: dict[Redundancy, ArgumentStatus] = {
    "within_class": "attributed",
    "cross_class": "invariant",
    "unmeasured": "unknown",
}


def _redundancy(class_scores: list[Contributor], field: str) -> Redundancy:
    """Read a field's redundancy off the class-level ablations.

    ``within_class`` whenever removing some class as a whole moved the value: that class
    determines the field by itself, whether through one pivotal segment or several
    redundant ones. Combined with ``argument_status == "invariant"`` -- no *single* segment
    moved it -- that pair is the redundant-encoding signature, and when the class is P3 it
    is an ADV-5 evasion caught rather than missed.

    ``cross_class`` requires a comparable run: classes were removed, the action survived,
    and the value held. Without one there is nothing to conclude, so the answer is
    ``unmeasured`` and policy is left to fail closed on the status instead.
    """
    if any(c.per_field.get(field, 0.0) > NOISE_FLOOR for c in class_scores):
        return "within_class"
    if any(c.comparable for c in class_scores):
        return "cross_class"
    return "unmeasured"


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
