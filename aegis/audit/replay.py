"""Re-run a warrant's attribution and check whether the issuer told the truth.

Everything else in this project verifies that a warrant is **authentic**: the signature is
the issuer's, the leaf is in the log, the log's head is the one a witness accepted. None of
that touches whether the attribution *inside* the warrant is correct. An operator running
the issuer (ADV-4) can measure that untrusted content set the destination account, sign a
credential saying the human did, and every verification step passes.

The transparency log makes that lie **non-repudiable** -- permanently and provably theirs.
This module makes it **falsifiable**: given the underlying trace, an auditor re-runs the
same measurement under the same committed conditions and compares. That is the strongest
property available short of attested execution, and it is worth being precise about what
it is not. A contradiction is evidence the claim is not reproducible; it is not proof of
intent, and honest causes exist (a provider silently revising a model behind a stable
name is the obvious one). The verdict vocabulary keeps that distinction rather than
collapsing it into pass/fail.

## Why the trace binding comes first

The auditor is handed a trace by the party under investigation. Re-running against it
without checking it against ``replay_ref.trace_hash`` would let the operator supply a
*different* context -- one on which the signed numbers are perfectly reproducible -- and
walk out with a clean bill. So the first check is that the disclosed trace is the one the
signature commits to, and failing it yields ``inconclusive``, never ``consistent``.

## Why partial commitments produce ``inconclusive``

Phase 3 committed to the context, the model and the method version. Building this verifier
showed that is not enough to determine the measurement: ``mode`` and
``drilldown_threshold`` change the counterfactuals and were not carried. Both were added to
``ReplayRef`` in Phase 4. Warrants issued before that verify by signature and cannot be
replayed, and this module says so instead of silently replaying under its own defaults --
which would produce confident contradictions of issuers who did nothing wrong.
"""

from __future__ import annotations

from decimal import Decimal
from typing import Any, Literal

from pydantic import BaseModel, Field

from aegis.attribution.engine import AttributionEngine, ModelClient
from aegis.attribution.models import ActionSignature, AttributionResult
from aegis.common.decimals import format_distribution, format_score, parse_score
from aegis.provenance.models import ContextTrace
from aegis.warrant.issuer import trace_commitment
from aegis.warrant.models import AttributionClaim

ReplayVerdict = Literal["consistent", "contradicted", "inconclusive"]

#: How far a replayed score may sit from the signed one before it counts as a
#: contradiction. Scores cross the signature quantized to 0.0001, so anything at or below
#: that quantum is a rounding artifact rather than a disagreement. Deliberately not looser:
#: a tolerance wide enough to absorb real drift is also wide enough to absorb a lie.
TOLERANCE = Decimal("0.0001")


class ReplayFinding(BaseModel):
    """One comparison between what was signed and what the re-run measured."""

    check: str
    verdict: ReplayVerdict
    detail: str = ""
    signed: str | None = None
    replayed: str | None = None


class ReplayReport(BaseModel):
    findings: list[ReplayFinding] = Field(default_factory=list)

    @property
    def verdict(self) -> ReplayVerdict:
        """The worst finding wins, and ``contradicted`` outranks ``inconclusive``.

        A trace that binds and a distribution that does not is a contradiction even if some
        later check could not be evaluated. The other order would let an issuer bury a
        provable discrepancy under an unevaluable one.
        """
        verdicts = {f.verdict for f in self.findings}
        if "contradicted" in verdicts:
            return "contradicted"
        if "inconclusive" in verdicts or not self.findings:
            return "inconclusive"
        return "consistent"

    @property
    def contradictions(self) -> list[ReplayFinding]:
        return [f for f in self.findings if f.verdict == "contradicted"]

    def as_dict(self) -> dict:
        return {
            "verdict": self.verdict,
            "checks": len(self.findings),
            "contradictions": len(self.contradictions),
            "findings": [f.model_dump() for f in self.findings],
        }


async def replay_attribution(
    claim: AttributionClaim | dict,
    body: dict,
    trace: ContextTrace,
    client: ModelClient,
    baseline: ActionSignature | None = None,
) -> ReplayReport:
    """Re-measure ``claim`` over a disclosed ``trace`` and report every disagreement.

    ``body`` and ``trace`` are the disclosure: the request as the model received it and the
    classified context the issuer says it measured. ``client`` is the auditor's own access
    to the model named in ``replay_ref`` -- their own key, their own account, so the issuer
    cannot arrange a different answer for the party checking them.
    """
    claim = _as_claim(claim)
    report = ReplayReport()

    replay_ref = claim.replay_ref
    if replay_ref is None:
        report.findings.append(
            ReplayFinding(
                check="replay_ref present",
                verdict="inconclusive",
                detail="the warrant carries no replay commitment; nothing to replay against",
            )
        )
        return report

    _check_binding(report, claim, trace)
    if report.verdict == "inconclusive":
        # A trace that does not match the commitment is not the measured context, so
        # anything measured over it says nothing about the issuer either way.
        return report

    engine = _engine_from(claim, client)
    if engine is None:
        report.findings.append(
            ReplayFinding(
                check="measurement settings committed",
                verdict="inconclusive",
                detail=(
                    "replay_ref does not carry the ablation mode or drilldown threshold, so "
                    "the committed conditions do not determine the measurement. Warrants "
                    "issued before those fields existed cannot be replayed."
                ),
            )
        )
        return report

    result = await engine.attribute(body, trace, baseline=baseline)
    _check_action(report, claim, result)
    _compare(report, claim, result)
    return report


# --------------------------------------------------------------------- internals


def _as_claim(claim: AttributionClaim | dict) -> AttributionClaim:
    if isinstance(claim, AttributionClaim):
        return claim
    # A warrant read off disk arrives as a plain document; accept either that or the
    # credentialSubject.attribution block already extracted.
    document = claim.get("credentialSubject", {}).get("attribution", claim)
    return AttributionClaim.model_validate(document)


def _check_binding(report: ReplayReport, claim: AttributionClaim, trace: ContextTrace) -> None:
    """Confirm the disclosed trace is the one the signature commits to."""
    reference = claim.replay_ref
    assert reference is not None  # guarded by the caller

    recomputed = trace_commitment(trace)
    report.findings.append(
        ReplayFinding(
            check="disclosed trace matches the signed commitment",
            verdict="consistent" if recomputed == reference.trace_hash else "inconclusive",
            detail=(
                ""
                if recomputed == reference.trace_hash
                else "the disclosure is not the context the warrant was measured over"
            ),
            signed=reference.trace_hash,
            replayed=recomputed,
        )
    )

    disclosed = [segment.source.content_hash for segment in trace.segments]
    ordered = disclosed == reference.segment_hashes
    report.findings.append(
        ReplayFinding(
            check="segment hashes match in order",
            verdict="consistent" if ordered else "inconclusive",
            detail=(
                ""
                if ordered
                else (
                    "leave-one-out walks the segments in order, so a reordering produces a "
                    "different set of counterfactuals"
                )
            ),
            signed=f"{len(reference.segment_hashes)} segments",
            replayed=f"{len(disclosed)} segments",
        )
    )

    same_model = reference.model_ref == (trace.model or reference.model_ref)
    report.findings.append(
        ReplayFinding(
            check="replaying against the model the warrant names",
            verdict="consistent" if same_model else "inconclusive",
            detail=(
                ""
                if same_model
                else "a different model measures a different quantity; the issuer is not impeached"
            ),
            signed=reference.model_ref,
            replayed=trace.model,
        )
    )


def _engine_from(claim: AttributionClaim, client: ModelClient) -> AttributionEngine | None:
    """Rebuild the engine the warrant says produced these numbers.

    Returns ``None`` when the commitment is incomplete. Falling back to defaults here would
    be the single most dangerous line in the module: it would replay under the auditor's
    settings while reporting a verdict about the issuer's.
    """
    reference = claim.replay_ref
    if reference is None or not reference.mode or not reference.drilldown_threshold:
        return None

    granularity = set(claim.granularity)
    return AttributionEngine(
        client=client,
        resamples=claim.resamples,
        mode=reference.mode,  # type: ignore[arg-type]
        drilldown_threshold=float(parse_score(reference.drilldown_threshold)),
        sentence_drilldown="sentence" in granularity,
        span_ablation="span" in granularity,
        class_ablation="class" in granularity,
    )


def _check_action(
    report: ReplayReport, claim: AttributionClaim, result: AttributionResult
) -> None:
    """The re-run must reproduce the same proposed action before its numbers mean anything.

    If the model now proposes something else, every field-level comparison below is
    comparing measurements of two different decisions. That is a reproducibility failure,
    not a finding against the issuer.
    """
    reproduced = bool(result.action.tool)
    report.findings.append(
        ReplayFinding(
            check="the re-run reproduces a proposed action",
            verdict="consistent" if reproduced else "inconclusive",
            detail=(
                ""
                if reproduced
                else "the model proposed no action on replay; nothing to compare against"
            ),
            replayed=result.action.tool,
        )
    )


def _compare(report: ReplayReport, claim: AttributionClaim, result: AttributionResult) -> None:
    """Compare every signed number against the re-measured one.

    Comparison happens on the **encoded** forms -- fixed-precision decimal strings -- not on
    floats. Those strings are what the signature covers, so comparing anything else checks a
    quantity the issuer never committed to, and reintroduces at the audit path exactly the
    serialization bug that ``common/decimals.py`` exists to keep out of the wire format.
    """
    _compare_distribution(report, "influence", claim.influence, result.influence.weights)
    _compare_distribution(report, "necessity", claim.necessity, result.necessity.weights)
    _compare_score(report, "confidence", claim.confidence, result.confidence)

    fields = sorted(set(claim.per_argument) | set(result.per_argument))
    for field in fields:
        _compare_distribution(
            report,
            f"per_argument[{field}]",
            claim.per_argument.get(field, {}),
            result.per_argument[field].weights if field in result.per_argument else {},
        )

    for field in sorted(set(claim.argument_status) | set(result.argument_status)):
        signed = claim.argument_status.get(field)
        replayed = result.argument_status.get(field)
        report.findings.append(
            ReplayFinding(
                check=f"argument_status[{field}]",
                verdict="consistent" if signed == replayed else "contradicted",
                signed=signed,
                replayed=replayed,
                detail=(
                    ""
                    if signed == replayed
                    else "the re-run establishes something different about this field"
                ),
            )
        )


def _compare_distribution(
    report: ReplayReport,
    check: str,
    signed: dict[str, str],
    replayed_weights: dict[Any, float],
) -> None:
    replayed = format_distribution(replayed_weights)
    classes = sorted(set(signed) | set(replayed))

    differences = [
        c
        for c in classes
        if abs(parse_score(signed.get(c, "0.0000")) - parse_score(replayed.get(c, "0.0000")))
        > TOLERANCE
    ]
    report.findings.append(
        ReplayFinding(
            check=check,
            verdict="consistent" if not differences else "contradicted",
            detail="" if not differences else f"differs on {', '.join(differences)}",
            signed=str(signed),
            replayed=str(replayed),
        )
    )


def _compare_score(report: ReplayReport, check: str, signed: str, replayed: float) -> None:
    encoded = format_score(replayed)
    agrees = abs(parse_score(signed) - parse_score(encoded)) <= TOLERANCE
    report.findings.append(
        ReplayFinding(
            check=check,
            verdict="consistent" if agrees else "contradicted",
            signed=signed,
            replayed=encoded,
        )
    )
