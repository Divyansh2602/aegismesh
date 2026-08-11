"""The pipeline, driven once, with every stage recorded.

This is the same sequence ``demo/phase3_demo.py`` runs, executed against the same
library code. Nothing here reimplements a step so that the website can show a nicer
version of it: if the API and the demo ever disagree, one of them is lying, and the
whole project is an argument about not doing that.
"""

from __future__ import annotations

import asyncio

from aegis.api.config import ApiSettings
from aegis.api.limits import CONCURRENCY
from aegis.api.runs import Run
from aegis.api.scenarios import (
    OPERATION,
    TOOL,
    build_delegation_chain,
    build_mandate_claim,
    build_mandate_context,
    build_registry,
)
from aegis.api.session import Session
from aegis.attribution.client import InProcessMockClient
from aegis.attribution.engine import AblationEvent, AttributionEngine
from aegis.attribution.models import ActionSignature
from aegis.log.log import TransparencyLog
from aegis.provenance.classifier import ContextClassifier
from aegis.provenance.models import ContextTrace

MODEL_LABEL = "aegis-mock-1 (bundled deterministic mock, not a hosted model)"
"""What produced these numbers, in the words the demos use.

Stated on every run rather than in a footnote. Attack-success against a model whose
susceptibility was written down says nothing about GPT-4 or Claude, and a site that
displays measured-looking numbers without saying what measured them is doing the exact
thing this project criticizes.
"""


def context_view(trace: ContextTrace) -> dict:
    """The classified context, with text, for the visitor who submitted it.

    Text is included here and *excluded* from anything that leaves the session -- the
    warrant carries hashes (``Segment.redacted``), and the shared log carries warrants.
    Showing a visitor the document they just pasted is not a disclosure; putting it
    somewhere another visitor can read it would be.
    """
    return {
        "trace_id": trace.trace_id,
        "model": trace.model,
        "mandate_id": trace.mandate_id,
        "principal": trace.principal,
        "bytes_by_class": {k.value: v for k, v in trace.bytes_by_class().items()},
        "segments": [
            {
                "segment_id": s.segment_id,
                "class": s.cls.value,
                "kind": s.source.kind,
                "origin": s.source.origin,
                "span": {"start": s.span.start, "end": s.span.end},
                "text": s.text,
                "classification_reason": s.classification_reason,
            }
            for s in trace.segments
        ],
    }


async def execute(
    run: Run,
    session: Session,
    log: TransparencyLog,
    log_lock: asyncio.Lock,
    settings: ApiSettings,
    attribution_slots: asyncio.Semaphore,
) -> None:
    """Run one scenario end to end, recording each stage on ``run``.

    Failures are recorded on the run and re-raised nowhere: this is a background task,
    and an exception escaping it would be swallowed by the event loop and leave the run
    stuck in "running" forever with no explanation. The visitor gets the failure.

    ``run.status`` is set last, and the final ``emit`` is what wakes every open stream --
    so a subscriber that sees a terminal status has already been handed every event.
    """
    try:
        await _execute(run, session, log, log_lock, settings, attribution_slots)
        run.status = "complete"
    except Exception as exc:  # noqa: BLE001 - recorded, surfaced, and ends the run
        run.status = "failed"
        run.error = f"{type(exc).__name__}: {exc}"
    finally:
        run.emit("end", {"status": run.status, "error": run.error})


async def _execute(
    run: Run,
    session: Session,
    log: TransparencyLog,
    log_lock: asyncio.Lock,
    settings: ApiSettings,
    attribution_slots: asyncio.Semaphore,
) -> None:
    body = run.scenario.body

    # ------------------------------------------------------------------ classify
    classifier = ContextClassifier(registry=build_registry(), mandate=build_mandate_context())
    trace = classifier.classify(body)
    view = context_view(trace)
    run.stage("context", view)
    run.emit(
        "classified",
        {"segments": len(trace.segments), "bytes_by_class": view["bytes_by_class"]},
    )

    # ------------------------------------------------------------- model proposes
    client = InProcessMockClient()
    trace.upstream_response = await client.complete(body)

    def on_ablation(event: AblationEvent) -> None:
        """Report one counterfactual as it completes.

        The visitor watching this is the point of Phase 5b: attribution takes tens of
        model calls, and a progress bar would tell them nothing about what the system is
        actually doing. ``comparable`` is streamed rather than left to be inferred from a
        zero influence, because those are different findings (design decision 6).
        """
        run.model_calls = event.sequence
        session.model_calls_spent += 1
        run.emit(
            "ablation",
            {
                "sequence": event.sequence,
                "granularity": event.granularity,
                "segment_id": event.segment_id,
                "class": event.cls.value,
                "excerpt_hash": event.excerpt_hash,
                "influence": round(event.influence, 4),
                "necessity": round(event.necessity, 4),
                "per_field": {f: round(v, 4) for f, v in event.per_field.items()},
                "comparable": event.comparable,
            },
        )

    engine = AttributionEngine(
        client=client,
        max_model_calls=settings.max_model_calls,
        observer=on_ablation,
    )
    proposed = []
    for signature in ActionSignature.all_from_response(trace.upstream_response):
        gated = engine.gate.evaluate(signature)
        proposed.append(
            {
                "tool": signature.tool,
                "arguments": signature.arguments,
                "consequential": gated.consequential,
                "gate_reason": gated.reason,
            }
        )
    # Every proposed call, not the first one. A response carrying `get_balance` beside
    # `execute_transfer` is the Phase 4 gate bypass (design decision 11), and a UI that
    # rendered only position 0 would hide the thing that was fixed.
    run.stage("proposal", {"model": MODEL_LABEL, "calls": proposed})
    run.emit("proposed", {"calls": proposed})

    # ----------------------------------------------------------------- attribute
    if attribution_slots.locked():
        # Say so rather than stalling silently. Waiting on API-CONC is the visitor meeting
        # the cost of attribution, which is the thing this phase is about measuring.
        run.emit("queued", {"control": CONCURRENCY.id, "reason": CONCURRENCY.name})
    async with attribution_slots:
        attribution = await engine.attribute(body, trace)
    run.emit(
        "gate",
        {"consequential": attribution.consequential, "reason": attribution.gate_reason},
    )

    # ``summary()`` rather than ``model_dump()``: the raw dump nests every distribution
    # under a ``weights`` key and leaves ProvenanceClass enums unflattened, which is a
    # shape the console would have to unpick on every read. summary() is also the exact
    # projection the demos print, so the site and the terminal show the same numbers.
    attribution_view = {
        **attribution.summary(),
        "mode": attribution.mode,
        "drilldown_threshold": attribution.drilldown_threshold,
        "model_ref": attribution.model_ref,
        "gate_reason": attribution.gate_reason,
        "action": attribution.action.model_dump(mode="json"),
        "top_contributors": [c.model_dump(mode="json") for c in attribution.top_contributors],
    }
    run.stage("attribution", attribution_view)
    run.emit(
        "attributed",
        {
            "model_calls": attribution.model_calls,
            "truncated": attribution.model_calls >= settings.max_model_calls,
            "argument_status": attribution.argument_status,
            "per_argument": {f: d.as_dict() for f, d in attribution.per_argument.items()},
        },
    )

    if not attribution.consequential:
        # Not a free pass. An unattributed action carries no evidence, so there is nothing
        # to warrant and nothing for a relying party to admit on.
        run.emit("halted", {"reason": "no consequential action was proposed"})
        return

    # --------------------------------------------------------------------- issue
    action = attribution.action
    warrant = session.issuer.issue(
        operation=action.tool or OPERATION,
        arguments=action.arguments,
        mandate=build_mandate_claim(),
        delegation_chain=build_delegation_chain(session.issuer_did),
        attribution=attribution,
        trace=trace,
        tool=TOOL,
    )
    document = warrant.to_document()
    run.stage("warrant", document)
    run.emit(
        "issued",
        {
            "warrant_id": warrant.id,
            "issuer": warrant.issuer,
            "issuer_decision": warrant.credentialSubject.policy_decision.decision,
            "rules_fired": warrant.credentialSubject.policy_decision.rules_fired,
        },
    )

    # ----------------------------------------------------------------- publish
    async with log_lock:
        # The append and the witness's observation of the resulting head have to be one
        # step. The log is shared, so between them another visitor could grow the tree,
        # and a consistency proof computed from a size the witness never accepted proves
        # nothing to the witness.
        previous = session.witness.tree_size
        receipt = log.append(document)
        session.witness.observe(
            log.signed_tree_head(),
            log.consistency_proof(previous) if previous else None,
        )
    run.leaf_index = receipt.leaf_index
    run.stage("receipt", receipt.model_dump(mode="json"))
    run.emit(
        "logged",
        {
            "leaf_index": receipt.leaf_index,
            "tree_size": receipt.tree_size,
            "root_hash": receipt.root_hash,
            "audit_path": len(receipt.inclusion_proof),
        },
    )

    # ----------------------------------------------------------------- enforce
    outcome = session.pep.verify(document, receipt, action.arguments)
    decision = {
        "admitted": outcome.admitted,
        "verdict": "PERMIT" if outcome.admitted else "REJECT",
        "issuer_decision": outcome.issuer_decision,
        "steps": [s.model_dump(mode="json") for s in outcome.steps],
        # ``outcome.reasons`` rather than ``policy_result.reasons``: a warrant that fails
        # an early step never reaches policy evaluation, so policy_result is None exactly
        # when something went most wrong.
        "reasons": list(outcome.reasons),
        "policy_reasons": list(outcome.policy_result.reasons) if outcome.policy_result else [],
    }
    run.stage("decision", decision)
    run.emit(
        "decision",
        {
            "verdict": decision["verdict"],
            "issuer_decision": decision["issuer_decision"],
            "failed_steps": [s.step for s in outcome.failed_steps],
            "reasons": decision["reasons"],
        },
    )
