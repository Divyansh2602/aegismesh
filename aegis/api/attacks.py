"""Attacking the defence, as API operations rather than demo prose.

``demo/phase3_demo.py`` scenes 7-10 attack the system after it has worked. They are the
most convincing part of the demo and, until now, the part a visitor could not reach: the
API could run the pipeline but not turn on it. This module exposes those four attacks so
the console's attack lab drives real code rather than replaying a recorded transcript.

Three rules shaped every one of them.

**Nothing here may damage the shared log.** The transparency log is the one piece of state
every visitor holds in common, and a receipt handed to one visitor is checked against a
root another visitor's witness accepted. An attack that genuinely forked it would break
every outstanding proof on the site -- so ``fork_log`` builds its own tree and points a
*fresh* witness at it. That is not a weakening of the demonstration. It is the same reason
a real operator's fork is detectable: the honest history is held by somebody else.

**The attacks call the same code the honest path calls.** The permissive issuer is a real
``WarrantIssuer`` with a real policy, the verdicts come from the session's real PEP, and
the fork is a real ``ForkDetected`` out of a real ``Witness``. Reimplementing any of it so
the website could show a tidier failure would make the attack lab the one screen on this
site whose output is not evidence.

**A defended attack is reported as defended, and the reason is named.** ``defended`` says
whether the attacker lost, ``detected_by`` says what stopped them, and ``note`` carries the
caveat where there is one. Two of Phase 4's attack scenes end with the attacker winning and
both stay in the output; the same rule applies here, which is why the field exists rather
than being assumed.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass

from fastapi import HTTPException

from aegis.api.runs import Evidence, Run
from aegis.api.scenarios import OPERATION, TOOL, build_delegation_chain, build_mandate_claim
from aegis.api.session import Session
from aegis.log.log import TransparencyLog, encode_hash
from aegis.log.witness import ForkDetected, Witness
from aegis.policy.library import permissive_operator_policy
from aegis.warrant.issuer import WarrantIssuer

#: Leaves in the doctored history ``fork_log`` builds. Small on purpose -- see that
#: function for why the cost of this attack must not scale with the shared log.
SHADOW_LEAVES = 3

#: What ``tamper_attribution`` rewrites a field's causation to: wholly the human's
#: mandate. It is the lie an operator would want to tell, because P0 is the one class a
#: relying party's policy will not object to.
WHITEWASH = {"P0": "1.0000"}


@dataclass(frozen=True)
class Attack:
    """One way to attack the defence, and what the design says should happen."""

    name: str
    title: str
    what_it_does: str
    expectation: str
    control: str
    """The control or design property that is supposed to stop this."""


CATALOGUE: dict[str, Attack] = {
    "tamper_attribution": Attack(
        name="tamper_attribution",
        title="The operator edits the warrant to blame the human",
        what_it_does=(
            "Rewrites the per-argument attribution inside an already-issued warrant so it "
            "reads as though the human's mandate caused the field, then presents it."
        ),
        expectation="rejected: the signature covers the canonicalized credential",
        control="SPEC step 3 (proof verification), and step 7 independently",
    ),
    "forge_permit": Attack(
        name="forge_permit",
        title="A dishonest issuer signs a permit",
        what_it_does=(
            "Re-issues the same measurement under a permissive issuer policy, so the "
            "warrant is genuinely signed, genuinely logged, and says PERMIT."
        ),
        expectation="rejected: the relying party evaluates its own policy",
        control="SPEC step 10 (relying-party policy evaluation)",
    ),
    "fork_log": Attack(
        name="fork_log",
        title="The operator shows one history to the bank and another to the auditor",
        what_it_does=(
            "Builds a second history under the log's own signing key and presents both to "
            "an independent witness."
        ),
        expectation="detected: a witness in another trust domain holds the other root",
        control="SPEC step 7 (inclusion against an independently held root)",
    ),
    "replay_arguments": Attack(
        name="replay_arguments",
        title="A valid warrant is replayed onto a bigger transfer",
        what_it_does=(
            "Takes an authentic, correctly issued, correctly logged warrant and presents "
            "it alongside different arguments than the ones it authorised."
        ),
        expectation="rejected: the warrant binds a hash of its arguments",
        control="C-14 (arguments binding), SPEC step 5",
    ),
}


def catalogue() -> list[dict]:
    """The attacks, as data, so the console renders buttons from the source of truth."""
    return [
        {
            "name": a.name,
            "title": a.title,
            "what_it_does": a.what_it_does,
            "expectation": a.expectation,
            "control": a.control,
        }
        for a in CATALOGUE.values()
    ]


async def execute(
    name: str,
    run: Run,
    session: Session,
    log: TransparencyLog,
    log_lock,
) -> dict:
    """Run one attack against ``run`` and report what the defence did about it."""
    attack = CATALOGUE.get(name)
    if attack is None:
        raise HTTPException(
            status_code=404,
            detail=f"unknown attack; known: {sorted(CATALOGUE)}",
        )

    evidence = _require_evidence(run)
    if name == "fork_log":
        # The only attack that needs no warrant: it attacks the log, not the credential.
        return _fork_log(attack, run, log)

    warrant = _require_warrant(run)
    if evidence.receipt is None:
        raise HTTPException(
            status_code=409,
            detail="this run published no warrant to the log, so there is nothing to attack",
        )

    if name == "tamper_attribution":
        return _tamper_attribution(attack, evidence, session, warrant)
    if name == "forge_permit":
        return await _forge_permit(attack, evidence, session, log, log_lock)
    return _replay_arguments(attack, evidence, session, warrant)


# --------------------------------------------------------------------------- guards


def _require_evidence(run: Run) -> Evidence:
    if run.evidence is None:
        raise HTTPException(
            status_code=409,
            detail=(
                f"this run has no attribution to attack (status={run.status}"
                + (f", error={run.error}" if run.error else "")
                + "). Attacks operate on evidence a run actually produced; none is invented."
            ),
        )
    return run.evidence


def _require_warrant(run: Run) -> dict:
    if "warrant" not in run.stages:
        raise HTTPException(
            status_code=409,
            detail=(
                "this run issued no warrant, so there is no credential to attack. A run "
                "that proposed no consequential action has nothing to warrant."
            ),
        )
    return run.stages["warrant"]


# -------------------------------------------------------------------------- attacks


def _tamper_attribution(
    attack: Attack, evidence: Evidence, session: Session, warrant: dict
) -> dict:
    """Rewrite a signed score and watch the signature stop covering it."""
    field = _field_to_blame(warrant)
    tampered = copy.deepcopy(warrant)
    per_argument = tampered["credentialSubject"]["attribution"]["per_argument"]
    original = per_argument.get(field)
    per_argument[field] = dict(WHITEWASH)

    outcome = session.pep.verify(tampered, evidence.receipt, evidence.arguments)
    return {
        **_envelope(attack),
        "mutation": {
            "field": field,
            "before": original,
            "after": {"P0": "1.0000"},
            "description": f"rewrote {field} influence to P0 1.0000",
        },
        "defended": not outcome.admitted,
        "detected_by": "SPEC step 3 — the proof no longer covers the credential",
        "enforcement": _enforcement(outcome),
        "note": (
            "Step 3 is the one that matters: the signature covers the canonicalized "
            "credential, so editing a score breaks it. Step 7 fails for a second and "
            "independent reason — the edited document is not the one in the log. A replay "
            "step may also fail here because this warrant was already presented once "
            "during the run itself; that is an artifact of attacking a warrant that has "
            "already been used, not a third defence."
        ),
    }


async def _forge_permit(
    attack: Attack,
    evidence: Evidence,
    session: Session,
    log: TransparencyLog,
    log_lock,
) -> dict:
    """Sign an honest measurement into a dishonest verdict, and log it properly.

    This one appends to the shared log, unlike the others, and that is correct rather
    than an oversight: the warrant is genuine. It is signed by this session's real issuer
    key over the real attribution, and an issuer that could not log its permits would be
    an issuer whose log proved nothing. What is dishonest is the *verdict*, and the point
    of the attack is that the relying party does not take the issuer's word for it.
    """
    lenient = WarrantIssuer(
        issuer_did=session.issuer_did,
        signing_key=session.issuer_key,
        verification_method=session.verification_method,
        policy=permissive_operator_policy(),
    )
    warrant = lenient.issue(
        operation=evidence.attribution.action.tool or OPERATION,
        arguments=evidence.arguments,
        mandate=build_mandate_claim(),
        delegation_chain=build_delegation_chain(session.issuer_did),
        attribution=evidence.attribution,
        trace=evidence.trace,
        tool=TOOL,
    )
    document = warrant.to_document()

    async with log_lock:
        # Identical to the honest path in ``runner``: append and witness observation are
        # one step, because the log is shared and a consistency proof computed from a size
        # the witness never accepted proves nothing to the witness.
        previous = session.witness.tree_size
        receipt = log.append(document)
        session.witness.observe(
            log.signed_tree_head(),
            log.consistency_proof(previous) if previous else None,
        )

    outcome = session.pep.verify(document, receipt, evidence.arguments)
    return {
        **_envelope(attack),
        "mutation": {
            "issuer_policy": "permissive_operator_policy",
            "description": (
                "same measurement, same key, same log — an issuer policy that permits "
                "what the honest one refused"
            ),
            "genuinely_signed": True,
            "genuinely_logged": True,
            "leaf_index": receipt.leaf_index,
        },
        "defended": not outcome.admitted,
        "detected_by": "SPEC step 10 — the relying party evaluates its own policy",
        "enforcement": _enforcement(outcome),
        "note": (
            "Every authenticity check passes, because nothing here is forged in the "
            "cryptographic sense. Step 10 is the crux: a PEP that honoured the issuer's "
            "verdict would have learned nothing from the warrant that an HTTP 200 could "
            "not have told it. The issuer's own decision travels as a claim, not as "
            "authority."
        ),
    }


def _fork_log(attack: Attack, run: Run, log: TransparencyLog) -> dict:
    """Show an independent witness two histories that cannot both be true.

    **The shared log is never written to.** Every visitor's receipts are checked against
    roots derived from it, so genuinely forking it would invalidate proofs already handed
    out — including proofs held by people who are not attacking anything.

    The order of presentation is deliberate and is a cost decision, not a narrative one.
    The demo builds a shadow history as long as the real one, which is O(n) appends each
    costing O(n) hashes — quadratic in the size of a shared log that grows for the life of
    the deployment, on an endpoint a stranger can call. Instead the witness accepts a short
    doctored history *first* and is then shown the real log's head. The conclusion is
    identical: two authentically signed heads under one key, and the second cannot extend
    what the witness already accepted. The cost is one small tree plus the head and proof
    the API already computes elsewhere.
    """
    auditor = Witness(log_id=log.log_id, log_key=log.signing_key.public)

    # The operator's doctored history, under the log's own key: authentic signature,
    # internally consistent, and not the history anybody else was shown.
    shadow = TransparencyLog(log_id=log.log_id, signing_key=log.signing_key)
    leaves = min(SHADOW_LEAVES, max(1, log.tree_size))
    for index in range(leaves):
        shadow.append({"id": f"urn:uuid:rewritten-history-{run.run_id}-{index}"})

    shadow_head = shadow.signed_tree_head()
    auditor.observe(shadow_head)

    genuine_head = log.signed_tree_head()
    proof = log.consistency_proof(auditor.tree_size) if auditor.tree_size < log.tree_size else None

    try:
        auditor.observe(genuine_head, proof)
        detected, reason = False, ""
    except ForkDetected as exc:
        detected, reason = True, str(exc)

    return {
        **_envelope(attack),
        "mutation": {
            "description": (
                f"a second history of {leaves} entries, signed by the log's own key, "
                "presented to a witness before the genuine head"
            ),
            "shadow_tree_size": shadow.tree_size,
            "shadow_root": encode_hash(shadow.root()),
            "shadow_head_verifies_under_the_log_key": shadow_head.verify(log.signing_key.public),
            "genuine_tree_size": genuine_head.tree_size,
            "genuine_root": genuine_head.root_hash,
            "shared_log_modified": False,
        },
        "defended": detected,
        "detected_by": "SPEC step 7 — a witness in another trust domain holds the root",
        "witness": {
            "fork_detected": detected,
            "reason": reason,
            "serves_a_root_now": auditor.current_root() is not None,
        },
        "note": (
            "A signature check alone cannot catch this: both heads are authentically "
            "signed by the log's key and each history is internally consistent. It is only "
            "visible against a root somebody else already accepted — which is why the "
            "witness has to sit in a different trust domain than the issuer. Scope, stated "
            "honestly: one witness is one point of trust. This detects a log that forks "
            "between two parties; it does nothing about a witness that colludes with the "
            "operator, because then both sides of the comparison are the same party. N "
            "independent witnesses gossiping heads is the production answer and is not "
            "built here. The witness used above is a fresh one belonging to this attack, "
            "so your session's own witness is left untouched and still serves its root."
        ),
    }


def _replay_arguments(
    attack: Attack, evidence: Evidence, session: Session, warrant: dict
) -> dict:
    """Move an authentic warrant onto arguments it never authorised."""
    presented, changed = _escalate(evidence.arguments)
    outcome = session.pep.verify(warrant, evidence.receipt, presented)
    return {
        **_envelope(attack),
        "mutation": {
            "field": changed,
            "authorised": evidence.arguments.get(changed),
            "presented": presented.get(changed),
            "description": (
                f"same warrant, {changed} changed from "
                f"{evidence.arguments.get(changed)!r} to {presented.get(changed)!r}"
            ),
        },
        "defended": not outcome.admitted,
        "detected_by": "C-14 — the warrant binds a hash of the arguments it authorised",
        "enforcement": _enforcement(outcome),
        "note": (
            "The warrant is authentic and its inclusion proof still checks out. What fails "
            "is step 5: the arguments presented do not hash to the value the credential "
            "committed to, so the warrant cannot be moved to a different action. As above, "
            "a replay step may also fail because this warrant was already presented during "
            "the run itself."
        ),
    }


# ------------------------------------------------------------------------- internals


def _envelope(attack: Attack) -> dict:
    return {
        "attack": attack.name,
        "title": attack.title,
        "what_it_does": attack.what_it_does,
        "expectation": attack.expectation,
        "control": attack.control,
    }


def _enforcement(outcome) -> dict:
    return {
        "verdict": "PERMIT" if outcome.admitted else "REJECT",
        "issuer_decision": outcome.issuer_decision,
        "steps": [s.model_dump(mode="json") for s in outcome.steps],
        "failed_steps": [s.step for s in outcome.failed_steps],
        "reasons": list(outcome.reasons),
        "policy_reasons": list(outcome.policy_result.reasons) if outcome.policy_result else [],
    }


def _field_to_blame(warrant: dict) -> str:
    """Pick the field whose attribution is worth falsifying.

    Read off the **document**, not off the ``AttributionResult``, because the document is
    what gets mutated and what the signature covers. Reasoning about one and editing the
    other is how you produce a mutation that changes nothing.

    Selection order matters more than it looks. Choosing whichever field sorted first
    picked ``amount`` on the poisoned scenario -- a field the human genuinely set, already
    carrying ``P0 1.0000``. Rewriting it to ``P0 1.0000`` is not a tamper: the bytes are
    identical, the signature still verifies, and the attack reports a defence that never
    happened. That is design decision 6's lesson arriving from the attacker's side --
    one action is legitimate in one field and hijacked in another, so "the attributed
    field" is not a well-defined thing to whitewash.

    So: prefer a field the measurement blamed on untrusted content, because that is the
    finding an operator would actually want to erase, and skip any field already equal to
    the target. Sorted throughout, because a demonstration that is not repeatable is not a
    demonstration.
    """
    subject = warrant.get("credentialSubject", {}).get("attribution", {})
    per_argument: dict = subject.get("per_argument", {})
    status: dict = subject.get("argument_status", {})

    attributed = sorted(f for f, s in status.items() if s == "attributed")
    untrusted = [f for f in attributed if per_argument.get(f, {}).get("P3")]

    for candidates in (untrusted, attributed, sorted(per_argument)):
        for field in candidates:
            if per_argument.get(field) != WHITEWASH:
                return field

    raise HTTPException(
        status_code=409,
        detail=(
            "this run's attribution has no field worth tampering with: every one of them "
            "already reads as wholly caused by the human mandate, so the lie is already "
            "the truth and rewriting it would change no bytes"
        ),
    )


def _escalate(arguments: dict) -> tuple[dict, str]:
    """Present the warrant with one argument changed, preferring a numeric escalation.

    A doubled amount is the version of this attack that reads as theft rather than as a
    typo, so it is preferred where a numeric field exists. Where none does, any changed
    field exercises the same binding -- the control is a hash over all of them, not a rule
    about amounts.
    """
    presented = dict(arguments)
    for field in sorted(arguments):
        value = arguments[field]
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            presented[field] = value * 2
            return presented, field

    for field in sorted(arguments):
        if isinstance(arguments[field], str):
            presented[field] = arguments[field] + "-ATTACKER-MODIFIED"
            return presented, field

    raise HTTPException(
        status_code=409,
        detail="this run's action has no arguments to move the warrant onto",
    )
