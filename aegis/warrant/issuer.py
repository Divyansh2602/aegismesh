"""aegis-warrant — mint and sign Action Warrants.

Signing follows the VC Data Integrity ``eddsa-jcs-2022`` cryptosuite: canonicalize the
proof configuration and the unsecured document separately, hash each with SHA-256,
concatenate the two digests, and sign those 64 bytes with Ed25519. Signing the two halves
separately is what stops a proof block being lifted from one credential onto another.

**Denials are signed and logged exactly like permits.** It is tempting to treat a refusal
as an internal event not worth a credential. It is the opposite: a denial is the evidence
that the system worked, it is what a regulator asks to see under Article 12, and
suppressing it is precisely what a dishonest operator would want to do. An issuer that
signs only its permits produces an audit trail in which nothing ever went wrong.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from datetime import timedelta
from typing import Any
from uuid import uuid4

from aegis.attribution.models import AttributionResult
from aegis.common.decimals import format_distribution, format_score
from aegis.common.hashing import canonical_json, hash_object
from aegis.common.ids import prefixed_id
from aegis.policy.engine import Policy
from aegis.policy.evidence import evidence_from_parts
from aegis.provenance.models import ContextTrace
from aegis.warrant.keys import SigningKey, VerifyingKey, multibase_decode
from aegis.warrant.models import (
    CRYPTOSUITE,
    DEFAULT_VALIDITY,
    WARRANT_CONTEXT,
    ActionClaim,
    ActionWarrant,
    AttributionClaim,
    ContributorClaim,
    CredentialSubject,
    DelegationHop,
    Environment,
    MandateClaim,
    PolicyDecisionClaim,
    Proof,
    ReplayRef,
    iso,
    utc_now,
)

#: How many measured contributors travel in a warrant. Enough for an investigator to see
#: what caused the action; few enough that the credential stays small.
MAX_CONTRIBUTORS = 5


class WarrantIssuer:
    """Issues warrants for one operator, under one key."""

    def __init__(
        self,
        issuer_did: str,
        signing_key: SigningKey,
        verification_method: str | None = None,
        policy: Policy | None = None,
        agent_runtime: str = "aegis-proxy/0.1.0",
        validity: timedelta = DEFAULT_VALIDITY,
    ) -> None:
        self.issuer_did = issuer_did
        self.signing_key = signing_key
        self.verification_method = verification_method or f"{issuer_did}#key-1"
        self.policy = policy
        self.agent_runtime = agent_runtime
        self.validity = validity

    # ------------------------------------------------------------------ issuance

    def issue(
        self,
        operation: str,
        arguments: Mapping[str, Any],
        mandate: MandateClaim,
        delegation_chain: list[DelegationHop],
        attribution: AttributionResult,
        trace: ContextTrace,
        tool: str | None = None,
        tool_descriptions_hash: str = "",
        nonce: str | None = None,
        seed: int | None = None,
    ) -> ActionWarrant:
        """Mint and sign a warrant for one proposed action.

        The issuer evaluates its own policy here and records the outcome. That record is a
        claim, not an authorization: whether the action happens is decided downstream by a
        party that does not trust this one.
        """
        tool = tool or attribution.action.tool or ""
        attribution_claim = self._attribution_claim(attribution, trace, seed)
        decision = self._decide(tool, operation, arguments, attribution, delegation_chain, mandate)

        now = utc_now()
        warrant = ActionWarrant(
            id=f"urn:uuid:{uuid4()}",
            issuer=self.issuer_did,
            validFrom=iso(now),
            validUntil=iso(now + self.validity),
            credentialSubject=CredentialSubject(
                action=ActionClaim(
                    tool=tool,
                    operation=operation,
                    arguments_hash=hash_object(dict(arguments)),
                    arguments_digest_map={
                        field: hash_object(value) for field, value in sorted(arguments.items())
                    },
                    nonce=nonce or prefixed_id("nnc"),
                    consequential=attribution.consequential,
                ),
                mandate=mandate,
                delegation_chain=delegation_chain,
                attribution=attribution_claim,
                policy_decision=decision,
                environment=Environment(
                    tool_descriptions_hash=tool_descriptions_hash,
                    agent_runtime=self.agent_runtime,
                ),
            ),
        )
        return self.sign(warrant)

    def sign(self, warrant: ActionWarrant) -> ActionWarrant:
        proof = Proof(
            created=iso(utc_now()),
            verificationMethod=self.verification_method,
        )
        document = warrant.to_document()
        digest = signing_input(warrant.unsecured(), _proof_config(proof, document))
        proof.proofValue = self.signing_key.sign_multibase(digest)
        warrant.proof = proof
        return warrant

    # ------------------------------------------------------------------ internals

    def _decide(
        self,
        tool: str,
        operation: str,
        arguments: Mapping[str, Any],
        attribution: AttributionResult,
        delegation_chain: list[DelegationHop],
        mandate: MandateClaim,
    ) -> PolicyDecisionClaim:
        if self.policy is None:
            # No policy configured is not "permit". An issuer with nothing to say records
            # that it had nothing to say, and the relying party's own rules decide.
            return PolicyDecisionClaim(
                policy_id="none",
                policy_version="0",
                policy_hash=hash_object({}),
                decision="deny",
                rules_fired=["issuer_has_no_policy"],
            )

        evidence = evidence_from_parts(
            tool=tool,
            operation=operation,
            arguments=arguments,
            influence=format_distribution(attribution.influence.weights),
            necessity=format_distribution(attribution.necessity.weights),
            per_argument={
                field: format_distribution(dist.weights)
                for field, dist in attribution.per_argument.items()
            },
            confidence=format_score(attribution.confidence),
            argument_status=attribution.argument_status,
            per_argument_confidence={
                field: format_score(value)
                for field, value in attribution.per_argument_confidence.items()
            },
            delegation_chain=[hop.model_dump() for hop in delegation_chain],
            mandate=mandate.model_dump(),
        )
        result = self.policy.evaluate(evidence)
        return PolicyDecisionClaim(
            policy_id=self.policy.policy_id,
            policy_version=self.policy.policy_version,
            policy_hash=self.policy.policy_hash(),
            decision=result.decision,
            rules_fired=result.rules_fired,
            obligations=result.obligations,
        )

    def _attribution_claim(
        self,
        attribution: AttributionResult,
        trace: ContextTrace,
        seed: int | None,
    ) -> AttributionClaim:
        return AttributionClaim(
            method=attribution.method,
            method_version=attribution.method_version,
            granularity=list(attribution.granularity),
            resamples=attribution.resamples,
            model_ref=attribution.model_ref,
            influence=format_distribution(attribution.influence.weights),
            necessity=format_distribution(attribution.necessity.weights),
            per_argument={
                field: format_distribution(dist.weights)
                for field, dist in sorted(attribution.per_argument.items())
            },
            argument_status=dict(sorted(attribution.argument_status.items())),
            per_argument_confidence={
                field: format_score(value)
                for field, value in sorted(attribution.per_argument_confidence.items())
            },
            top_contributors=[
                ContributorClaim(
                    segment_id=c.segment_id,
                    **{"class": c.cls.value},
                    origin=c.origin,
                    influence=format_score(c.influence),
                    excerpt_hash=c.sentence or c.excerpt_hash,
                    granularity=c.granularity,
                )
                for c in attribution.top_contributors[:MAX_CONTRIBUTORS]
            ],
            confidence=format_score(attribution.confidence),
            replay_ref=replay_ref(trace, attribution, seed),
        )


def replay_ref(
    trace: ContextTrace,
    attribution: AttributionResult,
    seed: int | None = None,
) -> ReplayRef:
    """Commit to the exact classified context the attribution was measured over.

    Ordered, because leave-one-out ablation walks the segments in order and a reordering
    would produce a different set of counterfactuals. Hashes only, for the same reason
    excerpts are hashed everywhere else: this travels outside the operator's boundary.
    """
    return ReplayRef(
        trace_hash=trace_commitment(trace),
        segment_hashes=[segment.source.content_hash for segment in trace.segments],
        model_ref=attribution.model_ref or trace.model,
        method_version=attribution.method_version,
        seed=seed,
    )


def trace_commitment(trace: ContextTrace) -> str:
    """A hash binding the segments, their classes, and their order.

    Deliberately excludes ``retrieved_at`` and the trace's own timestamp: an auditor
    re-running attribution reconstructs the context, not the clock, and including wall
    time would make an honest replay fail.
    """
    return hash_object(
        {
            "trace_id": trace.trace_id,
            "model": trace.model,
            "segments": [
                {
                    "segment_id": segment.segment_id,
                    "class": segment.cls.value,
                    "content_hash": segment.source.content_hash,
                    "origin": segment.source.origin,
                    "kind": segment.source.kind,
                    "span": {"start": segment.span.start, "end": segment.span.end},
                }
                for segment in trace.segments
            ],
        }
    )


def _proof_config(proof: Proof, document: dict) -> dict:
    """The proof options that are signed: everything but the signature itself.

    The credential's own ``@context`` is copied in, per the cryptosuite -- copied from the
    document rather than from the module constant, so that a warrant carrying an unexpected
    context still signs and verifies over identical bytes. Otherwise the proof's meaning
    would not be bound to the vocabulary the credential is interpreted under.
    """
    config = proof.model_dump(by_alias=True, mode="json", exclude_none=True)
    config.pop("proofValue", None)
    config["@context"] = document.get("@context", list(WARRANT_CONTEXT))
    return config


def signing_input(unsecured_document: dict, proof_config: dict) -> bytes:
    """``sha256(JCS(proof_config)) || sha256(JCS(document))`` -- the eddsa-jcs-2022 hash."""
    return (
        hashlib.sha256(canonical_json(proof_config)).digest()
        + hashlib.sha256(canonical_json(unsecured_document)).digest()
    )


def verify_signature(document: dict, key: VerifyingKey) -> bool:
    """Check a warrant document's proof against a public key.

    Takes the raw document rather than a parsed model so that verification operates on the
    bytes as received. Reparsing into a model and re-serializing before checking would
    verify a signature over something the sender may never have sent.
    """
    proof = document.get("proof")
    if not isinstance(proof, dict):
        return False
    if proof.get("cryptosuite") != CRYPTOSUITE:
        return False
    proof_value = proof.get("proofValue")
    if not isinstance(proof_value, str):
        return False

    unsecured = {k: v for k, v in document.items() if k != "proof"}
    config = {k: v for k, v in proof.items() if k != "proofValue"}
    config["@context"] = document.get("@context", list(WARRANT_CONTEXT))

    try:
        signature = multibase_decode(proof_value)
    except ValueError:
        return False
    return key.verify(signature, signing_input(unsecured, config))
