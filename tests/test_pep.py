"""Policy enforcement: the eleven-step verification algorithm (SPEC.md section 7).

These are the tests that decide whether the architecture is worth anything. Two of them
carry most of that weight:

  * ``test_issuer_permit_does_not_override_the_relying_party`` -- step 10. If a PEP honours
    the issuer's verdict, the warrant has told it nothing it could not have been told by an
    HTTP 200, and the operator is trusted again.
  * ``test_inclusion_must_reach_the_witnessed_root`` -- step 7. If inclusion is checked
    against a root the operator supplied, the log proves only that the operator can do
    arithmetic consistently.

The last class documents what this design does *not* achieve, in the style of Phase 1's
``test_the_attack_succeeds_without_enforcement``.
"""

from datetime import UTC, datetime, timedelta

import pytest

from aegis.log.log import TransparencyLog
from aegis.log.witness import Witness
from aegis.pep.replay import ReplayCache
from aegis.pep.verifier import PolicyEnforcementPoint
from aegis.policy.library import acme_treasury_policy, permissive_operator_policy
from aegis.warrant.issuer import WarrantIssuer
from aegis.warrant.keys import KeyRing, SigningKey
from aegis.warrant.models import DelegationHop

from conftest import (
    ATTACKER,
    ISSUER_DID,
    ISSUER_METHOD,
    LEGIT,
    LOG_ID,
    OPERATION,
    ORCHESTRATOR_MANIFEST,
    PRINCIPAL,
    PROCESSOR_MANIFEST,
    TOOL,
    build_chain,
    build_mandate,
    clean_request,
    poisoned_request,
    publish,
    run_pipeline,
)


def steps(outcome) -> dict[int, bool]:
    return {s.step: s.passed for s in outcome.steps}


# --------------------------------------------------------------- the headline


class TestTheHeadlineCase:
    def test_poisoned_transfer_is_refused_end_to_end(
        self, poisoned_warrant, log, witness, pep, decisions
    ):
        """The Phase 3 definition of done: the payment API rejects the hijacked transfer."""
        warrant, arguments = poisoned_warrant
        receipt = publish(log, witness, warrant)

        outcome = pep.verify(warrant.to_document(), receipt, arguments)

        assert not outcome.admitted
        assert arguments["destination_account"] == ATTACKER
        # Denied on policy, not on a technicality: everything cryptographic checked out.
        assert all(steps(outcome)[s] for s in (1, 2, 3, 4, 5, 6, 7, 8, 9, 11))
        assert steps(outcome)[10] is False
        assert "no_untrusted_influence_on_destination" in outcome.policy_result.rules_fired
        assert decisions and decisions[-1]["decision"] == "deny"

    def test_the_same_pipeline_admits_a_clean_transfer(
        self, clean_warrant, log, witness, pep
    ):
        """A control that blocks legitimate work gets switched off (asset A6).

        Without this test the suite would pass just as happily if the PEP denied
        everything, which is not a security property -- it is a broken deployment.
        """
        warrant, arguments = clean_warrant
        receipt = publish(log, witness, warrant)

        outcome = pep.verify(warrant.to_document(), receipt, arguments)

        assert arguments["destination_account"] == LEGIT
        assert outcome.admitted, outcome.reasons
        assert all(s.passed for s in outcome.steps)


# ------------------------------------------------------------------- step 10


class TestStep10RelyingPartyDecidesForItself:
    def test_issuer_permit_does_not_override_the_relying_party(
        self, issuer_key, log, witness, pep
    ):
        """A dishonest or misconfigured issuer says permit. The payment API denies anyway.

        This is the property the whole design exists for. The relying party evaluates its
        own policy against evidence it verified; the issuer's conclusion is an input to
        that, never a substitute for it.
        """
        trace, attribution, arguments = run_pipeline(poisoned_request())
        lenient = WarrantIssuer(
            issuer_did=ISSUER_DID,
            signing_key=issuer_key,
            verification_method=ISSUER_METHOD,
            policy=permissive_operator_policy(),
        )
        warrant = lenient.issue(
            operation=OPERATION,
            arguments=arguments,
            mandate=build_mandate(),
            delegation_chain=build_chain(),
            attribution=attribution,
            trace=trace,
            tool=TOOL,
        )
        assert warrant.credentialSubject.policy_decision.decision == "permit"

        receipt = publish(log, witness, warrant)
        outcome = pep.verify(warrant.to_document(), receipt, arguments)

        assert outcome.issuer_decision == "permit"
        assert outcome.decision == "deny"
        assert steps(outcome)[10] is False

    def test_policy_is_not_evaluated_against_an_unauthentic_warrant(
        self, poisoned_warrant, log, witness, pep
    ):
        """Reporting a policy result over unverified evidence invites it being read as a
        verdict. A warrant that fails authentication gets no policy opinion at all."""
        warrant, arguments = poisoned_warrant
        receipt = publish(log, witness, warrant)
        document = warrant.to_document()
        document["proof"]["proofValue"] = "z" + "1" * 80

        outcome = pep.verify(document, receipt, arguments)

        assert steps(outcome)[3] is False
        assert outcome.policy_result is None
        assert "not evaluated" in next(s.detail for s in outcome.steps if s.step == 10)

    def test_field_level_policy_reads_values_the_warrant_never_carried(
        self, clean_warrant, log, witness, pep
    ):
        """The amount is only ever a digest in the warrant.

        The relying party reads the amount from the request in front of it; step 5 is what
        proves that request is the one the warrant describes. That is how a value-bound
        rule is enforced without the warrant disclosing the value.
        """
        warrant, arguments = clean_warrant
        assert "2000000" not in str(warrant.to_document())
        publish(log, witness, warrant)
        assert arguments["amount"] == 2000000.0


# -------------------------------------------------------------------- step 7


class TestStep7IndependentRoot:
    def test_inclusion_must_reach_the_witnessed_root(
        self, poisoned_warrant, log, witness, pep, log_key
    ):
        """A receipt from the operator's private fork does not verify against the witness.

        The forged receipt is internally perfect -- correct proof, correct root, correct
        signature. It only fails because the root it reaches is not the one an independent
        party accepted.
        """
        warrant, arguments = poisoned_warrant
        publish(log, witness, warrant)

        shadow = TransparencyLog(log_id=LOG_ID, signing_key=log_key)
        shadow.append({"id": "urn:uuid:decoy"})
        forged_receipt = shadow.append(warrant.to_document())
        assert forged_receipt.signed_root.verify(log_key.public)

        outcome = pep.verify(warrant.to_document(), forged_receipt, arguments)
        assert steps(outcome)[7] is False

    def test_a_warrant_that_was_never_logged_is_rejected(
        self, poisoned_warrant, log, witness, pep
    ):
        """An unlogged permit is unusable, which is what makes logging load-bearing rather
        than advisory."""
        warrant, arguments = poisoned_warrant
        decoy = publish(log, witness, warrant)
        unlogged = warrant.model_copy(deep=True)
        unlogged.id = "urn:uuid:never-submitted"

        outcome = pep.verify(unlogged.to_document(), decoy, arguments)
        assert steps(outcome)[7] is False

    def test_a_receipt_ahead_of_the_witness_is_rejected(
        self, poisoned_warrant, log, witness, pep
    ):
        """An operator cannot get ahead of its witness and settle the difference later."""
        warrant, arguments = poisoned_warrant
        publish(log, witness, warrant)
        log.append({"id": "urn:uuid:unwitnessed"})
        receipt = log.receipt_for(0)

        outcome = pep.verify(warrant.to_document(), receipt, arguments)
        assert steps(outcome)[7] is False

    def test_no_witnessed_root_means_no_admission(self, poisoned_warrant, log, keyring):
        """A PEP whose witness has seen nothing fails closed, not open."""
        warrant, arguments = poisoned_warrant
        receipt = log.append(warrant.to_document())
        blind = PolicyEnforcementPoint(
            keyring=keyring,
            policy=acme_treasury_policy(),
            witness=Witness(log_id=LOG_ID, log_key=SigningKey.from_seed("x").public),
            known_manifests={ORCHESTRATOR_MANIFEST, PROCESSOR_MANIFEST},
            decision_sink=lambda record: None,
        )
        outcome = blind.verify(warrant.to_document(), receipt, arguments)
        assert steps(outcome)[7] is False


# ------------------------------------------------------- steps 1-6, 8, 9, 11


class TestCredentialChecks:
    def test_unknown_issuer_key_is_rejected(self, poisoned_warrant, log, witness, pep):
        warrant, arguments = poisoned_warrant
        receipt = publish(log, witness, warrant)
        pep.keyring = KeyRing()
        outcome = pep.verify(warrant.to_document(), receipt, arguments)
        assert steps(outcome)[2] is False

    def test_revoked_issuer_key_is_rejected(self, poisoned_warrant, log, witness, pep):
        warrant, arguments = poisoned_warrant
        receipt = publish(log, witness, warrant)
        pep.keyring.revoke(ISSUER_METHOD)
        outcome = pep.verify(warrant.to_document(), receipt, arguments)
        assert steps(outcome)[2] is False

    def test_unknown_context_is_rejected(self, poisoned_warrant, log, witness, pep):
        warrant, arguments = poisoned_warrant
        receipt = publish(log, witness, warrant)
        document = warrant.to_document()
        document["@context"] = ["https://evil.example/ns/v1"]
        outcome = pep.verify(document, receipt, arguments)
        assert steps(outcome)[1] is False

    def test_expired_warrant_is_rejected(self, poisoned_warrant, log, witness, pep):
        """A warrant authorizes one action, now -- not a session."""
        warrant, arguments = poisoned_warrant
        receipt = publish(log, witness, warrant)
        pep.clock = lambda: datetime.now(UTC) + timedelta(minutes=10)
        outcome = pep.verify(warrant.to_document(), receipt, arguments)
        assert steps(outcome)[4] is False

    @pytest.mark.parametrize(
        "tamper",
        [
            pytest.param({"destination_account": ATTACKER + "X"}, id="destination_swapped"),
            pytest.param({"amount": 4000000.0}, id="amount_doubled"),
            pytest.param({"currency": "EUR"}, id="currency_changed"),
        ],
    )
    def test_a_warrant_cannot_be_lifted_onto_different_arguments(
        self, clean_warrant, log, witness, pep, tamper
    ):
        """Control C-14, and the replay that needs no forgery at all: a warrant the
        operator was legitimately issued, presented for a different action."""
        warrant, arguments = clean_warrant
        receipt = publish(log, witness, warrant)
        outcome = pep.verify(warrant.to_document(), receipt, {**arguments, **tamper})
        assert steps(outcome)[5] is False

    def test_dropping_a_covered_field_is_rejected(self, clean_warrant, log, witness, pep):
        warrant, arguments = clean_warrant
        receipt = publish(log, witness, warrant)
        reduced = {k: v for k, v in arguments.items() if k != "currency"}
        outcome = pep.verify(warrant.to_document(), receipt, reduced)
        assert steps(outcome)[5] is False

    def test_a_nonce_cannot_be_used_twice(self, clean_warrant, log, witness, pep):
        warrant, arguments = clean_warrant
        receipt = publish(log, witness, warrant)
        first = pep.verify(warrant.to_document(), receipt, arguments)
        second = pep.verify(warrant.to_document(), receipt, arguments)
        assert first.admitted
        assert steps(second)[6] is False

    def test_replay_cache_forgets_after_the_retention_window(self):
        """Bounded by time, not by count: a cache evicting by size can be flushed by an
        attacker who floods it and then replays the nonce they wanted."""
        cache = ReplayCache(retention=timedelta(minutes=15))
        now = datetime.now(UTC)
        assert cache.check_and_record("n1", now)
        assert not cache.check_and_record("n1", now + timedelta(minutes=14))
        assert cache.check_and_record("n1", now + timedelta(minutes=16))


class TestDelegationChain:
    def _issue(self, issuer, chain, mandate=None):
        trace, attribution, arguments = run_pipeline(clean_request())
        return (
            issuer.issue(
                operation=OPERATION,
                arguments=arguments,
                mandate=mandate or build_mandate(),
                delegation_chain=chain,
                attribution=attribution,
                trace=trace,
                tool=TOOL,
            ),
            arguments,
        )

    def test_scope_must_attenuate_never_widen(self, issuer, log, witness, pep):
        """Each hop is a subset of the last. A hop that grants itself more than it was
        given is a confused-deputy escalation wearing a valid signature."""
        chain = build_chain()
        chain[2] = chain[2].model_copy(update={"scope": ["treasury.payments:*", "hr.payroll:*"]})
        warrant, arguments = self._issue(issuer, chain)
        receipt = publish(log, witness, warrant)
        outcome = pep.verify(warrant.to_document(), receipt, arguments)
        assert steps(outcome)[8] is False

    def test_chain_must_start_at_the_named_principal(self, issuer, log, witness, pep):
        chain = build_chain()
        chain[0] = chain[0].model_copy(update={"actor": "did:web:acme.example:users:someone"})
        warrant, arguments = self._issue(issuer, chain)
        receipt = publish(log, witness, warrant)
        outcome = pep.verify(warrant.to_document(), receipt, arguments)
        assert steps(outcome)[8] is False

    def test_chain_must_start_with_a_human(self, issuer, log, witness, pep):
        chain = build_chain()
        chain[0] = chain[0].model_copy(
            update={"kind": "agent", "manifest_hash": ORCHESTRATOR_MANIFEST}
        )
        warrant, arguments = self._issue(issuer, chain)
        receipt = publish(log, witness, warrant)
        outcome = pep.verify(warrant.to_document(), receipt, arguments)
        assert steps(outcome)[8] is False

    def test_unknown_agent_manifest_is_rejected(self, issuer, log, witness, pep):
        chain = build_chain()
        chain[2] = chain[2].model_copy(update={"manifest_hash": "sha256:" + "ab" * 32})
        warrant, arguments = self._issue(issuer, chain)
        receipt = publish(log, witness, warrant)
        outcome = pep.verify(warrant.to_document(), receipt, arguments)
        assert steps(outcome)[8] is False

    def test_a_pep_with_no_manifest_registry_fails_closed(
        self, clean_warrant, log, witness, keyring
    ):
        """An empty registry must not read as "accept anything" -- that would disable
        control C-6 in exactly the deployments least likely to notice."""
        warrant, arguments = clean_warrant
        receipt = publish(log, witness, warrant)
        unconfigured = PolicyEnforcementPoint(
            keyring=keyring,
            policy=acme_treasury_policy(),
            witness=witness,
            known_manifests=None,
            decision_sink=lambda record: None,
        )
        outcome = unconfigured.verify(warrant.to_document(), receipt, arguments)
        assert steps(outcome)[8] is False

    def test_a_chain_deeper_than_policy_allows_is_denied(self, issuer, log, witness, pep):
        chain = build_chain()
        chain.append(
            DelegationHop(
                hop=3,
                actor="did:web:acme-bank.example:agents:sub-processor",
                kind="agent",
                scope=[f"{TOOL}:{OPERATION}"],
                manifest_hash=PROCESSOR_MANIFEST,
                attenuated=True,
            )
        )
        warrant, arguments = self._issue(issuer, chain)
        receipt = publish(log, witness, warrant)
        outcome = pep.verify(warrant.to_document(), receipt, arguments)
        assert steps(outcome)[10] is False
        assert "chain_too_deep" in outcome.policy_result.rules_fired


class TestMandate:
    def _issue(self, issuer, mandate):
        trace, attribution, arguments = run_pipeline(clean_request())
        return (
            issuer.issue(
                operation=OPERATION,
                arguments=arguments,
                mandate=mandate,
                delegation_chain=build_chain(),
                attribution=attribution,
                trace=trace,
                tool=TOOL,
            ),
            arguments,
        )

    def test_expired_mandate_is_rejected(self, issuer, log, witness, pep):
        warrant, arguments = self._issue(issuer, build_mandate(expires_in=timedelta(hours=-1)))
        receipt = publish(log, witness, warrant)
        outcome = pep.verify(warrant.to_document(), receipt, arguments)
        assert steps(outcome)[9] is False

    def test_action_outside_the_mandate_scope_is_rejected(self, issuer, log, witness, pep):
        mandate = build_mandate()
        mandate.scope.action_classes = ["treasury.payments:read_balance"]
        warrant, arguments = self._issue(issuer, mandate)
        receipt = publish(log, witness, warrant)
        outcome = pep.verify(warrant.to_document(), receipt, arguments)
        assert steps(outcome)[9] is False

    def test_value_constraint_is_enforced_against_received_arguments(
        self, issuer, log, witness, pep
    ):
        mandate = build_mandate()
        mandate.scope.constraints = {"amount_max": 1000, "currency": ["USD"]}
        warrant, arguments = self._issue(issuer, mandate)
        receipt = publish(log, witness, warrant)
        outcome = pep.verify(warrant.to_document(), receipt, arguments)
        assert steps(outcome)[9] is False

    def test_a_constraint_on_an_absent_field_is_a_violation(self, issuer, log, witness, pep):
        """Otherwise an agent escapes every value bound by omitting the bounded field."""
        mandate = build_mandate()
        mandate.scope.constraints = {"daily_total_max": 100}
        warrant, arguments = self._issue(issuer, mandate)
        receipt = publish(log, witness, warrant)
        outcome = pep.verify(warrant.to_document(), receipt, arguments)
        assert steps(outcome)[9] is False

    def test_wrong_principal_is_rejected(self, clean_warrant, log, witness, pep):
        warrant, arguments = clean_warrant
        receipt = publish(log, witness, warrant)
        outcome = pep.verify(
            warrant.to_document(), receipt, arguments, expected_principal="did:web:x:users:other"
        )
        assert steps(outcome)[9] is False
        assert PRINCIPAL in outcome.reasons[0]


class TestDecisionRecord:
    def test_the_relying_party_records_its_own_decision(
        self, clean_warrant, log, witness, pep, decisions
    ):
        warrant, arguments = clean_warrant
        receipt = publish(log, witness, warrant)
        pep.verify(warrant.to_document(), receipt, arguments)
        record = decisions[-1]
        assert record["warrant_id"] == warrant.id
        assert record["policy_hash"] == acme_treasury_policy().policy_hash()

    def test_a_pep_that_cannot_record_its_decision_fails_closed(
        self, clean_warrant, log, witness, keyring
    ):
        warrant, arguments = clean_warrant
        receipt = publish(log, witness, warrant)
        silent = PolicyEnforcementPoint(
            keyring=keyring,
            policy=acme_treasury_policy(),
            witness=witness,
            known_manifests={ORCHESTRATOR_MANIFEST, PROCESSOR_MANIFEST},
            decision_sink=None,
        )
        outcome = silent.verify(warrant.to_document(), receipt, arguments)
        assert steps(outcome)[11] is False


# ------------------------------------------------------- documented limitations


class TestKnownLimitations:
    """What this design does not achieve. Recorded as tests so it cannot quietly rot."""

    def test_the_log_does_not_prove_the_attribution_is_true(
        self, issuer_key, log, witness, pep
    ):
        """A lying issuer produces a warrant that passes every one of the eleven steps.

        ADV-4 runs the issuer. Nothing stops it signing a credential asserting the human
        caused a field the attacker set: the signature is genuine, the log entry is
        genuine, the inclusion proof is genuine. The transparency log makes the lie
        permanently, verifiably theirs -- it converts forgery from undetectable into
        non-repudiable, not into prevented.

        ``attribution.replay_ref`` is what makes the lie *falsifiable*: an auditor granted
        the underlying trace can re-run the ablation and compare. Building that verifier is
        Phase 4; the commitment it needs is already under the signature here.
        """
        from aegis.provenance.classes import ProvenanceClass

        trace, attribution, arguments = run_pipeline(poisoned_request())
        assert attribution.per_argument["destination_account"].get(
            ProvenanceClass.UNTRUSTED_EXTERNAL
        ) == 1.0, "the honest measurement blames untrusted content"

        # The operator rewrites its own measurement before signing: the attacker's account
        # is relabelled as something the human chose.
        for field in attribution.per_argument:
            attribution.per_argument[field].weights = {ProvenanceClass.HUMAN_MANDATE: 1.0}
            attribution.argument_status[field] = "attributed"
            attribution.per_argument_confidence[field] = 1.0
        attribution.influence.weights = {ProvenanceClass.HUMAN_MANDATE: 1.0}
        attribution.confidence = 1.0

        liar = WarrantIssuer(
            issuer_did=ISSUER_DID,
            signing_key=issuer_key,
            verification_method=ISSUER_METHOD,
            policy=permissive_operator_policy(),
        )
        warrant = liar.issue(
            operation=OPERATION,
            arguments=arguments,
            mandate=build_mandate(),
            delegation_chain=build_chain(),
            attribution=attribution,
            trace=trace,
            tool=TOOL,
        )
        receipt = publish(log, witness, warrant)
        outcome = pep.verify(warrant.to_document(), receipt, arguments)

        assert outcome.admitted, "this is the limitation, not a passing security property"
        assert arguments["destination_account"] == ATTACKER

        # What the system does still give the auditor: a non-repudiable commitment to the
        # exact context the claim was supposedly measured over.
        ref = warrant.credentialSubject.attribution.replay_ref
        assert ref.trace_hash and ref.segment_hashes

    def test_a_suppressed_denial_leaves_no_gap(self, poisoned_warrant, log, witness):
        """Consistency proofs detect rewriting, not omission.

        An entry that was never submitted leaves no hole to find. For permits this is
        harmless -- the PEP will not honour an action without an inclusion proof, so an
        unlogged permit is unusable. For denials it is real: a suppressed denial is simply
        invisible, and the loss is evidence rather than control.
        """
        warrant, _ = poisoned_warrant
        assert warrant.credentialSubject.policy_decision.decision == "deny"

        log.append({"id": "urn:uuid:something-else"})
        witness.observe(log.signed_tree_head())

        assert witness.current_root() == log.root(), (
            "the log is perfectly consistent; the denial's absence is undetectable from here"
        )
        assert len(log) == 1

    def test_the_replay_cache_is_local_to_one_enforcement_point(self, clean_warrant, log, witness, pep, keyring):
        """Two PEPs do not share a nonce cache, so a warrant can be replayed once at each.

        Real deployments need a shared cache or per-audience binding in the warrant.
        """
        warrant, arguments = clean_warrant
        receipt = publish(log, witness, warrant)
        second_pep = PolicyEnforcementPoint(
            keyring=keyring,
            policy=acme_treasury_policy(),
            witness=witness,
            known_manifests={ORCHESTRATOR_MANIFEST, PROCESSOR_MANIFEST},
            decision_sink=lambda record: None,
        )
        assert pep.verify(warrant.to_document(), receipt, arguments).admitted
        assert second_pep.verify(warrant.to_document(), receipt, arguments).admitted
