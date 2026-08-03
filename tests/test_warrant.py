"""Action Warrant issuance and signature verification.

The assertions here are about properties a warrant must have to be worth anything to
someone who does not trust the party that issued it: that the signature covers what it
claims to, that no document text escapes with it, and that a denial is as much a credential
as a permit.
"""

from decimal import Decimal

import pytest

from aegis.common.decimals import QUANTUM, parse_score
from aegis.common.hashing import hash_object
from aegis.warrant.issuer import WarrantIssuer, verify_signature
from aegis.warrant.keys import (
    KeyRing,
    SigningKey,
    UnknownKeyError,
    VerifyingKey,
    b58_decode,
    b58_encode,
)
from aegis.warrant.models import WARRANT_TYPE, ActionWarrant

from conftest import (
    ATTACKER,
    ISSUER_METHOD,
    LEGIT,
    OPERATION,
    TOOL,
    build_chain,
    build_mandate,
    poisoned_request,
    run_pipeline,
)


class TestBase58AndKeys:
    @pytest.mark.parametrize(
        "raw",
        [b"", b"\x00", b"\x00\x00\x01", b"hello world", bytes(range(256))],
    )
    def test_base58_round_trips(self, raw):
        assert b58_decode(b58_encode(raw)) == raw

    def test_leading_zero_bytes_survive(self):
        """Base58 is not positional at the front: leading zeros must be encoded
        explicitly or a key silently loses its high bytes."""
        assert b58_encode(b"\x00\x00\xff").startswith("11")
        assert b58_decode(b58_encode(b"\x00\x00\xff")) == b"\x00\x00\xff"

    def test_public_key_round_trips_through_multibase(self, issuer_key: SigningKey):
        encoded = issuer_key.public.to_multibase()
        assert encoded.startswith("z")
        assert VerifyingKey.from_multibase(encoded).to_bytes() == issuer_key.public.to_bytes()

    def test_seeded_keys_are_reproducible(self):
        assert (
            SigningKey.from_seed("same").public.to_bytes()
            == SigningKey.from_seed("same").public.to_bytes()
        )
        assert (
            SigningKey.from_seed("a").public.to_bytes()
            != SigningKey.from_seed("b").public.to_bytes()
        )

    def test_revoked_keys_do_not_resolve(self, issuer_key: SigningKey):
        ring = KeyRing()
        ring.register(ISSUER_METHOD, issuer_key.public)
        ring.revoke(ISSUER_METHOD)
        with pytest.raises(UnknownKeyError):
            ring.resolve(ISSUER_METHOD)


class TestIssuance:
    def test_warrant_is_a_verifiable_credential(self, poisoned_warrant):
        warrant, _ = poisoned_warrant
        document = warrant.to_document()
        assert document["@context"][0] == "https://www.w3.org/ns/credentials/v2"
        assert set(WARRANT_TYPE) <= set(document["type"])
        assert document["proof"]["cryptosuite"] == "eddsa-jcs-2022"

    def test_signature_verifies(self, poisoned_warrant, issuer_key: SigningKey):
        warrant, _ = poisoned_warrant
        assert verify_signature(warrant.to_document(), issuer_key.public)

    def test_signature_fails_under_a_different_key(self, poisoned_warrant):
        warrant, _ = poisoned_warrant
        assert not verify_signature(
            warrant.to_document(), SigningKey.from_seed("someone-else").public
        )

    @pytest.mark.parametrize(
        "mutate",
        [
            pytest.param(
                lambda d: d["credentialSubject"]["attribution"]["per_argument"][
                    "destination_account"
                ].update({"P0": "0.9500", "P3": "0.0000"}),
                id="attribution_rewritten_to_blame_the_human",
            ),
            pytest.param(
                lambda d: d["credentialSubject"]["policy_decision"].update({"decision": "permit"}),
                id="decision_flipped_to_permit",
            ),
            pytest.param(
                lambda d: d["credentialSubject"]["action"].update({"arguments_hash": "sha256:00"}),
                id="action_rebound",
            ),
            pytest.param(
                lambda d: d.update({"validUntil": "2099-01-01T00:00:00Z"}),
                id="validity_extended",
            ),
            pytest.param(
                lambda d: d["proof"].update({"verificationMethod": "did:web:evil#key-1"}),
                id="proof_options_altered",
            ),
        ],
    )
    def test_any_alteration_breaks_the_signature(
        self, poisoned_warrant, issuer_key: SigningKey, mutate
    ):
        """Both halves of the eddsa-jcs-2022 hash are covered.

        The last case matters most: the proof options are hashed separately from the
        document, so tampering with the proof block itself must fail too. If only the
        document were signed, a proof could be lifted onto another credential.
        """
        warrant, _ = poisoned_warrant
        document = warrant.to_document()
        mutate(document)
        assert not verify_signature(document, issuer_key.public)

    def test_a_denial_is_signed_like_any_other_warrant(self, poisoned_warrant, issuer_key):
        """A refusal is evidence that the system worked, so it is a credential too.

        An issuer that signed only its permits would produce an audit trail in which
        nothing ever went wrong -- precisely what a dishonest operator wants.
        """
        warrant, _ = poisoned_warrant
        assert warrant.credentialSubject.policy_decision.decision == "deny"
        assert verify_signature(warrant.to_document(), issuer_key.public)

    def test_issuer_with_no_policy_records_a_denial_not_a_permit(self, issuer_key):
        trace, attribution, arguments = run_pipeline(poisoned_request())
        silent = WarrantIssuer(
            issuer_did="did:web:silent.example",
            signing_key=issuer_key,
            policy=None,
        )
        warrant = silent.issue(
            operation=OPERATION,
            arguments=arguments,
            mandate=build_mandate(),
            delegation_chain=build_chain(),
            attribution=attribution,
            trace=trace,
            tool=TOOL,
        )
        assert warrant.credentialSubject.policy_decision.decision == "deny"
        assert warrant.credentialSubject.policy_decision.rules_fired == ["issuer_has_no_policy"]


class TestDisclosure:
    def test_no_document_text_travels_in_the_warrant(self, poisoned_warrant):
        """A warrant crosses organizational boundaries. It must carry hashes, not content.

        The attacker's account number is the one string guaranteed to be in the poisoned
        invoice, so its absence is a sharp check that excerpts were not embedded.
        """
        warrant, _ = poisoned_warrant
        serialized = str(warrant.to_document())
        assert ATTACKER not in serialized
        assert LEGIT not in serialized
        assert "NOTE FROM SUPPLIER" not in serialized

    def test_argument_values_are_present_only_as_digests(self, poisoned_warrant):
        warrant, arguments = poisoned_warrant
        digests = warrant.credentialSubject.action.arguments_digest_map
        assert set(digests) == set(arguments)
        for field, value in arguments.items():
            assert digests[field] == hash_object(value)

    def test_contributors_carry_hashes_not_excerpts(self, poisoned_warrant):
        warrant, _ = poisoned_warrant
        contributors = warrant.credentialSubject.attribution.top_contributors
        assert contributors
        assert all(c.excerpt_hash.startswith("sha256:") for c in contributors)


class TestScoreEncoding:
    def test_every_score_is_a_fixed_precision_string(self, poisoned_warrant):
        """Floats in a signed payload would put our JCS number handling on the
        verification path for values we could have encoded unambiguously instead."""
        warrant, _ = poisoned_warrant
        attribution = warrant.credentialSubject.attribution

        scores = [attribution.confidence]
        scores += list(attribution.influence.values())
        scores += list(attribution.necessity.values())
        for dist in attribution.per_argument.values():
            scores += list(dist.values())
        scores += [c.influence for c in attribution.top_contributors]

        assert scores
        for score in scores:
            assert isinstance(score, str)
            assert parse_score(score).as_tuple().exponent == QUANTUM.as_tuple().exponent

    def test_a_rounded_distribution_need_not_sum_to_one(self, poisoned_warrant):
        """Independent rounding lands on 0.9999 or 1.0001, and that is not an error.

        Stated as a test because a verifier that demands an exact sum would reject honest
        warrants, and that is an easy check for someone to add in good faith later.
        """
        warrant, _ = poisoned_warrant
        attribution = warrant.credentialSubject.attribution
        attributed = [
            field
            for field, status in attribution.argument_status.items()
            if status == "attributed"
        ]
        assert attributed
        for field in attributed:
            total = sum(parse_score(v) for v in attribution.per_argument[field].values())
            assert abs(total - Decimal(1)) <= Decimal("0.0002")

    def test_an_invariant_field_carries_no_weight_at_all(self, poisoned_warrant):
        """A field nothing was pivotal for must not be padded into a uniform distribution.

        The uniform fallback asserted that untrusted content held a 0.2 share of causing a
        value the measurement showed it had no effect on -- enough to trip a policy
        forbidding any untrusted influence, and the reason a legitimate payment was denied.
        """
        warrant, _ = poisoned_warrant
        attribution = warrant.credentialSubject.attribution
        invariant = [f for f, s in attribution.argument_status.items() if s == "invariant"]
        assert invariant, "the poisoned case has invariant fields; if not, this test is stale"
        for field in invariant:
            assert attribution.per_argument[field] == {}


class TestReplayRef:
    def test_replay_ref_commits_to_the_measured_context(self, poisoned_warrant):
        """Emitted in Phase 3 because it sits under the signature.

        The verifier that re-runs the ablation is Phase 4 work, but adding these fields
        later would invalidate every warrant already issued or fork the format.
        """
        warrant, _ = poisoned_warrant
        ref = warrant.credentialSubject.attribution.replay_ref
        assert ref is not None
        assert ref.trace_hash.startswith("sha256:")
        assert len(ref.segment_hashes) >= 3
        assert all(h.startswith("sha256:") for h in ref.segment_hashes)
        assert ref.method_version

    def test_segment_hashes_are_ordered_as_ablated(self, poisoned_warrant, issuer):
        trace, attribution, arguments = run_pipeline(poisoned_request())
        warrant = issuer.issue(
            operation=OPERATION,
            arguments=arguments,
            mandate=build_mandate(),
            delegation_chain=build_chain(),
            attribution=attribution,
            trace=trace,
            tool=TOOL,
        )
        ref = warrant.credentialSubject.attribution.replay_ref
        assert ref.segment_hashes == [s.source.content_hash for s in trace.segments]


class TestRoundTrip:
    def test_document_survives_a_json_round_trip(self, poisoned_warrant, issuer_key):
        """A warrant is transmitted as JSON. If parsing and re-serializing changed a byte,
        every relying party would see a valid warrant as a forgery."""
        import json

        warrant, _ = poisoned_warrant
        document = json.loads(json.dumps(warrant.to_document()))
        assert verify_signature(document, issuer_key.public)
        assert ActionWarrant.from_document(document).to_document() == warrant.to_document()

    def test_unknown_fields_are_preserved(self, poisoned_warrant):
        """A warrant from a newer implementation must round-trip through an older
        verifier without losing fields the signature covers."""
        warrant, _ = poisoned_warrant
        document = warrant.to_document()
        document["credentialSubject"]["futureField"] = {"added": "later"}
        reparsed = ActionWarrant.from_document(document).to_document()
        assert reparsed["credentialSubject"]["futureField"] == {"added": "later"}
