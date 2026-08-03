"""Transparency log and witness behaviour.

The scenario that matters is at the bottom: an operator who shows one history to the
relying party and a different one to the auditor. Everything above it exists to make that
case meaningful.
"""

import pytest

from aegis.log.log import (
    Receipt,
    SignedTreeHead,
    TransparencyLog,
    decode_hash,
    verify_receipt,
)
from aegis.log.witness import ForkDetected, Witness
from aegis.warrant.keys import SigningKey

from conftest import LOG_ID


def entry(n: int) -> dict:
    return {"id": f"urn:uuid:{n}", "credentialSubject": {"n": n}}


class TestAppendAndReceipts:
    def test_receipt_proves_inclusion_against_the_root(self, log: TransparencyLog):
        receipts = [log.append(entry(i)) for i in range(5)]
        root = log.root()
        for i, receipt in enumerate(receipts):
            # Each receipt was issued at a smaller tree; re-derive at the current size.
            current = log.receipt_for(i)
            assert verify_receipt(entry(i), current, root)
            assert receipt.leaf_index == i

    def test_a_document_that_was_never_logged_cannot_be_proven(self, log: TransparencyLog):
        log.append(entry(0))
        receipt = log.append(entry(1))
        assert not verify_receipt(entry(99), receipt, log.root())

    def test_key_order_does_not_change_the_leaf(self, log: TransparencyLog):
        """The log canonicalizes what it stores, so the same logical warrant submitted
        with keys in a different order is visibly the same entry, not a new one."""
        log.append({"a": 1, "b": 2})
        first_root = log.root()
        second = TransparencyLog(log_id=LOG_ID, signing_key=SigningKey.from_seed("x"))
        second.append({"b": 2, "a": 1})
        assert second.root() == first_root

    def test_receipt_survives_json_round_trip(self, log: TransparencyLog):
        import json

        log.append(entry(0))
        receipt = log.append(entry(1))
        restored = Receipt.model_validate(json.loads(receipt.model_dump_json()))
        assert verify_receipt(entry(1), restored, log.root())


class TestSignedTreeHead:
    def test_head_verifies_under_the_log_key(self, log: TransparencyLog, log_key: SigningKey):
        log.append(entry(0))
        assert log.signed_tree_head().verify(log_key.public)

    def test_head_does_not_verify_under_another_key(self, log: TransparencyLog):
        log.append(entry(0))
        assert not log.signed_tree_head().verify(SigningKey.from_seed("not-the-log").public)

    def test_root_cannot_be_replayed_under_a_new_timestamp(
        self, log: TransparencyLog, log_key: SigningKey
    ):
        """Size and timestamp are signed alongside the root.

        Signing the root alone would let a log re-present a stale root as current, which
        is enough to hide every entry added since.
        """
        log.append(entry(0))
        head = log.signed_tree_head()
        forged = head.model_copy(update={"timestamp": "2099-01-01T00:00:00Z"})
        assert not forged.verify(log_key.public)

    def test_unsigned_head_is_rejected(self, log_key: SigningKey):
        head = SignedTreeHead(
            log_id=LOG_ID, tree_size=1, root_hash="sha256:00", timestamp="2026-08-03T00:00:00Z"
        )
        assert not head.verify(log_key.public)


class TestWitness:
    def test_accepts_a_growing_log(self, log: TransparencyLog, witness: Witness):
        for i in range(6):
            previous = witness.tree_size
            log.append(entry(i))
            witness.observe(
                log.signed_tree_head(),
                log.consistency_proof(previous) if previous else None,
            )
        assert witness.tree_size == 6
        assert witness.current_root() == log.root()

    def test_rejects_a_head_signed_by_the_wrong_key(self, witness: Witness):
        impostor = TransparencyLog(log_id=LOG_ID, signing_key=SigningKey.from_seed("impostor"))
        impostor.append(entry(0))
        with pytest.raises(ForkDetected, match="does not verify"):
            witness.observe(impostor.signed_tree_head())

    def test_rejects_a_head_for_a_different_log(self, witness: Witness, log_key: SigningKey):
        other = TransparencyLog(log_id="did:web:some.other.log", signing_key=log_key)
        other.append(entry(0))
        with pytest.raises(ForkDetected):
            witness.observe(other.signed_tree_head())

    def test_rejects_growth_with_no_consistency_proof(
        self, log: TransparencyLog, witness: Witness
    ):
        """"The operator did not send a proof" and "the operator cannot send one" are
        indistinguishable from the witness's position, and only one is innocent."""
        log.append(entry(0))
        witness.observe(log.signed_tree_head())
        log.append(entry(1))
        with pytest.raises(ForkDetected):
            witness.observe(log.signed_tree_head(), None)

    def test_rejects_a_shrinking_log(self, log: TransparencyLog, witness: Witness, log_key):
        for i in range(4):
            log.append(entry(i))
        witness.observe(log.signed_tree_head())
        shorter = TransparencyLog(log_id=LOG_ID, signing_key=log_key)
        shorter.append(entry(0))
        with pytest.raises(ForkDetected, match="shrank"):
            witness.observe(shorter.signed_tree_head())

    def test_detects_a_forked_log(self, log: TransparencyLog, witness: Witness, log_key):
        """The ADV-4 scenario: one history for the relying party, another for the auditor.

        The operator publishes two entries, then rewrites the second and appends a third,
        presenting the result as a normal extension. The rewrite is invisible in isolation
        -- both trees are internally valid and both heads carry a genuine signature from
        the log's key. It is only visible against a root someone else already accepted,
        which is the entire reason the witness exists.
        """
        log.append(entry(0))
        log.append(entry(1))
        witness.observe(log.signed_tree_head())
        honest_root = witness.current_root()

        forked = TransparencyLog(log_id=LOG_ID, signing_key=log_key)
        forked.append(entry(0))
        forked.append({"id": "urn:uuid:1", "credentialSubject": {"n": "rewritten"}})
        forked.append(entry(2))

        assert forked.root() != honest_root
        assert forked.signed_tree_head().verify(log_key.public), (
            "the forked head is genuinely signed; a signature check alone does not catch this"
        )

        with pytest.raises(ForkDetected, match="altered or removed"):
            witness.observe(forked.signed_tree_head(), forked.consistency_proof(2))

    def test_a_forked_witness_serves_no_root_at_all(
        self, log: TransparencyLog, witness: Witness, log_key
    ):
        """Continuing to serve the last good root would let the operator keep transacting
        against a history the witness already knows is disputed."""
        log.append(entry(0))
        log.append(entry(1))
        witness.observe(log.signed_tree_head())

        forked = TransparencyLog(log_id=LOG_ID, signing_key=log_key)
        forked.append(entry(0))
        forked.append({"id": "urn:uuid:1", "credentialSubject": {"n": "rewritten"}})
        forked.append(entry(2))
        with pytest.raises(ForkDetected):
            witness.observe(forked.signed_tree_head(), forked.consistency_proof(2))

        assert witness.current_root() is None
        with pytest.raises(ForkDetected, match="already forked"):
            witness.observe(log.signed_tree_head())

    def test_two_roots_at_the_same_size_are_a_fork(
        self, log: TransparencyLog, witness: Witness, log_key
    ):
        log.append(entry(0))
        witness.observe(log.signed_tree_head())
        other = TransparencyLog(log_id=LOG_ID, signing_key=log_key)
        other.append(entry(42))
        with pytest.raises(ForkDetected, match="two different roots"):
            witness.observe(other.signed_tree_head())


class TestHashEncoding:
    def test_round_trips(self, log: TransparencyLog):
        log.append(entry(0))
        head = log.signed_tree_head()
        assert decode_hash(head.root_hash) == log.root()

    def test_rejects_an_unprefixed_digest(self):
        with pytest.raises(ValueError):
            decode_hash("deadbeef")
