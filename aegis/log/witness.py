"""An independent witness of the transparency log.

This is a small object and it carries a large part of the argument. SPEC.md section 7
step 7 requires the relying party to verify inclusion against a root it obtained
*independently, never from the operator*. Without something in a different trust domain
holding that root, step 7 is a comment: the operator hands over a warrant, a receipt, and
the root the receipt should be checked against, and the whole exercise proves only that the
operator can do arithmetic consistently. Nothing then distinguishes this design from an
internal audit log, which is the thing it exists to be better than.

The witness does exactly three things:

1. checks the log's signature over each signed tree head it is shown,
2. checks that each new head is consistent with the last one it accepted,
3. refuses, permanently, if either check fails.

**Scope, stated honestly: one witness is one point of trust.** A single witness detects a
log that forks *between* the witness and someone else. It does nothing about a witness that
colludes with the operator, because then both sides of the comparison are controlled by the
same party. The production answer is N independent witnesses gossiping heads to each other,
so that a fork must fool all of them simultaneously. That is out of scope here; this
demonstrates the mechanism, not the deployment.
"""

from __future__ import annotations

from aegis.log import merkle
from aegis.log.log import SignedTreeHead, decode_hash
from aegis.warrant.keys import VerifyingKey


class ForkDetected(Exception):
    """The log presented two histories that cannot both be true.

    Raised rather than returned because there is no benign explanation and no sensible way
    to continue. A caller that could ignore this by forgetting to check a boolean is a
    caller that will.
    """


class Witness:
    """Holds the last signed tree head it accepted, and checks the next one against it."""

    def __init__(self, log_id: str, log_key: VerifyingKey) -> None:
        self.log_id = log_id
        self.log_key = log_key
        self._head: SignedTreeHead | None = None
        self._forked = False

    @property
    def head(self) -> SignedTreeHead | None:
        return self._head

    @property
    def tree_size(self) -> int:
        return self._head.tree_size if self._head else 0

    def current_root(self) -> bytes | None:
        """The root the relying party should verify inclusion against.

        Returns ``None`` once a fork has been seen. A witness that keeps serving its last
        good root after detecting a fork would let the operator carry on transacting
        against history the witness already knows is disputed.
        """
        if self._forked or self._head is None:
            return None
        return decode_hash(self._head.root_hash)

    def observe(self, head: SignedTreeHead, consistency_proof: list[str] | None = None) -> None:
        """Accept a new signed tree head, or raise ``ForkDetected``.

        ``consistency_proof`` is required for any head larger than the last one accepted.
        Omitting it is treated as a failure rather than as a first observation, because
        "the operator did not send a proof" and "the operator cannot produce a proof" are
        indistinguishable from here, and only one of them is innocent.
        """
        if self._forked:
            raise ForkDetected(f"{self.log_id} already forked; refusing further heads")
        if head.log_id != self.log_id:
            raise ForkDetected(f"head is for {head.log_id}, not {self.log_id}")
        if not head.verify(self.log_key):
            raise ForkDetected("signed tree head does not verify under the log's key")

        if self._head is None:
            self._head = head
            return

        previous = self._head
        if head.tree_size < previous.tree_size:
            self._forked = True
            raise ForkDetected(
                f"log shrank: {previous.tree_size} -> {head.tree_size}"
            )
        if head.tree_size == previous.tree_size:
            if head.root_hash != previous.root_hash:
                self._forked = True
                raise ForkDetected(
                    f"two different roots at size {head.tree_size}: "
                    f"{previous.root_hash} and {head.root_hash}"
                )
            self._head = head
            return

        proof = [decode_hash(h) for h in (consistency_proof or [])]
        consistent = merkle.verify_consistency(
            previous.tree_size,
            head.tree_size,
            decode_hash(previous.root_hash),
            decode_hash(head.root_hash),
            proof,
        )
        if not consistent:
            self._forked = True
            raise ForkDetected(
                f"size {head.tree_size} does not extend the accepted tree at size "
                f"{previous.tree_size}: an entry was altered or removed"
            )
        self._head = head
