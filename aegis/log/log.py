"""aegis-log — the append-only transparency log (docs/SPEC.md section 5).

Warrants are submitted here and receive a receipt. A relying party will not honour an
action whose warrant has no receipt, which is what makes the log load-bearing rather than
decorative: an operator who declines to log a permit has produced a warrant nobody will
accept.

**Why this is not a blockchain.** The requirement is tamper-evidence and third-party
verifiability, not decentralized consensus. A Certificate-Transparency-style Merkle log
gives append-only guarantees with O(log n) inclusion and consistency proofs at microsecond
cost. A blockchain would add consensus latency, per-record cost, and the compliance
problem of publishing regulated financial metadata to a public chain, while providing no
integrity property this lacks once external witnesses exist. Anchoring roots to a public
chain for third-party timestamping is the one genuinely useful blockchain role, and it is
optional. THREAT_MODEL.md section 5 has the long form.

**What the log does not do.** It proves an entry was recorded and never altered. It does
not prove the entry was true. An issuer that signs a warrant containing fabricated
attribution produces a log entry that is permanently, verifiably theirs -- which converts
forgery from undetectable into non-repudiable, but not into prevented.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from aegis.common.hashing import HASH_PREFIX, canonical_json
from aegis.log import merkle
from aegis.log.incremental import IncrementalTree
from aegis.log.storage import InMemoryLogStorage, LogStorage
from aegis.warrant.keys import SigningKey, VerifyingKey, multibase_decode
from aegis.warrant.models import iso, utc_now


def encode_hash(digest: bytes) -> str:
    return HASH_PREFIX + digest.hex()


def decode_hash(text: str) -> bytes:
    if not text.startswith(HASH_PREFIX):
        raise ValueError(f"expected a {HASH_PREFIX} digest, got {text[:16]!r}")
    return bytes.fromhex(text[len(HASH_PREFIX) :])


class SignedTreeHead(BaseModel):
    """The log's signed commitment to its contents at one size.

    The signature covers size, root, and timestamp together. Signing the root alone would
    let a log replay an old root under a new timestamp; signing size alongside it is what
    makes a consistency proof between two heads meaningful.
    """

    log_id: str
    tree_size: int
    root_hash: str
    timestamp: str
    signature: str | None = None

    def signed_bytes(self) -> bytes:
        return canonical_json(
            {
                "log_id": self.log_id,
                "root_hash": self.root_hash,
                "timestamp": self.timestamp,
                "tree_size": self.tree_size,
            }
        )

    def verify(self, key: VerifyingKey) -> bool:
        if not self.signature:
            return False
        try:
            raw = multibase_decode(self.signature)
        except ValueError:
            return False
        return key.verify(raw, self.signed_bytes())


class Receipt(BaseModel):
    """Proof that a specific warrant is in the log (SPEC.md section 5.1)."""

    log_id: str
    leaf_index: int
    tree_size: int
    root_hash: str
    inclusion_proof: list[str] = Field(default_factory=list)
    signed_root: SignedTreeHead

    def proof_bytes(self) -> list[bytes]:
        return [decode_hash(h) for h in self.inclusion_proof]


class TransparencyLog:
    """An append-only Merkle log over canonicalized warrant documents."""

    def __init__(
        self,
        log_id: str,
        signing_key: SigningKey,
        storage: LogStorage | None = None,
    ) -> None:
        """``storage`` defaults to in-memory, which is what every demo and test wants.

        The tree is held in memory either way and rebuilt from the stored entries on load.
        Proofs read cached internal nodes, so serving them from the database would turn an
        O(log n) proof into O(n) queries for a tree small enough to fit in a few megabytes
        -- storage is for surviving a restart, not for the read path.

        The tree is an ``IncrementalTree`` rather than a leaf list walked by
        ``merkle.root_hash``. Both produce identical roots and proofs and the tests assert
        exactly that; what changed is the cost. Recomputing made ``append`` O(n) and
        building a log O(n^2), which was invisible while the log reset on every restart and
        became a real curve once Phase 5a made it durable and shared.
        """
        self.log_id = log_id
        self.signing_key = signing_key
        self.storage: LogStorage = InMemoryLogStorage() if storage is None else storage
        self._entries: list[bytes] = self.storage.load()
        self._tree = IncrementalTree([merkle.leaf_hash(entry) for entry in self._entries])

    def __len__(self) -> int:
        return self._tree.size

    @property
    def tree_size(self) -> int:
        return self._tree.size

    def root(self) -> bytes:
        return self._tree.root()

    def append(self, document: dict[str, Any]) -> Receipt:
        """Add a warrant document and return its receipt.

        The entry is the canonical JSON of the document as submitted. Canonicalizing here
        rather than trusting the submitter's byte stream means two submissions of the same
        logical warrant produce the same leaf, so a duplicate is visibly a duplicate.
        """
        entry = canonical_json(document)
        leaf = merkle.leaf_hash(entry)
        index = self._tree.size

        # Durable first. If the write fails, the in-memory tree must not advance past what
        # was persisted, or a restart would silently produce a *shorter* log than the one
        # whose roots were already signed and handed out.
        self.storage.append(index, entry, leaf)

        self._entries.append(entry)
        self._tree.append(leaf)
        return self.receipt_for(index)

    def receipt_for(self, index: int) -> Receipt:
        return Receipt(
            log_id=self.log_id,
            leaf_index=index,
            tree_size=self._tree.size,
            root_hash=encode_hash(self.root()),
            inclusion_proof=[encode_hash(h) for h in self._tree.inclusion_proof(index)],
            signed_root=self.signed_tree_head(),
        )

    def signed_tree_head(self) -> SignedTreeHead:
        head = SignedTreeHead(
            log_id=self.log_id,
            tree_size=self._tree.size,
            root_hash=encode_hash(self.root()),
            timestamp=iso(utc_now()),
        )
        head.signature = self.signing_key.sign_multibase(head.signed_bytes())
        return head

    def consistency_proof(self, first_size: int) -> list[str]:
        return [encode_hash(h) for h in self._tree.consistency_proof(first_size)]

    def entry(self, index: int) -> bytes:
        return self._entries[index]


def verify_receipt(document: dict[str, Any], receipt: Receipt, root: bytes) -> bool:
    """Check that ``document`` is in a log whose root is ``root``.

    ``root`` is passed in rather than read from the receipt on purpose. The receipt's own
    root came from the operator, and an operator who forged a warrant would forge a
    matching root to go with it. Verification is only worth anything against a root the
    relying party obtained elsewhere -- SPEC.md section 7 step 7.
    """
    leaf = merkle.leaf_hash(canonical_json(document))
    return merkle.verify_inclusion(
        leaf,
        receipt.leaf_index,
        receipt.tree_size,
        receipt.proof_bytes(),
        root,
    )
