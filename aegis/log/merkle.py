"""RFC 6962 Merkle tree: hashing, proof generation, proof verification.

Hand-implemented rather than imported. Two reasons, and the second is the real one.

First, it is about 150 lines, and the dependency would be larger than the code.

Second, and more importantly: this is the part of the system a sceptical auditor has to be
able to check for themselves. The claim "the operator cannot have quietly rewritten this
record" reduces entirely to whether these functions are correct. A verifier that has to be
taken on faith is not a verifier.

Structure, per RFC 6962 section 2.1 (restated more clearly in RFC 9162):

    leaf   = SHA-256(0x00 || entry)
    node   = SHA-256(0x01 || left || right)
    MTH({}) = SHA-256("")

The domain-separating prefixes are not decoration. Without them an attacker could present
an internal node's two children as a leaf entry, making one tree admit two different
histories -- the second-preimage attack the prefixes exist to prevent.

Splits are always at ``k`` = the largest power of two strictly less than ``n``. That is
what makes the tree's shape a function of its size alone, so two parties who agree on the
entries agree on the root without exchanging anything else.
"""

from __future__ import annotations

import hashlib

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"


def empty_root() -> bytes:
    """MTH of the empty tree: the hash of the empty string, per RFC 6962."""
    return hashlib.sha256(b"").digest()


def leaf_hash(entry: bytes) -> bytes:
    return hashlib.sha256(LEAF_PREFIX + entry).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(NODE_PREFIX + left + right).digest()


def _split(n: int) -> int:
    """Largest power of two strictly less than ``n``. Requires ``n > 1``."""
    k = 1
    while k << 1 < n:
        k <<= 1
    return k


def root_hash(leaves: list[bytes]) -> bytes:
    """Merkle Tree Hash over a list of *leaf hashes*.

    Takes leaf hashes rather than raw entries so that callers who already computed them
    (the log, when appending) do not recompute, and so the distinction between "entry" and
    "leaf hash" never blurs -- confusing the two is how domain separation gets lost.
    """
    if not leaves:
        return empty_root()
    if len(leaves) == 1:
        return leaves[0]
    k = _split(len(leaves))
    return node_hash(root_hash(leaves[:k]), root_hash(leaves[k:]))


def inclusion_proof(leaves: list[bytes], index: int) -> list[bytes]:
    """Audit path proving ``leaves[index]`` is in the tree of ``leaves``."""
    if not 0 <= index < len(leaves):
        raise IndexError(f"leaf index {index} outside tree of size {len(leaves)}")
    if len(leaves) == 1:
        return []
    k = _split(len(leaves))
    if index < k:
        return inclusion_proof(leaves[:k], index) + [root_hash(leaves[k:])]
    return inclusion_proof(leaves[k:], index - k) + [root_hash(leaves[:k])]


def consistency_proof(leaves: list[bytes], first: int) -> list[bytes]:
    """Proof that the tree of size ``first`` is a prefix of the tree of ``leaves``.

    This is the proof that makes suppression and rewriting detectable (control C-13). An
    inclusion proof alone says a record is in *some* tree; consistency says the tree the
    record is in is the same tree, extended, as the one seen before.
    """
    n = len(leaves)
    if not 0 < first <= n:
        raise ValueError(f"consistency proof needs 0 < first <= n, got first={first} n={n}")
    if first == n:
        return []
    return _subproof(leaves, first, True)


def _subproof(leaves: list[bytes], m: int, on_border: bool) -> list[bytes]:
    """RFC 6962 SUBPROOF.

    ``on_border`` tracks whether the subtree of size ``m`` is exactly the left edge of the
    current subtree. When it is, its root is already known to the verifier and is omitted;
    when it is not, the root must be supplied.
    """
    n = len(leaves)
    if m == n:
        return [] if on_border else [root_hash(leaves)]
    k = _split(n)
    if m <= k:
        return _subproof(leaves[:k], m, on_border) + [root_hash(leaves[k:])]
    return _subproof(leaves[k:], m - k, False) + [root_hash(leaves[:k])]


def verify_inclusion(
    leaf: bytes,
    index: int,
    tree_size: int,
    proof: list[bytes],
    root: bytes,
) -> bool:
    """Recompute the root from a leaf and its audit path (RFC 9162 section 2.1.3.2).

    Verification is written as its own function rather than reusing the generator, because
    a verifier that shares code with the prover proves nothing about the prover.
    """
    if index >= tree_size or index < 0 or tree_size <= 0:
        return False
    if tree_size == 1:
        return not proof and leaf == root

    fn, sn = index, tree_size - 1
    computed = leaf
    for sibling in proof:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            computed = node_hash(sibling, computed)
            if not fn & 1:
                while fn and not fn & 1:
                    fn >>= 1
                    sn >>= 1
        else:
            computed = node_hash(computed, sibling)
        fn >>= 1
        sn >>= 1

    return sn == 0 and computed == root


def verify_consistency(
    first_size: int,
    second_size: int,
    first_root: bytes,
    second_root: bytes,
    proof: list[bytes],
) -> bool:
    """Verify that ``second_root`` extends ``first_root`` (RFC 9162 section 2.1.4.2).

    A false result means the log presented two histories that cannot both be true: either
    an entry was altered or one was removed. There is no benign explanation, which is why
    the witness treats it as fatal rather than as a warning.
    """
    if first_size < 1 or first_size > second_size:
        return False
    if first_size == second_size:
        return not proof and first_root == second_root

    path = list(proof)
    if first_size & (first_size - 1) == 0:
        # A tree whose size is a power of two is a complete subtree, so its root is not
        # transmitted -- the verifier already has it.
        path.insert(0, first_root)
    if not path:
        return False

    fn, sn = first_size - 1, second_size - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1

    computed_first = computed_second = path[0]
    for sibling in path[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            computed_first = node_hash(sibling, computed_first)
            computed_second = node_hash(sibling, computed_second)
            if not fn & 1:
                while fn and not fn & 1:
                    fn >>= 1
                    sn >>= 1
        else:
            computed_second = node_hash(computed_second, sibling)
        fn >>= 1
        sn >>= 1

    return sn == 0 and computed_first == first_root and computed_second == second_root
