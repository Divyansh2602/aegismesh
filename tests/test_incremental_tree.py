"""The incremental tree must agree with the readable one, everywhere.

``merkle.py`` is the specification: recomputed from the leaf list, ~150 lines, checkable by
a sceptic. ``incremental.py`` is what actually runs. Keeping both is only defensible if a
disagreement is a test failure rather than a silent divergence, so this file is that
guarantee.

The sweep is exhaustive rather than sampled on purpose. Merkle proof bugs are **shape**
bugs: they appear at non-power-of-two sizes, at the boundary where a carried node stops
being carried, and at the exact split points — never at the sizes a hand-picked example
would use. Sizes 0..130 cross seven powers of two, which is where every shape this tree can
take occurs at least once.
"""

from __future__ import annotations

import pytest

from aegis.log import merkle
from aegis.log.incremental import IncrementalTree


def leaves_for(n: int) -> list[bytes]:
    return [merkle.leaf_hash(f"entry-{i}".encode()) for i in range(n)]


class TestTheIncrementalRootMatchesTheRecomputedOne:
    @pytest.mark.parametrize("n", range(0, 131))
    def test_every_size_agrees_with_the_specification(self, n):
        leaves = leaves_for(n)
        assert IncrementalTree(leaves).root() == merkle.root_hash(leaves)

    def test_the_empty_tree_is_the_hash_of_the_empty_string(self):
        assert IncrementalTree().root() == merkle.empty_root()

    def test_appending_one_at_a_time_matches_building_at_once(self):
        """A log grows by one. If incremental appends and a bulk build ever disagreed, the
        root a visitor was handed would depend on how the process happened to start."""
        leaves = leaves_for(97)
        grown = IncrementalTree()
        for index, leaf in enumerate(leaves, start=1):
            grown.append(leaf)
            assert grown.root() == merkle.root_hash(leaves[:index])


class TestTheProofsMatchTheSpecification:
    @pytest.mark.parametrize("n", range(1, 66))
    def test_every_inclusion_proof_agrees(self, n):
        leaves = leaves_for(n)
        tree = IncrementalTree(leaves)
        for index in range(n):
            assert tree.inclusion_proof(index) == merkle.inclusion_proof(leaves, index)

    @pytest.mark.parametrize("n", range(1, 66))
    def test_every_consistency_proof_agrees(self, n):
        leaves = leaves_for(n)
        tree = IncrementalTree(leaves)
        for first in range(1, n + 1):
            assert tree.consistency_proof(first) == merkle.consistency_proof(leaves, first)

    @pytest.mark.parametrize("n", [1, 2, 3, 5, 8, 13, 33, 64, 65])
    def test_the_proofs_it_produces_actually_verify(self, n):
        """Agreeing with the oracle and being *correct* are different claims. The
        verifiers are written independently of the generators, so this closes the loop."""
        leaves = leaves_for(n)
        tree = IncrementalTree(leaves)
        root = tree.root()
        for index in range(n):
            assert merkle.verify_inclusion(
                leaves[index], index, n, tree.inclusion_proof(index), root
            )
        for first in range(1, n + 1):
            assert merkle.verify_consistency(
                first,
                n,
                merkle.root_hash(leaves[:first]),
                root,
                tree.consistency_proof(first),
            )

    def test_an_index_outside_the_tree_is_refused(self):
        tree = IncrementalTree(leaves_for(4))
        with pytest.raises(IndexError):
            tree.inclusion_proof(4)

    def test_a_proof_from_the_empty_tree_is_refused(self):
        """Every tree extends the empty one, so the proof would assert nothing."""
        tree = IncrementalTree(leaves_for(4))
        with pytest.raises(ValueError):
            tree.consistency_proof(0)


class TestTheCostStoppedBeingQuadratic:
    def test_appending_does_not_walk_the_whole_tree(self):
        """The reason this module exists, asserted rather than described.

        Counting hashes rather than timing: a wall-clock assertion is a flaky test on a
        shared runner, while the number of ``node_hash`` calls per append is exactly the
        property that changed. A left-complete tree touches only the right spine, so an
        append costs at most one hash per level.
        """
        calls = 0
        original = merkle.node_hash

        def counting(left: bytes, right: bytes) -> bytes:
            nonlocal calls
            calls += 1
            return original(left, right)

        import aegis.log.incremental as incremental

        incremental.node_hash = counting  # type: ignore[assignment]
        try:
            tree = IncrementalTree(leaves_for(1024))
            calls = 0
            tree.append(merkle.leaf_hash(b"one-more"))
        finally:
            incremental.node_hash = original  # type: ignore[assignment]

        # 1025 leaves is 11 levels deep. The recomputing implementation would hash every
        # internal node of a 1024-leaf tree here — over a thousand.
        assert calls <= 11, f"append cost {calls} hashes; it should touch only the spine"
