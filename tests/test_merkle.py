"""RFC 6962 Merkle tree: structure, proofs, and what a tampered log looks like.

The tests sweep every (index, size) and every (first, second) pair up to size 17 rather
than pinning a handful of vectors. Merkle proof bugs are characteristically *shape*
bugs -- they appear only at sizes that are not powers of two, or only for the rightmost
leaf, or only when the split lands exactly on the boundary. A sweep finds those; three
hand-picked examples do not.
"""

import hashlib

import pytest

from aegis.log import merkle


def leaves(n: int) -> list[bytes]:
    return [merkle.leaf_hash(f"entry-{i}".encode()) for i in range(n)]


class TestStructure:
    def test_empty_tree_is_the_hash_of_the_empty_string(self):
        assert merkle.root_hash([]) == hashlib.sha256(b"").digest()

    def test_single_leaf_tree_root_is_the_leaf(self):
        assert merkle.root_hash(leaves(1)) == leaves(1)[0]

    def test_two_leaf_root_is_the_node_hash(self):
        pair = leaves(2)
        assert merkle.root_hash(pair) == merkle.node_hash(pair[0], pair[1])

    def test_leaf_and_node_hashing_are_domain_separated(self):
        """The 0x00 / 0x01 prefixes stop an internal node being presented as a leaf.

        Without them an attacker could submit an entry whose bytes are the concatenation
        of two child hashes, and the same root would admit two different histories.
        """
        left, right = leaves(2)
        assert merkle.leaf_hash(left + right) != merkle.node_hash(left, right)

    def test_root_changes_when_any_leaf_changes(self):
        original = leaves(8)
        tampered = list(original)
        tampered[3] = merkle.leaf_hash(b"entry-3-modified")
        assert merkle.root_hash(original) != merkle.root_hash(tampered)

    def test_root_changes_when_leaves_are_reordered(self):
        original = leaves(8)
        swapped = list(original)
        swapped[2], swapped[5] = swapped[5], swapped[2]
        assert merkle.root_hash(original) != merkle.root_hash(swapped)


class TestInclusion:
    @pytest.mark.parametrize("size", range(1, 18))
    def test_every_leaf_proves_inclusion_at_every_size(self, size):
        tree = leaves(size)
        root = merkle.root_hash(tree)
        for index in range(size):
            proof = merkle.inclusion_proof(tree, index)
            assert merkle.verify_inclusion(tree[index], index, size, proof, root), (
                f"leaf {index} of {size} failed"
            )

    @pytest.mark.parametrize("size", range(1, 18))
    def test_proof_length_is_logarithmic(self, size):
        tree = leaves(size)
        longest = max(len(merkle.inclusion_proof(tree, i)) for i in range(size))
        assert longest <= size.bit_length()

    def test_a_leaf_not_in_the_tree_cannot_be_proven(self):
        tree = leaves(8)
        root = merkle.root_hash(tree)
        forged = merkle.leaf_hash(b"never-submitted")
        proof = merkle.inclusion_proof(tree, 3)
        assert not merkle.verify_inclusion(forged, 3, 8, proof, root)

    def test_a_proof_for_a_different_index_does_not_verify(self):
        tree = leaves(8)
        root = merkle.root_hash(tree)
        proof = merkle.inclusion_proof(tree, 3)
        assert not merkle.verify_inclusion(tree[3], 4, 8, proof, root)

    def test_a_proof_from_a_different_tree_does_not_verify(self):
        tree = leaves(8)
        other = [merkle.leaf_hash(f"other-{i}".encode()) for i in range(8)]
        assert not merkle.verify_inclusion(
            tree[3], 3, 8, merkle.inclusion_proof(other, 3), merkle.root_hash(tree)
        )

    def test_a_mutated_audit_path_does_not_verify(self):
        tree = leaves(8)
        root = merkle.root_hash(tree)
        proof = merkle.inclusion_proof(tree, 3)
        proof[0] = hashlib.sha256(b"wrong").digest()
        assert not merkle.verify_inclusion(tree[3], 3, 8, proof, root)

    def test_index_outside_the_tree_is_rejected(self):
        tree = leaves(4)
        root = merkle.root_hash(tree)
        assert not merkle.verify_inclusion(tree[0], 4, 4, [], root)
        assert not merkle.verify_inclusion(tree[0], -1, 4, [], root)


class TestConsistency:
    @pytest.mark.parametrize("second", range(1, 18))
    def test_every_prefix_is_provably_consistent(self, second):
        tree = leaves(second)
        second_root = merkle.root_hash(tree)
        for first in range(1, second + 1):
            proof = merkle.consistency_proof(tree, first)
            first_root = merkle.root_hash(tree[:first])
            assert merkle.verify_consistency(first, second, first_root, second_root, proof), (
                f"{first} -> {second} failed"
            )

    def test_a_rewritten_entry_breaks_consistency(self):
        """The property the whole transparency argument rests on.

        An operator who alters an already-published entry and appends more cannot produce
        a consistency proof, because no such proof exists -- the new tree is not an
        extension of the old one (control C-13).
        """
        original = leaves(4)
        original_root = merkle.root_hash(original)

        forked = list(original)
        forked[2] = merkle.leaf_hash(b"entry-2-rewritten")
        forked.append(merkle.leaf_hash(b"entry-4"))

        proof = merkle.consistency_proof(forked, 4)
        assert not merkle.verify_consistency(
            4, len(forked), original_root, merkle.root_hash(forked), proof
        )

    def test_a_removed_entry_breaks_consistency(self):
        original = leaves(6)
        original_root = merkle.root_hash(original)
        truncated = original[:3] + original[4:] + [merkle.leaf_hash(b"entry-6")]
        proof = merkle.consistency_proof(truncated, 6)
        assert not merkle.verify_consistency(
            6, len(truncated), original_root, merkle.root_hash(truncated), proof
        )

    def test_a_shrinking_tree_is_rejected(self):
        tree = leaves(8)
        assert not merkle.verify_consistency(
            8, 4, merkle.root_hash(tree), merkle.root_hash(tree[:4]), []
        )

    def test_identical_sizes_need_identical_roots_and_no_proof(self):
        tree = leaves(5)
        root = merkle.root_hash(tree)
        assert merkle.verify_consistency(5, 5, root, root, [])
        assert not merkle.verify_consistency(5, 5, root, merkle.root_hash(leaves(4)), [])

    def test_an_empty_proof_cannot_bridge_two_sizes(self):
        tree = leaves(7)
        assert not merkle.verify_consistency(
            3, 7, merkle.root_hash(tree[:3]), merkle.root_hash(tree), []
        )

    def test_first_size_must_be_positive_and_within_the_tree(self):
        tree = leaves(4)
        with pytest.raises(ValueError):
            merkle.consistency_proof(tree, 0)
        with pytest.raises(ValueError):
            merkle.consistency_proof(tree, 5)
