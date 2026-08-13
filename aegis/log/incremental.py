"""The same RFC 6962 tree, maintained incrementally instead of recomputed.

``merkle.py`` recomputes every subtree root from the leaf list on every call. That is the
most readable possible form of it, and readability is the whole reason the tree was
hand-written: the claim "the operator cannot have quietly rewritten this record" reduces
entirely to whether those functions are correct, so they must be checkable by a sceptic.

The cost of that form only became a problem when Phase 5a made the log **durable and
shared**, so its size stopped resetting. Measured on 2026-08-13: ``root_hash`` is O(n)
hashes, ``append`` triggers three full walks (``root`` twice plus an inclusion proof), and
building a tree of n leaves is O(n^2) — 22.6ms at n=100, 36.7s at n=5 000, 727s at
n=20 000. A public site whose pitch is that the log keeps growing had a cost curve pointed
the wrong way.

**This module does not replace ``merkle.py``; it is checked against it.** Every function
here has a counterpart there, and ``tests/test_incremental_tree.py`` asserts they agree for
every tree size and every index and split point across the range where the shapes vary.
The readable implementation is the specification; this one is the thing that runs. That
relationship is better than having only one implementation, because a disagreement between
them is a test failure rather than a silent divergence.

## Why levels work

RFC 6962 splits at ``k`` = the largest power of two strictly less than ``n``, which makes
the tree *left-complete*: every internal node except those on the right spine covers
exactly 2^L consecutive leaves starting at a multiple of 2^L. So the tree can be stored as
levels, where ``levels[L][j]`` is the root of leaves ``[j*2^L, (j+1)*2^L)``, and an odd
trailing node is carried upward unchanged. Appending touches only the right spine — O(log
n) — and any *canonical* subtree root is then a direct lookup rather than a walk.
"""

from __future__ import annotations

from aegis.log.merkle import _split, empty_root, node_hash


class IncrementalTree:
    """A left-complete RFC 6962 tree with cached internal nodes.

    ``levels[0]`` is the leaf hashes; ``levels[L][j]`` is the root of the subtree covering
    leaves ``[j*2^L, (j+1)*2^L)``, truncated at the end of the tree. The final level always
    holds exactly one node, which is the Merkle Tree Hash.
    """

    __slots__ = ("levels",)

    def __init__(self, leaves: list[bytes] | None = None) -> None:
        self.levels: list[list[bytes]] = [[]]
        for leaf in leaves or []:
            self.append(leaf)

    # ------------------------------------------------------------------ structure

    @property
    def size(self) -> int:
        return len(self.levels[0])

    def append(self, leaf: bytes) -> None:
        """Add one leaf and repair the right spine. O(log n) hashes.

        Only the rightmost node of each level can change when a leaf is added, because
        every other node covers a range that is already complete and therefore frozen —
        which is the append-only property expressed as an invariant about the data
        structure rather than as a promise about behaviour.
        """
        self.levels[0].append(leaf)

        level = 0
        while len(self.levels[level]) > 1:
            current = self.levels[level]
            # An even-length level pairs its last two nodes; an odd-length level carries
            # its last node upward unchanged. That carry is what reproduces RFC 6962's
            # split-at-largest-power-of-two shape without ever computing the split.
            parent = (
                node_hash(current[-2], current[-1])
                if len(current) % 2 == 0
                else current[-1]
            )
            index = (len(current) - 1) // 2

            if level + 1 == len(self.levels):
                self.levels.append([])
            above = self.levels[level + 1]
            if index < len(above):
                above[index] = parent
                del above[index + 1 :]
            else:
                above.append(parent)
            level += 1

        # A carry can leave levels above the new top stale; the top level is the one with a
        # single node, and anything past it no longer describes this tree.
        del self.levels[level + 1 :]

    def root(self) -> bytes:
        """The Merkle Tree Hash. O(1) — this is the read the whole service does most."""
        if not self.levels[0]:
            return empty_root()
        return self.levels[-1][0]

    # ---------------------------------------------------------------------- proofs

    def range_root(self, offset: int, size: int) -> bytes:
        """Root of ``leaves[offset : offset + size]``, per RFC 6962's shape.

        A *canonical* range — power-of-two length, aligned, and entirely inside the tree —
        is a stored node and costs one lookup. Anything else is split exactly the way
        ``merkle.root_hash`` splits it, so the answers cannot diverge, and the recursion
        bottoms out in canonical pieces after O(log n) steps.
        """
        if size == 0:
            return empty_root()
        if size == 1:
            return self.levels[0][offset]
        if (
            size & (size - 1) == 0
            and offset % size == 0
            and offset + size <= self.size
        ):
            level = size.bit_length() - 1
            return self.levels[level][offset // size]

        k = _split(size)
        return node_hash(
            self.range_root(offset, k), self.range_root(offset + k, size - k)
        )

    def inclusion_proof(self, index: int) -> list[bytes]:
        """Audit path for ``leaves[index]``. Ordered deepest sibling first, as RFC 6962
        specifies and as ``merkle.inclusion_proof`` produces."""
        if not 0 <= index < self.size:
            raise IndexError(f"leaf index {index} outside tree of size {self.size}")

        path: list[bytes] = []
        offset, size, target = 0, self.size, index
        while size > 1:
            k = _split(size)
            if target < k:
                path.append(self.range_root(offset + k, size - k))
                size = k
            else:
                path.append(self.range_root(offset, k))
                offset += k
                target -= k
                size -= k
        path.reverse()
        return path

    def consistency_proof(self, first: int) -> list[bytes]:
        """Proof that the tree of size ``first`` is a prefix of this one."""
        n = self.size
        if not 0 < first <= n:
            raise ValueError(f"consistency proof needs 0 < first <= n, got first={first} n={n}")
        if first == n:
            return []
        return self._subproof(0, n, first, True)

    def _subproof(self, offset: int, n: int, m: int, on_border: bool) -> list[bytes]:
        """RFC 6962 SUBPROOF, over a range of this tree rather than a sliced list.

        ``on_border`` tracks whether the subtree of size ``m`` is exactly the left edge of
        the current subtree. When it is, its root is already known to the verifier and is
        omitted; when it is not, it must be supplied.
        """
        path: list[bytes] = []
        while True:
            if m == n:
                if not on_border:
                    path.append(self.range_root(offset, n))
                break
            k = _split(n)
            if m <= k:
                path.append(self.range_root(offset + k, n - k))
                n = k
            else:
                path.append(self.range_root(offset, k))
                offset += k
                n -= k
                m -= k
                on_border = False
        path.reverse()
        return path
