"""Provenance classes and their trust ordering.

The five classes are defined in docs/SPEC.md section 2. The ordering below is the only
place trust is ranked; everything else defers to ``trust_rank``.
"""

from __future__ import annotations

from enum import StrEnum


class ProvenanceClass(StrEnum):
    """Where a piece of context came from, and therefore how much it is trusted."""

    HUMAN_MANDATE = "P0"
    SYSTEM_POLICY = "P1"
    TRUSTED_TOOL = "P2"
    UNTRUSTED_EXTERNAL = "P3"
    AGENT_GENERATED = "P4"


#: Higher rank means more trusted. P4 is deliberately absent -- an agent-generated
#: segment has no intrinsic trust; it derives its class from its causal parents via the
#: monotonicity rule, so ranking it directly would be a category error.
_TRUST_ORDER: dict[ProvenanceClass, int] = {
    ProvenanceClass.HUMAN_MANDATE: 40,
    ProvenanceClass.SYSTEM_POLICY: 30,
    ProvenanceClass.TRUSTED_TOOL: 20,
    ProvenanceClass.AGENT_GENERATED: 10,
    ProvenanceClass.UNTRUSTED_EXTERNAL: 0,
}

#: The class assigned when provenance cannot be established. Unknown provenance is
#: treated as hostile, not as neutral -- this is the fail-safe default the whole design
#: rests on (THREAT_MODEL.md, control C-1).
DEFAULT_CLASS = ProvenanceClass.UNTRUSTED_EXTERNAL


def trust_rank(cls: ProvenanceClass) -> int:
    return _TRUST_ORDER[cls]


def min_trust(classes: list[ProvenanceClass]) -> ProvenanceClass:
    """Return the least-trusted class in ``classes``.

    This implements the core of the monotonicity rule (SPEC.md 2.2, control C-9): an
    agent-generated segment inherits the lowest trust among the segments that causally
    influenced it. Without it, an attacker injects into agent A, A summarizes the poisoned
    text, and agent B receives that summary as trusted peer output -- the injection has
    been laundered across a trust boundary.

    An empty input yields the fail-safe default rather than raising, because "this segment
    has no known parents" is exactly the situation where we must not assume trust.
    """
    if not classes:
        return DEFAULT_CLASS
    return min(classes, key=trust_rank)
