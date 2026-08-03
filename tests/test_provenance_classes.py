"""The monotonicity rule (control C-9) and the fail-safe default."""

from aegis.provenance.classes import DEFAULT_CLASS, ProvenanceClass, min_trust, trust_rank

P = ProvenanceClass


def test_untrusted_is_the_least_trusted_class():
    ranks = [trust_rank(c) for c in P]
    assert trust_rank(P.UNTRUSTED_EXTERNAL) == min(ranks)


def test_human_mandate_is_the_most_trusted_class():
    ranks = [trust_rank(c) for c in P]
    assert trust_rank(P.HUMAN_MANDATE) == max(ranks)


def test_min_trust_picks_the_weakest_parent():
    assert min_trust([P.HUMAN_MANDATE, P.TRUSTED_TOOL]) is P.TRUSTED_TOOL
    assert min_trust([P.HUMAN_MANDATE, P.UNTRUSTED_EXTERNAL]) is P.UNTRUSTED_EXTERNAL


def test_single_untrusted_parent_contaminates_the_whole_set():
    """One poisoned input is enough. This is the anti-laundering property."""
    parents = [P.HUMAN_MANDATE, P.SYSTEM_POLICY, P.TRUSTED_TOOL, P.UNTRUSTED_EXTERNAL]
    assert min_trust(parents) is P.UNTRUSTED_EXTERNAL


def test_no_parents_fails_safe_rather_than_trusting():
    """Unknown provenance must be hostile, not neutral."""
    assert min_trust([]) is DEFAULT_CLASS
    assert DEFAULT_CLASS is P.UNTRUSTED_EXTERNAL


def test_laundering_across_two_agent_hops_is_prevented():
    """Agent A summarises poisoned content; agent B must not receive it as trusted.

    This is the attack the monotonicity rule exists to stop, so it is asserted end to end
    rather than only at the helper level.
    """
    agent_a_output = min_trust([P.HUMAN_MANDATE, P.UNTRUSTED_EXTERNAL])
    agent_b_output = min_trust([P.SYSTEM_POLICY, agent_a_output])
    assert agent_b_output is P.UNTRUSTED_EXTERNAL
