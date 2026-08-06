"""The monotonicity threshold theta, and the parent-influence estimate it thresholds.

SPEC.md section 2.2 defines an agent-generated segment's class as the least trust among its
causal parents *above an influence threshold theta*, default 0.15, and says theta must be
swept in Phase 4.

**Sweeping it required implementing it first.** Phase 1 approximated causal parents as
every preceding segment, documented that as conservative, and left the replacement to
Phase 2, which never happened. The consequence was not a missing feature so much as a
missing question: with every parent counted, theta multiplies a constant 1.0 and no value
of it changes any classification. The knob existed in the specification and not in the
system, and nobody would have noticed by reading either one alone.

## What influence(parent -> agent output) can honestly mean here

The specification's quantity is causal: re-generate the agent's turn with the parent
removed and measure the disagreement. That is the same leave-one-out machinery the
attribution engine uses, and it is not available at classification time -- classification
runs *before* attribution and feeds it, so making it depend on attribution is circular. It
also needs a model that can regenerate intermediate agent turns, which costs one call per
parent per agent message on every request rather than only on consequential ones.

So two estimators ship, and the difference between them is stated rather than blurred:

``AllParents``      -- every parent influences every output. Phase 1's rule, kept as the
                       default because it can only over-restrict. theta has no effect
                       under it, which is the honest encoding of "not measured".
``LexicalOverlap``  -- the share of a parent's distinctive tokens that survive into the
                       agent's output. A **proxy**, not a measurement: it sees copying and
                       quotation, and it is blind to a faithful paraphrase, which is
                       exactly what a competent summarizing agent produces. Its failure
                       mode is therefore the dangerous one -- it under-detects laundering
                       of paraphrased content -- and the sweep in ``evaluation/theta.py``
                       measures how fast that sets in.

Nothing here should be read as the specification's quantity having been measured. What has
been measured is what a cheap proxy buys and where it breaks, which is the argument for
whether the expensive version is worth building.
"""

from __future__ import annotations

import re
from typing import Protocol

from aegis.provenance.classes import DEFAULT_CLASS, ProvenanceClass, trust_rank

#: Default from SPEC.md section 2.2. Carried here so the specification and the code have
#: one place to disagree rather than two.
DEFAULT_THETA = 0.15

_TOKEN = re.compile(r"[\w@.:/-]+")

#: Tokens too common to distinguish one source from another. Deliberately short: a long
#: stoplist tuned on our own scenarios would raise measured overlap without raising the
#: estimator's real discriminating power.
_COMMON = frozenset(
    {
        "the", "a", "an", "and", "or", "of", "to", "for", "in", "on", "is", "are",
        "was", "were", "be", "by", "with", "from", "that", "this", "it", "as", "at",
        "please", "you", "your", "our", "we", "i", "me", "my", "has", "have", "will",
    }
)


class ParentInfluence(Protocol):
    """Estimates how much a candidate parent shaped an agent's output."""

    def __call__(self, parent_text: str, output_text: str) -> float: ...


def all_parents(parent_text: str, output_text: str) -> float:
    """Phase 1's rule: everything in the window is a parent.

    Returns 1.0 unconditionally, so every parent clears every theta below 1.0. Conservative
    by construction -- it can only over-restrict, never over-trust -- and it is why theta
    was inert until now.
    """
    return 1.0


def lexical_overlap(parent_text: str, output_text: str) -> float:
    """Share of the parent's distinctive tokens that appear in the agent's output.

    Directional on purpose. Scoring the intersection against the *output's* tokens would
    let a one-line summary of a long poisoned document score near 1.0 against every parent
    it barely touched, because a short output has few tokens to match. The question is how
    much of this parent survived, so the parent is the denominator.
    """
    parent = _tokens(parent_text)
    if not parent:
        return 0.0
    output = _tokens(output_text)
    return len(parent & output) / len(parent)


def derive_class(
    parents: list[tuple[ProvenanceClass, str]],
    output_text: str,
    theta: float = DEFAULT_THETA,
    influence: ParentInfluence = all_parents,
) -> tuple[ProvenanceClass, list[int]]:
    """Apply the monotonicity rule, returning the derived class and which parents counted.

    Returning the surviving parents matters as much as the class. An investigator asking
    why an agent's summary was demoted to P3 needs to see *which* untrusted segment reached
    it, and a bare class cannot answer that. It is also what makes a theta sweep readable:
    the classification changes because the parent set changed, and both are visible.

    No parent clearing theta yields the fail-safe default rather than P4. An agent output
    nothing measurably caused is not thereby trustworthy -- it is unexplained, and control
    C-1 says unexplained is hostile.
    """
    surviving = [
        index
        for index, (_, text) in enumerate(parents)
        if influence(text, output_text) >= theta
    ]
    if not surviving:
        return DEFAULT_CLASS, []

    classes = [parents[index][0] for index in surviving]
    return min(classes, key=trust_rank), surviving


def _tokens(text: str) -> set[str]:
    return {t for t in (m.lower() for m in _TOKEN.findall(text)) if t not in _COMMON}
