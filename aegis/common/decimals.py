"""Fixed-precision encoding for every score that crosses a signature.

The problem this solves is narrow and easy to miss. ``common/hashing.py`` canonicalizes
JSON with Python's number formatting, which is not RFC 8785's -- JCS mandates ECMAScript
``Number::toString``, and the two disagree on floats needing 17 significant digits. For
most of the system that deviation is harmless. For the Action Warrant it is not: the whole
design rests on a third party in another language recomputing our exact bytes and checking
an Ed25519 signature over them. A verifier that serializes ``0.87`` differently sees a
valid warrant as a forgery.

So scores are never floats inside a signed credential. They are strings at a fixed
quantum, and the rules below are part of the wire format rather than an implementation
detail -- two correct implementations that skip any of them will still disagree.

**Normalize first, then round.** Rounding before normalizing lets the divisor differ
between implementations, which moves every value.

**ROUND_HALF_EVEN.** Named explicitly because it is not Python's ``round()`` semantics for
floats, not ``ROUND_HALF_UP``, and not what most languages default to. A tie at 0.00005
must break the same way everywhere.

**A rounded distribution does not sum to 1.0000, and verifiers must not require it to.**
Four independent roundings routinely land on 0.9999 or 1.0001. Any check demanding an
exact sum rejects honest warrants.

Consumers parse back to :class:`~decimal.Decimal`, never to ``float``. Parsing to float at
the policy enforcement point would reintroduce exactly this bug one layer down, where it
looks like a comparison being subtly wrong rather than a serialization mismatch.
"""

from __future__ import annotations

from collections.abc import Mapping
from decimal import ROUND_HALF_EVEN, Decimal

#: Four decimal places. Enough to express an influence share meaningfully, few enough that
#: the string form stays readable in a warrant an auditor reads by eye.
QUANTUM = Decimal("0.0001")

#: Rounding mode, named here once so the spec and the code cannot drift apart.
ROUNDING = ROUND_HALF_EVEN

def quantize(value: float | int | str | Decimal) -> Decimal:
    """Round ``value`` to the wire quantum using the mandated rounding mode."""
    if not isinstance(value, Decimal):
        # str() first: Decimal(float) captures the binary representation exactly
        # (0.1 -> 0.1000000000000000055511151231257827), which then rounds from a value
        # no other implementation shares.
        value = Decimal(str(value))
    return value.quantize(QUANTUM, rounding=ROUNDING)


def format_score(value: float | int | str | Decimal) -> str:
    """Encode a single score for a signed payload: ``0.87`` -> ``"0.8700"``."""
    return str(quantize(value))


def parse_score(text: str | Decimal) -> Decimal:
    """Decode a score from a signed payload into a Decimal.

    Deliberately returns Decimal rather than float. See the module docstring.
    """
    if isinstance(text, Decimal):
        return text
    return Decimal(text)


def format_distribution(weights: Mapping[object, float | Decimal]) -> dict[str, str]:
    """Encode a normalized distribution, keyed by the string form of each class.

    ``weights`` must already be normalized. This function rounds; it does not renormalize,
    because renormalizing after rounding would reintroduce the ordering dependence the
    normalize-then-round rule exists to remove.
    """
    return {str(key): format_score(value) for key, value in sorted(weights.items(), key=str)}


def parse_distribution(encoded: Mapping[str, str]) -> dict[str, Decimal]:
    """Decode a distribution from a signed payload into Decimals.

    Classes absent from the encoded form stay absent. Defaulting them to zero is the
    policy engine's job, and it is a decision that depends on the path being looked up --
    a missing influence share means "measured nothing", but a missing ``argument_status``
    means the field was never assessed at all.
    """
    return {key: parse_score(value) for key, value in encoded.items()}
