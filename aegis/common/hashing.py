"""Hashing and canonical JSON serialization (RFC 8785, JCS).

Everything that gets signed or compared across a trust boundary is canonicalized first.
Two parties must derive byte-identical input from the same logical object, or signature
verification fails for reasons that look exactly like tampering.

**This is hand-written rather than delegated to ``json.dumps``, and that is not
gold-plating.** ``json.dumps(sort_keys=True, separators=...)`` gets whitespace and key
order right and numbers wrong. Python renders a float via ``repr``; JCS mandates
ECMAScript ``Number::toString``. They disagree on ordinary values, not exotic ones -- the
mock model proposes ``amount: 2000000.0``, which Python writes as ``2000000.0`` and every
JavaScript, Go, or Java JCS implementation writes as ``2000000``. That value goes straight
into ``arguments_hash``, so a relying party in another language recomputing the hash from
the very same arguments would conclude the warrant had been tampered with.

An earlier revision of this file documented the deviation and deferred it with a note
saying it could not be hit because signed payloads carried numbers as strings. That held
for influence scores, which we control. It did not hold for tool-call arguments, which
arrive from the agent and can be any JSON the model emitted. The deviation was on the
critical path the whole time.

So: numbers follow ECMAScript ``Number::toString``, keys sort by UTF-16 code unit, strings
use RFC 8259 minimal escaping, and non-ASCII passes through as UTF-8.

Remaining limits, stated rather than hidden:

  * Python ``int`` is serialized exactly at any magnitude. A JCS implementation backed by
    IEEE-754 doubles cannot represent integers beyond 2^53 and will disagree. JSON itself
    does not resolve this; do not put such integers in a signed payload.
  * ``NaN`` and the infinities are rejected. They are not JSON, and silently emitting
    ``null`` for them would let an unrepresentable value pass through a signature check.
"""

from __future__ import annotations

import hashlib
import hmac
import math
from decimal import Decimal
from typing import Any

HASH_PREFIX = "sha256:"

#: Beyond this exponent ECMAScript switches to scientific notation.
_MAX_PLAIN_EXPONENT = 21

_ESCAPES = {
    '"': '\\"',
    "\\": "\\\\",
    "\b": "\\b",
    "\f": "\\f",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
}


def _escape_string(value: str) -> str:
    out = ['"']
    for char in value:
        escape = _ESCAPES.get(char)
        if escape is not None:
            out.append(escape)
        elif char < "\x20":
            out.append(f"\\u{ord(char):04x}")
        else:
            # Everything else, including all non-ASCII, is emitted literally as UTF-8.
            # JCS forbids \u-escaping characters that do not require it.
            out.append(char)
    out.append('"')
    return "".join(out)


def _serialize_number(value: float | int | Decimal) -> str:
    """Render a number per ECMAScript ``Number::toString`` (ECMA-262 6.1.6.1.20).

    The specification is stated in terms of the shortest digit string ``s`` and an exponent
    ``n`` with ``value = s x 10^(n-k)``, ``k = len(s)``. Python's ``repr`` already produces
    the shortest round-tripping digits, so the work here is entirely in choosing between
    plain and exponential form the way ECMAScript chooses -- the thresholds differ from
    Python's, which is where the two implementations part company.
    """
    if isinstance(value, bool):  # bool is an int subclass; JSON has a separate literal.
        raise TypeError("bool must be serialized as a JSON literal, not a number")
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            raise ValueError(f"{value!r} is not representable in JSON")
        if value == 0:
            return "0"  # JCS folds -0 to 0.
        decimal = Decimal(repr(value))
    else:
        decimal = value

    sign, digits, exponent = decimal.as_tuple()
    if not isinstance(exponent, int):  # NaN / Infinity Decimals
        raise ValueError(f"{value!r} is not representable in JSON")

    # Strip trailing zeros so that `s` is the shortest digit string, adjusting the
    # exponent to keep the value identical. Without this, 2000000.0 keeps eight digits
    # and lands in a different formatting branch than the one ECMAScript picks.
    digit_list = list(digits)
    while len(digit_list) > 1 and digit_list[-1] == 0:
        digit_list.pop()
        exponent += 1

    s = "".join(str(d) for d in digit_list)
    if s == "0":
        return "0"
    k = len(s)
    n = k + exponent
    prefix = "-" if sign else ""

    if k <= n <= _MAX_PLAIN_EXPONENT:
        return prefix + s + "0" * (n - k)
    if 0 < n <= _MAX_PLAIN_EXPONENT:
        return prefix + s[:n] + "." + s[n:]
    if -6 < n <= 0:
        return prefix + "0." + "0" * -n + s
    exp = n - 1
    mantissa = s if k == 1 else s[0] + "." + s[1:]
    return f"{prefix}{mantissa}e{'+' if exp >= 0 else '-'}{abs(exp)}"


def _sort_key(key: str) -> bytes:
    """JCS sorts object keys by UTF-16 code unit, not by Unicode code point.

    For ASCII field names the two orders agree, so this looks like pedantry. It stops
    agreeing above the BMP, where a code-point sort and a UTF-16 sort invert -- and a
    warrant whose keys sorted differently on two implementations would fail verification
    with no visible cause.
    """
    return key.encode("utf-16-be")


def _serialize(value: Any, out: list[str]) -> None:
    if value is None:
        out.append("null")
    elif value is True:
        out.append("true")
    elif value is False:
        out.append("false")
    elif isinstance(value, str):
        out.append(_escape_string(value))
    elif isinstance(value, (int, float, Decimal)):
        out.append(_serialize_number(value))
    elif isinstance(value, dict):
        out.append("{")
        # Type-check before sorting, not during. Sorting first makes a non-string key
        # surface as an AttributeError from inside the sort key function, which reads like
        # a bug in the canonicalizer rather than bad input.
        for key in value:
            if not isinstance(key, str):
                raise TypeError(f"JSON object keys must be strings, got {type(key).__name__}")
        for index, key in enumerate(sorted(value, key=_sort_key)):
            if index:
                out.append(",")
            out.append(_escape_string(key))
            out.append(":")
            _serialize(value[key], out)
        out.append("}")
    elif isinstance(value, (list, tuple)):
        out.append("[")
        for index, item in enumerate(value):
            if index:
                out.append(",")
            _serialize(item, out)
        out.append("]")
    else:
        raise TypeError(f"{type(value).__name__} is not JSON-serializable")


def canonical_json(obj: Any) -> bytes:
    """Serialize to canonical JSON per RFC 8785."""
    out: list[str] = []
    _serialize(obj, out)
    return "".join(out).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return HASH_PREFIX + hashlib.sha256(data).hexdigest()


def hash_text(text: str) -> str:
    return sha256_hex(text.encode("utf-8"))


def hash_object(obj: Any) -> str:
    """Hash of the canonical JSON encoding of ``obj``."""
    return sha256_hex(canonical_json(obj))


def verify_hash(text: str, expected: str) -> bool:
    """Constant-time comparison of a text's hash against an expected digest."""
    return hmac.compare_digest(hash_text(text), expected)
