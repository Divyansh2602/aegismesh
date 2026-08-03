"""Hashing and canonical JSON serialization.

Everything that gets signed or compared across a trust boundary is canonicalized first.
Two parties must derive byte-identical input from the same logical object, or signature
verification fails for reasons that look like tampering.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

HASH_PREFIX = "sha256:"


def canonical_json(obj: Any) -> bytes:
    """Serialize to canonical JSON (RFC 8785 JCS, practical subset).

    Sorted keys, no insignificant whitespace, UTF-8, no ASCII escaping.

    Known deviation from strict RFC 8785: number serialization follows Python's repr
    rather than ECMAScript ``Number::toString``. Values that differ are floats needing
    17 significant digits. AegisMesh avoids the issue by carrying all money and influence
    values as strings or bounded-precision decimals in signed payloads -- see SPEC.md.
    Revisit before any cross-implementation interop claim.
    """
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return HASH_PREFIX + hashlib.sha256(data).hexdigest()


def hash_text(text: str) -> str:
    return sha256_hex(text.encode("utf-8"))


def hash_object(obj: Any) -> str:
    """Hash of the canonical JSON encoding of ``obj``."""
    return sha256_hex(canonical_json(obj))


def verify_hash(text: str, expected: str) -> bool:
    """Constant-time comparison of a text's hash against an expected digest."""
    import hmac

    return hmac.compare_digest(hash_text(text), expected)
