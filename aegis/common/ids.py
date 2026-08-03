"""ULID generation.

ULIDs are used instead of UUID4 because they sort lexicographically by creation time,
which makes trace and log inspection readable without a separate index. Implemented here
rather than pulled in as a dependency because it is 30 lines and the transparency log in
Phase 3 depends on the ordering property being one we control.

Spec: https://github.com/ulid/spec
"""

from __future__ import annotations

import os
import time

# Crockford base32: excludes I, L, O, U to avoid transcription ambiguity.
_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_TIME_LEN = 10
_RAND_LEN = 16


def _encode(value: int, length: int) -> str:
    chars = []
    for _ in range(length):
        chars.append(_ALPHABET[value & 0x1F])
        value >>= 5
    return "".join(reversed(chars))


def ulid() -> str:
    """Return a new ULID: 48-bit millisecond timestamp + 80 bits of randomness."""
    timestamp = int(time.time() * 1000)
    randomness = int.from_bytes(os.urandom(10), "big")
    return _encode(timestamp, _TIME_LEN) + _encode(randomness, _RAND_LEN)


def prefixed_id(prefix: str) -> str:
    """Return a namespaced identifier, e.g. ``seg_01J8ZQ...``."""
    return f"{prefix}_{ulid()}"


def segment_id() -> str:
    return prefixed_id("seg")


def trace_id() -> str:
    return prefixed_id("trc")


def mandate_id() -> str:
    return prefixed_id("mnd")
