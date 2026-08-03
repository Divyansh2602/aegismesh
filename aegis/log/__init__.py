"""aegis-log: the append-only Merkle transparency log.

See docs/SPEC.md section 5. RFC 6962 in structure, hand-implemented in ``merkle.py``
because the tamper-evidence claim reduces entirely to whether those functions are correct,
and a verifier taken on faith is not a verifier.

Not a blockchain, and THREAT_MODEL.md section 5 explains why at length: the requirement is
tamper-evidence and third-party verifiability, not decentralized consensus.
"""

from aegis.log.log import (
    Receipt,
    SignedTreeHead,
    TransparencyLog,
    decode_hash,
    encode_hash,
    verify_receipt,
)
from aegis.log.witness import ForkDetected, Witness

__all__ = [
    "ForkDetected",
    "Receipt",
    "SignedTreeHead",
    "TransparencyLog",
    "Witness",
    "decode_hash",
    "encode_hash",
    "verify_receipt",
]
