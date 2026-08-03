"""Ed25519 keys, multibase encoding, and a stand-in for DID resolution.

Two things here are deliberately hand-rolled rather than pulled in as dependencies.

**base58btc** is twenty lines and sits directly on the verification path. An auditor
reading ``tools/verify_warrant.py`` should be able to follow every byte from the JSON on
disk to the signature check without trusting a transitive dependency.

**The key ring** stands in for DID resolution. Resolving ``did:web:...#key-1`` to a public
key in production means an HTTPS fetch of a DID document; here it is a dictionary. The
substitution is safe for the security argument because the property that matters is that
the relying party obtains the issuer's key from *its own* trust configuration rather than
from the warrant. A warrant that carried its own verification key would prove nothing --
an attacker would simply ship a warrant signed by a key of their choosing.
"""

from __future__ import annotations

import hashlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

#: multicodec prefix for an Ed25519 public key, per the multicodec table. The VC Data
#: Integrity suites identify key type by this prefix rather than by a separate field.
_ED25519_PUB_MULTICODEC = b"\xed\x01"

MULTIBASE_BASE58BTC = "z"


def b58_encode(data: bytes) -> str:
    """Bitcoin-flavoured base58. Leading zero bytes become leading '1's."""
    value = int.from_bytes(data, "big")
    out: list[str] = []
    while value > 0:
        value, remainder = divmod(value, 58)
        out.append(_B58_ALPHABET[remainder])
    for byte in data:
        if byte != 0:
            break
        out.append(_B58_ALPHABET[0])
    return "".join(reversed(out))


def b58_decode(text: str) -> bytes:
    value = 0
    for char in text:
        index = _B58_ALPHABET.find(char)
        if index < 0:
            raise ValueError(f"invalid base58 character: {char!r}")
        value = value * 58 + index

    leading_zeros = 0
    for char in text:
        if char != _B58_ALPHABET[0]:
            break
        leading_zeros += 1

    body = value.to_bytes((value.bit_length() + 7) // 8, "big") if value else b""
    return b"\x00" * leading_zeros + body


def multibase_encode(data: bytes) -> str:
    """Multibase base58btc: a 'z' prefix naming the alphabet used."""
    return MULTIBASE_BASE58BTC + b58_encode(data)


def multibase_decode(text: str) -> bytes:
    if not text.startswith(MULTIBASE_BASE58BTC):
        raise ValueError(f"unsupported multibase prefix: {text[:1]!r}")
    return b58_decode(text[1:])


class VerifyingKey:
    """A public key, plus the multibase form that appears in a DID document."""

    __slots__ = ("_key",)

    def __init__(self, key: Ed25519PublicKey) -> None:
        self._key = key

    @classmethod
    def from_bytes(cls, raw: bytes) -> VerifyingKey:
        return cls(Ed25519PublicKey.from_public_bytes(raw))

    @classmethod
    def from_multibase(cls, text: str) -> VerifyingKey:
        decoded = multibase_decode(text)
        if not decoded.startswith(_ED25519_PUB_MULTICODEC):
            raise ValueError("public key is not multicodec ed25519-pub")
        return cls.from_bytes(decoded[len(_ED25519_PUB_MULTICODEC) :])

    def to_bytes(self) -> bytes:
        return self._key.public_bytes(Encoding.Raw, PublicFormat.Raw)

    def to_multibase(self) -> str:
        return multibase_encode(_ED25519_PUB_MULTICODEC + self.to_bytes())

    def verify(self, signature: bytes, message: bytes) -> bool:
        """Return whether ``signature`` is valid. Never raises on a bad signature.

        Returning a bool rather than raising keeps the verification algorithm in
        ``aegis/pep/verifier.py`` linear: every one of its eleven steps reports pass or
        fail the same way, so no step can be accidentally skipped by an exception path.
        """
        try:
            self._key.verify(signature, message)
        except InvalidSignature:
            return False
        return True


class SigningKey:
    """An Ed25519 private key.

    ``from_seed`` exists so the demo and the tests are byte-for-byte reproducible offline.
    It is not a key-derivation function and must never be used to make a production key
    from a password -- the seed is the key.
    """

    __slots__ = ("_key",)

    def __init__(self, key: Ed25519PrivateKey) -> None:
        self._key = key

    @classmethod
    def generate(cls) -> SigningKey:
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_seed(cls, seed: str | bytes) -> SigningKey:
        material = seed.encode("utf-8") if isinstance(seed, str) else seed
        return cls(Ed25519PrivateKey.from_private_bytes(hashlib.sha256(material).digest()))

    def to_bytes(self) -> bytes:
        return self._key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())

    @property
    def public(self) -> VerifyingKey:
        return VerifyingKey(self._key.public_key())

    def sign(self, message: bytes) -> bytes:
        return self._key.sign(message)

    def sign_multibase(self, message: bytes) -> str:
        return multibase_encode(self.sign(message))


class UnknownKeyError(LookupError):
    """Raised when a verification method resolves to no key we are willing to trust."""


class KeyRing:
    """The relying party's own map of verification method -> public key.

    Revocation is modelled as removal from this map. That is weaker than a real revocation
    list -- it is local, so one party revoking does not inform another -- and the gap is
    stated in THREAT_MODEL.md rather than papered over.
    """

    def __init__(self) -> None:
        self._keys: dict[str, VerifyingKey] = {}
        self._revoked: set[str] = set()

    def register(self, verification_method: str, key: VerifyingKey) -> None:
        self._keys[verification_method] = key

    def revoke(self, verification_method: str) -> None:
        self._revoked.add(verification_method)

    def resolve(self, verification_method: str) -> VerifyingKey:
        if verification_method in self._revoked:
            raise UnknownKeyError(f"{verification_method} is revoked")
        key = self._keys.get(verification_method)
        if key is None:
            raise UnknownKeyError(f"{verification_method} is not a known verification method")
        return key

    def knows(self, verification_method: str) -> bool:
        return verification_method in self._keys and verification_method not in self._revoked
