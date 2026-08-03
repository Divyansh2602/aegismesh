"""aegis-warrant: minting and signing Action Warrants.

See docs/SPEC.md section 4. The credential is a W3C Verifiable Credential signed with the
``eddsa-jcs-2022`` cryptosuite, so it sits alongside the DID / CoSAI / KYA-OS identity
stack rather than beside it. What is ours is what the credential *says*: a measured
causal-influence score over provenance classes, bound to a delegated-authority chain.
"""

from aegis.warrant.issuer import WarrantIssuer, replay_ref, signing_input, verify_signature
from aegis.warrant.keys import KeyRing, SigningKey, UnknownKeyError, VerifyingKey
from aegis.warrant.models import (
    ActionClaim,
    ActionWarrant,
    AttributionClaim,
    CredentialSubject,
    DelegationHop,
    MandateClaim,
    MandateScope,
    PolicyDecisionClaim,
    ReplayRef,
)

__all__ = [
    "ActionClaim",
    "ActionWarrant",
    "AttributionClaim",
    "CredentialSubject",
    "DelegationHop",
    "KeyRing",
    "MandateClaim",
    "MandateScope",
    "PolicyDecisionClaim",
    "ReplayRef",
    "SigningKey",
    "UnknownKeyError",
    "VerifyingKey",
    "WarrantIssuer",
    "replay_ref",
    "signing_input",
    "verify_signature",
]
