"""aegis-pep: the policy enforcement point at the relying party.

See docs/SPEC.md section 7. This is the component that turns the system from one that
observes into one that refuses, and it runs in the trust domain of whoever holds the asset
-- the payment API, not the agent's operator.
"""

from aegis.pep.replay import ReplayCache
from aegis.pep.verifier import (
    STEP_NAMES,
    PolicyEnforcementPoint,
    StepResult,
    VerificationOutcome,
)

__all__ = [
    "STEP_NAMES",
    "PolicyEnforcementPoint",
    "ReplayCache",
    "StepResult",
    "VerificationOutcome",
]
