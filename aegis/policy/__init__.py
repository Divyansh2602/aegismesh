"""Declarative policy, shared as an evaluator and never as a verdict.

See docs/SPEC.md section 6. The issuer and the policy enforcement point both use this
package; they configure it with different policies, in different trust domains, and may
reach opposite conclusions about the same action. That is the intended behaviour, not a
race to be resolved.
"""

from aegis.policy.engine import Condition, Policy, PolicyResult, Rule
from aegis.policy.evidence import evidence_from_parts, evidence_from_warrant
from aegis.policy.library import (
    acme_treasury_policy,
    operator_issuer_policy,
    permissive_operator_policy,
)

__all__ = [
    "Condition",
    "Policy",
    "PolicyResult",
    "Rule",
    "acme_treasury_policy",
    "evidence_from_parts",
    "evidence_from_warrant",
    "operator_issuer_policy",
    "permissive_operator_policy",
]
