"""aegis-causa: causal attribution by leave-one-out counterfactual ablation.

See docs/SPEC.md section 3. Prior art this builds on rather than claims: CausalArmor,
AgentSentry, and Causal Agent Replay all re-execute agent steps to measure causal
influence. The contribution of AegisMesh is not the measurement -- it is binding the
measurement into a portable, enforceable credential (Phase 3).
"""

from aegis.attribution.engine import AttributionEngine
from aegis.attribution.gate import ConsequenceGate
from aegis.attribution.models import (
    ActionSignature,
    AttributionResult,
    Contributor,
    InfluenceDistribution,
)

__all__ = [
    "ActionSignature",
    "AttributionEngine",
    "AttributionResult",
    "ConsequenceGate",
    "Contributor",
    "InfluenceDistribution",
]
