"""Provenance classification and the monotonicity rule.

See docs/SPEC.md section 2.
"""

from aegis.provenance.classes import ProvenanceClass, min_trust, trust_rank
from aegis.provenance.models import ContextTrace, Segment, SegmentSource, SourceKind
from aegis.provenance.registry import ToolRegistry, TrustedTool

__all__ = [
    "ContextTrace",
    "ProvenanceClass",
    "Segment",
    "SegmentSource",
    "SourceKind",
    "ToolRegistry",
    "TrustedTool",
    "min_trust",
    "trust_rank",
]
