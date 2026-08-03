"""Assemble the evidence a policy is evaluated against.

The same shape is built twice, in two trust domains, from two different sources:

  * the **issuer** builds it from the attribution it just measured and the arguments the
    model proposed;
  * the **relying party** builds it from the attribution claimed in a signed warrant and
    the arguments *it actually received on the wire*.

The second source is the one that matters. The warrant carries only per-field digests, so
the relying party cannot read an amount out of it -- it reads the amount from the request
in front of it, and step 5 of the verification algorithm proves that request is the one the
warrant describes. That is what lets a value-bound rule like "transfers over 10,000 need
human causation" be enforced without the warrant ever disclosing the amount.
"""

from __future__ import annotations

from collections.abc import Mapping
from decimal import Decimal
from typing import Any

from aegis.common.decimals import parse_distribution, parse_score
from aegis.warrant.models import ActionWarrant


def evidence_from_parts(
    tool: str,
    operation: str,
    arguments: Mapping[str, Any],
    influence: Mapping[str, Decimal | str],
    necessity: Mapping[str, Decimal | str],
    per_argument: Mapping[str, Mapping[str, Decimal | str]],
    confidence: Decimal | str,
    argument_status: Mapping[str, str] | None = None,
    per_argument_confidence: Mapping[str, Decimal | str] | None = None,
    delegation_chain: list[dict] | None = None,
    mandate: Mapping[str, Any] | None = None,
) -> dict:
    return {
        "action": {
            "tool": tool,
            "operation": operation,
            "arguments": dict(arguments),
        },
        "attribution": {
            "influence": _decimals(influence),
            "necessity": _decimals(necessity),
            "per_argument": {k: _decimals(v) for k, v in per_argument.items()},
            "argument_status": dict(argument_status or {}),
            "per_argument_confidence": _decimals(per_argument_confidence or {}),
            "confidence": parse_score(confidence),
        },
        "delegation_chain": list(delegation_chain or []),
        "mandate": dict(mandate or {}),
    }


def evidence_from_warrant(warrant: ActionWarrant, arguments: Mapping[str, Any]) -> dict:
    """Build policy evidence from a signed warrant plus the arguments really received."""
    subject = warrant.credentialSubject
    attribution = subject.attribution
    return evidence_from_parts(
        tool=subject.action.tool,
        operation=subject.action.operation,
        arguments=arguments,
        influence=attribution.influence,
        necessity=attribution.necessity,
        per_argument=attribution.per_argument,
        confidence=attribution.confidence,
        argument_status=attribution.argument_status,
        per_argument_confidence=attribution.per_argument_confidence,
        delegation_chain=[hop.model_dump() for hop in subject.delegation_chain],
        mandate=subject.mandate.model_dump(),
    )


def _decimals(values: Mapping[str, Decimal | str]) -> dict[str, Decimal]:
    if all(isinstance(v, Decimal) for v in values.values()):
        return dict(values)  # type: ignore[arg-type]
    return parse_distribution({k: str(v) for k, v in values.items()})
