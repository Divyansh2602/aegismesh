"""Declarative policy evaluation over warrant evidence (docs/SPEC.md section 6).

This package is shared by the issuer and the policy enforcement point, and that needs
saying plainly because it looks like a trust-boundary violation and is not: they share an
*evaluator*, never a *policy*. The operator's issuer runs its rules; the relying party runs
its own, in its own trust domain, and may reach the opposite conclusion. That divergence is
the design working, not a bug -- SPEC.md section 7 step 10.

**Rules are data, not code.** The obvious implementation makes each rule a Python callable,
which is shorter and reads better. It also makes ``policy_hash`` a lie: the hash would
cover a rule's name and thresholds while the behaviour lived in a function body nobody
committed to. A warrant records the policy hash so that any decision can be replayed
against the exact policy that produced it, and that guarantee only holds if the hash covers
the whole policy. So conditions are declared as path/operator/value triples and the hash
covers all of them.

What the hash still does not cover is *this file* -- the evaluator itself. A policy hash
identifies the rules, not the engine that ran them. Replay therefore requires an agreed
engine version, which is why ``engine_version`` is part of the hashed material.
"""

from __future__ import annotations

from decimal import Decimal, InvalidOperation
from typing import Any, Literal

from pydantic import BaseModel, Field

from aegis.common.hashing import hash_object

#: Bumped whenever evaluation semantics change in a way that could alter a decision.
#: Part of the hashed policy material, so a replay against a different engine is visible
#: rather than silently producing a different answer.
ENGINE_VERSION = "0.1.0"

Operator = Literal["lt", "le", "gt", "ge", "eq", "ne"]

_NUMERIC_OPS = {"lt", "le", "gt", "ge"}

#: Paths under these prefixes treat a missing value as a measured zero. That is not
#: convenience: an influence distribution omits classes whose measured influence fell below
#: the noise floor, so "P2 is absent" is the encoding of "P2 caused nothing".
#:
#: Scoped to the numeric maps only. ``attribution.argument_status`` is deliberately *not*
#: included -- a missing status is a genuine unknown, and defaulting it to zero would make
#: a rule that guards on it silently not fire.
_ZERO_DEFAULT_PREFIXES = (
    "attribution.influence.",
    "attribution.necessity.",
    "attribution.per_argument.",
    "attribution.per_argument_confidence.",
)


class Undetermined:
    """A path that resolved to nothing and has no defined default."""

    __slots__ = ()

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "<undetermined>"


UNDETERMINED = Undetermined()


class Condition(BaseModel):
    """One comparison against the evidence.

    ``path`` is a dotted lookup into the policy input, e.g.
    ``attribution.per_argument.destination_account.P3``.
    """

    path: str
    op: Operator
    value: str

    def describe(self) -> str:
        return f"{self.path} {self.op} {self.value}"


class Rule(BaseModel):
    """A deny rule. All conditions must hold, evaluated in order with short-circuit.

    Order matters and is part of the policy's meaning: put guards first. A rule whose guard
    does not match never reaches its later conditions, so an unresolvable value in a rule
    that does not apply cannot deny an unrelated action.
    """

    id: str
    description: str = ""
    conditions: list[Condition] = Field(default_factory=list)

    def evaluate(self, evidence: dict) -> bool:
        for condition in self.conditions:
            outcome = _compare(evidence, condition)
            if outcome is UNDETERMINED:
                # A rule that applies but cannot be evaluated denies. Control C-16: an
                # action we cannot reason about fails closed, so defeating the evidence
                # yields a refusal rather than a bypass.
                return True
            if outcome is False:
                return False
        return True

    def hashable(self) -> dict:
        return {
            "id": self.id,
            "conditions": [c.model_dump() for c in self.conditions],
        }


class PolicyResult(BaseModel):
    decision: Literal["permit", "deny", "permit_with_obligations"]
    rules_fired: list[str] = Field(default_factory=list)
    obligations: list[str] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)

    @property
    def permitted(self) -> bool:
        return self.decision != "deny"


class Policy(BaseModel):
    """A versioned, hashed rule set.

    ``default_decision`` is ``deny`` because SPEC.md section 6 opens with
    ``default decision := "deny"``, and because a policy engine that permits when its rules
    fail to load is worse than no policy engine.
    """

    policy_id: str
    policy_version: str
    rules: list[Rule] = Field(default_factory=list)
    default_decision: Literal["permit", "deny"] = "deny"

    def policy_hash(self) -> str:
        return hash_object(
            {
                "engine_version": ENGINE_VERSION,
                "policy_id": self.policy_id,
                "policy_version": self.policy_version,
                "default_decision": self.default_decision,
                "rules": [rule.hashable() for rule in self.rules],
            }
        )

    def evaluate(self, evidence: dict) -> PolicyResult:
        fired = [rule for rule in self.rules if rule.evaluate(evidence)]
        if fired:
            return PolicyResult(
                decision="deny",
                rules_fired=[rule.id for rule in fired],
                reasons=[rule.description or rule.id for rule in fired],
            )
        if self.default_decision == "deny" and not self.rules:
            # An empty deny-by-default policy denies everything. Surfacing that as an
            # explicit reason stops it being mistaken for a rule that fired.
            return PolicyResult(decision="deny", reasons=["policy has no rules; default is deny"])
        return PolicyResult(decision="permit")


def _resolve(evidence: dict, path: str) -> Any:
    current: Any = evidence
    for part in path.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
            continue
        if isinstance(current, list) and part == "length":
            return len(current)
        if path.startswith(_ZERO_DEFAULT_PREFIXES):
            return Decimal(0)
        return UNDETERMINED
    return current


def _compare(evidence: dict, condition: Condition) -> bool | Undetermined:
    actual = _resolve(evidence, condition.path)
    if actual is UNDETERMINED:
        return UNDETERMINED

    if condition.op in _NUMERIC_OPS:
        try:
            left = _to_decimal(actual)
            right = Decimal(condition.value)
        except (InvalidOperation, TypeError, ValueError):
            # A numeric rule pointed at something non-numeric is a policy authoring error.
            # It denies rather than being skipped, so the mistake is loud.
            return UNDETERMINED
        return {
            "lt": left < right,
            "le": left <= right,
            "gt": left > right,
            "ge": left >= right,
        }[condition.op]

    equal = str(actual) == condition.value
    return equal if condition.op == "eq" else not equal


def _to_decimal(value: Any) -> Decimal:
    """Coerce to Decimal via ``str``, never via ``float``.

    Going through float would undo the point of encoding scores as fixed-precision strings
    in the first place -- the rounding error would reappear at the comparison, one layer
    below where anyone thinks to look for it.
    """
    if isinstance(value, Decimal):
        return value
    if isinstance(value, bool):
        raise TypeError("refusing to compare a boolean numerically")
    return Decimal(str(value))
