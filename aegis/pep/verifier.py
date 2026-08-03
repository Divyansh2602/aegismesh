"""aegis-pep — the policy enforcement point (docs/SPEC.md section 7).

This runs at the relying party, in a different trust domain from the issuer, and it is
where the design either means something or does not. Two steps carry that weight.

**Step 7** verifies log inclusion against a root obtained *independently* -- here from a
witness, never from the operator. Skipping it, or checking inclusion against the root the
operator helpfully supplied alongside the receipt, reduces the whole apparatus to an
operator asserting its own good behaviour in cryptographic notation.

**Step 10** evaluates the relying party's *own* policy against the verified evidence. The
issuer's ``policy_decision`` is an input, not an answer. A PEP that honours the issuer's
verdict has learned nothing from the warrant that a plain HTTP 200 would not have told it,
and has quietly restored exactly the trust in the operator the architecture removes.

Every step reports pass or fail and the outcome is the conjunction. Steps are not
short-circuited on failure, because an auditor reading a denial wants to know everything
that was wrong with it, not just the first thing. The one exception is step 10: policy is
not evaluated against a warrant that failed authentication, because reporting a policy
result over unverified evidence invites someone to read it as a verdict.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from typing import Any

from pydantic import BaseModel, Field

from aegis.common.hashing import hash_object
from aegis.log.log import Receipt, verify_receipt
from aegis.log.witness import Witness
from aegis.pep.replay import ReplayCache
from aegis.policy.engine import Policy, PolicyResult
from aegis.policy.evidence import evidence_from_warrant
from aegis.warrant.issuer import verify_signature
from aegis.warrant.keys import KeyRing, UnknownKeyError
from aegis.warrant.models import (
    WARRANT_CONTEXT,
    WARRANT_TYPE,
    ActionWarrant,
    parse_iso,
)

STEP_NAMES = {
    1: "parse credential",
    2: "resolve issuer key",
    3: "verify signature",
    4: "check validity window",
    5: "bind to this action",
    6: "check nonce freshness",
    7: "verify log inclusion against an independent root",
    8: "verify delegation chain",
    9: "check mandate",
    10: "evaluate local policy",
    11: "emit decision record",
}


class StepResult(BaseModel):
    step: int
    name: str
    passed: bool
    detail: str = ""


class VerificationOutcome(BaseModel):
    decision: str
    steps: list[StepResult] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)
    issuer_decision: str | None = None
    """Recorded for comparison, never for authority. When this disagrees with ``decision``
    it is the most interesting line in the record."""

    policy_result: PolicyResult | None = None

    @property
    def admitted(self) -> bool:
        return self.decision == "permit"

    @property
    def failed_steps(self) -> list[StepResult]:
        return [s for s in self.steps if not s.passed]


class PolicyEnforcementPoint:
    """Verifies warrants on behalf of one relying party.

    ``known_manifests`` has no default of "accept anything". A PEP that cannot say which
    agent builds it recognizes cannot meaningfully check step 8, and treating an empty
    registry as permissive would turn control C-6 off in exactly the deployments least
    likely to notice.
    """

    def __init__(
        self,
        keyring: KeyRing,
        policy: Policy,
        witness: Witness,
        known_manifests: Iterable[str] | None = None,
        replay_cache: ReplayCache | None = None,
        decision_sink: Callable[[dict], Any] | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.keyring = keyring
        self.policy = policy
        self.witness = witness
        self.known_manifests = set(known_manifests) if known_manifests is not None else None
        self.replay_cache = replay_cache or ReplayCache()
        self.decision_sink = decision_sink
        self.clock = clock or (lambda: datetime.now(UTC))

    def verify(
        self,
        document: Mapping[str, Any],
        receipt: Receipt,
        arguments: Mapping[str, Any],
        expected_principal: str | None = None,
    ) -> VerificationOutcome:
        """Run the eleven-step algorithm over a warrant and the action it claims to admit.

        ``arguments`` are the ones the relying party actually received on the wire, not the
        ones the warrant describes. That asymmetry is the point of step 5.
        """
        steps: list[StepResult] = []
        document = dict(document)

        warrant, step1 = self._step1_parse(document)
        steps.append(step1)

        key, step2 = self._step2_resolve(warrant)
        steps.append(step2)

        steps.append(self._step3_signature(document, key, authentic=step1.passed))
        authentic = steps[-1].passed

        steps.append(self._step4_validity(warrant))
        steps.append(self._step5_bind(warrant, arguments))
        steps.append(self._step6_nonce(warrant))
        steps.append(self._step7_inclusion(document, receipt))
        steps.append(self._step8_chain(warrant))
        steps.append(self._step9_mandate(warrant, arguments, expected_principal))

        policy_result, step10 = self._step10_policy(warrant, arguments, authentic)
        steps.append(step10)

        decision = "permit" if all(s.passed for s in steps) else "deny"
        outcome = VerificationOutcome(
            decision=decision,
            steps=steps,
            reasons=[f"step {s.step} ({s.name}): {s.detail}" for s in steps if not s.passed],
            issuer_decision=(
                warrant.credentialSubject.policy_decision.decision if warrant else None
            ),
            policy_result=policy_result,
        )
        outcome.steps.append(self._step11_emit(warrant, outcome))
        return outcome

    # ------------------------------------------------------------------ steps

    def _step1_parse(self, document: dict) -> tuple[ActionWarrant | None, StepResult]:
        try:
            warrant = ActionWarrant.from_document(document)
        except Exception as exc:  # noqa: BLE001 - any parse failure is a rejection
            return None, _fail(1, f"not a well-formed credential: {type(exc).__name__}")

        if list(warrant.context[:2]) != WARRANT_CONTEXT:
            return None, _fail(1, f"unrecognized @context: {warrant.context}")
        if set(WARRANT_TYPE) - set(warrant.type):
            return None, _fail(1, f"unrecognized type: {warrant.type}")
        return warrant, _ok(1, "ActionWarrant v1")

    def _step2_resolve(self, warrant: ActionWarrant | None):
        if warrant is None or warrant.proof is None:
            return None, _fail(2, "no proof to resolve a key for")
        method = warrant.proof.verificationMethod
        try:
            return self.keyring.resolve(method), _ok(2, method)
        except UnknownKeyError as exc:
            return None, _fail(2, str(exc))

    def _step3_signature(self, document: dict, key, authentic: bool) -> StepResult:
        if key is None:
            return _fail(3, "not evaluated: no verification key")
        if not authentic:
            return _fail(3, "not evaluated: credential did not parse")
        if verify_signature(document, key):
            return _ok(3, "eddsa-jcs-2022 signature valid")
        return _fail(3, "signature does not verify over the canonicalized credential")

    def _step4_validity(self, warrant: ActionWarrant | None) -> StepResult:
        if warrant is None:
            return _fail(4, "not evaluated: credential did not parse")
        now = self.clock()
        try:
            valid = warrant.is_valid_at(now)
        except ValueError as exc:
            return _fail(4, f"unparseable validity window: {exc}")
        if valid:
            return _ok(4, f"valid {warrant.validFrom} .. {warrant.validUntil}")
        return _fail(4, f"outside {warrant.validFrom} .. {warrant.validUntil} at {now:%H:%M:%SZ}")

    def _step5_bind(
        self, warrant: ActionWarrant | None, arguments: Mapping[str, Any]
    ) -> StepResult:
        """Recompute the arguments hash from what actually arrived.

        This is what stops a valid warrant being lifted onto a different action -- the
        replay in control C-14 that matters, because it needs no forgery at all, only a
        warrant the operator was legitimately given for something cheaper.
        """
        if warrant is None:
            return _fail(5, "not evaluated: credential did not parse")
        action = warrant.credentialSubject.action
        recomputed = hash_object(dict(arguments))
        if recomputed != action.arguments_hash:
            return _fail(
                5,
                f"arguments do not match the warrant "
                f"(warrant {action.arguments_hash[:23]}..., received {recomputed[:23]}...)",
            )

        for field, digest in action.arguments_digest_map.items():
            if field not in arguments:
                return _fail(5, f"warrant covers field {field!r}, which was not supplied")
            if hash_object(arguments[field]) != digest:
                return _fail(5, f"field {field!r} does not match its digest")
        return _ok(5, f"bound to {len(action.arguments_digest_map)} field digest(s)")

    def _step6_nonce(self, warrant: ActionWarrant | None) -> StepResult:
        if warrant is None:
            return _fail(6, "not evaluated: credential did not parse")
        nonce = warrant.credentialSubject.action.nonce
        if self.replay_cache.check_and_record(nonce, self.clock()):
            return _ok(6, f"nonce {nonce} not seen before")
        return _fail(6, f"nonce {nonce} already used -- replay")

    def _step7_inclusion(self, document: dict, receipt: Receipt) -> StepResult:
        """The ADV-4 defense. Non-optional, and the root does not come from the operator."""
        root = self.witness.current_root()
        if root is None:
            return _fail(7, "witness has no accepted root (never observed, or fork detected)")
        if receipt.tree_size > self.witness.tree_size:
            return _fail(
                7,
                f"receipt claims tree size {receipt.tree_size}, witness has accepted only "
                f"{self.witness.tree_size}",
            )
        if not verify_receipt(document, receipt, root):
            return _fail(7, "inclusion proof does not reach the witnessed root")
        return _ok(7, f"included at leaf {receipt.leaf_index} under the witnessed root")

    def _step8_chain(self, warrant: ActionWarrant | None) -> StepResult:
        if warrant is None:
            return _fail(8, "not evaluated: credential did not parse")
        subject = warrant.credentialSubject
        chain = subject.delegation_chain
        if not chain:
            return _fail(8, "empty delegation chain")
        if chain[0].kind != "human":
            return _fail(8, "chain does not originate with a human principal")
        if chain[0].actor != subject.mandate.principal:
            return _fail(
                8,
                f"chain starts at {chain[0].actor}, mandate names {subject.mandate.principal}",
            )

        for previous, current in zip(chain, chain[1:], strict=False):
            if current.hop != previous.hop + 1:
                return _fail(8, f"hop numbering breaks at {current.hop}")
            uncovered = [s for s in current.scope if not _covered_by(previous.scope, s)]
            if uncovered:
                return _fail(
                    8,
                    f"hop {current.hop} claims {uncovered} beyond hop {previous.hop}'s scope "
                    f"-- delegation must attenuate, never widen",
                )

        if self.known_manifests is None:
            return _fail(8, "no agent manifest registry configured; cannot recognize any agent")
        for hop in chain:
            if hop.kind != "agent":
                continue
            if not hop.manifest_hash:
                return _fail(8, f"agent at hop {hop.hop} carries no manifest hash")
            if hop.manifest_hash not in self.known_manifests:
                return _fail(
                    8, f"unknown agent manifest at hop {hop.hop}: {hop.manifest_hash[:23]}..."
                )
        return _ok(8, f"{len(chain)} hop(s), each a subset of the last")

    def _step9_mandate(
        self,
        warrant: ActionWarrant | None,
        arguments: Mapping[str, Any],
        expected_principal: str | None,
    ) -> StepResult:
        if warrant is None:
            return _fail(9, "not evaluated: credential did not parse")
        subject = warrant.credentialSubject
        mandate = subject.mandate
        now = self.clock()

        try:
            if parse_iso(mandate.expires_at) < now:
                return _fail(9, f"mandate expired at {mandate.expires_at}")
        except ValueError as exc:
            return _fail(9, f"unparseable mandate expiry: {exc}")

        if expected_principal and mandate.principal != expected_principal:
            return _fail(9, f"principal {mandate.principal} is not {expected_principal}")

        action_class = f"{subject.action.tool}:{subject.action.operation}"
        if not _covered_by(mandate.scope.action_classes, action_class):
            return _fail(9, f"{action_class} is not in the mandate's scope")

        violated = _violated_constraints(mandate.scope.constraints, arguments)
        if violated:
            return _fail(9, f"mandate constraint(s) violated: {'; '.join(violated)}")
        return _ok(9, f"{action_class} within mandate {mandate.id}")

    def _step10_policy(
        self,
        warrant: ActionWarrant | None,
        arguments: Mapping[str, Any],
        authentic: bool,
    ) -> tuple[PolicyResult | None, StepResult]:
        if warrant is None or not authentic:
            return None, _fail(10, "not evaluated: warrant is not authentic")
        evidence = evidence_from_warrant(warrant, arguments)
        result = self.policy.evaluate(evidence)
        issuer = warrant.credentialSubject.policy_decision.decision
        detail = f"{self.policy.policy_id}@{self.policy.policy_version} -> {result.decision}"
        if result.decision != issuer:
            detail += f" (issuer claimed {issuer})"
        if result.permitted:
            return result, _ok(10, detail)
        return result, StepResult(
            step=10,
            name=STEP_NAMES[10],
            passed=False,
            detail=f"{detail}: {', '.join(result.reasons)}",
        )

    def _step11_emit(
        self, warrant: ActionWarrant | None, outcome: VerificationOutcome
    ) -> StepResult:
        """Log the relying party's own decision.

        Its own, in its own log. Recording the verdict back into the operator's log would
        let the operator drop the denials, and a decision record only the deciding party
        controls is the only kind worth keeping.
        """
        record = {
            "type": "PolicyDecisionRecord",
            "warrant_id": warrant.id if warrant else None,
            "policy_id": self.policy.policy_id,
            "policy_version": self.policy.policy_version,
            "policy_hash": self.policy.policy_hash(),
            "decision": outcome.decision,
            "failed_steps": [s.step for s in outcome.steps if not s.passed],
            "recorded_at": self.clock().strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        if self.decision_sink is None:
            return _fail(11, "no decision sink configured; the decision was not recorded")
        self.decision_sink(record)
        return _ok(11, f"decision recorded for {record['warrant_id']}")


# ---------------------------------------------------------------------- helpers


def _ok(step: int, detail: str) -> StepResult:
    return StepResult(step=step, name=STEP_NAMES[step], passed=True, detail=detail)


def _fail(step: int, detail: str) -> StepResult:
    return StepResult(step=step, name=STEP_NAMES[step], passed=False, detail=detail)


def _covered_by(patterns: Iterable[str], scope: str) -> bool:
    """Whether any pattern admits ``scope``. Only a trailing ``*`` wildcards.

    Restricted to a suffix wildcard deliberately. General glob matching in an
    authorization scope is a reliable source of surprises -- ``treasury.*:read`` looks
    narrow and is not -- and delegation only ever needs to say "this family of actions".
    """
    for pattern in patterns:
        if pattern == scope or pattern == "*":
            return True
        if pattern.endswith("*") and scope.startswith(pattern[:-1]):
            return True
    return False


def _violated_constraints(
    constraints: Mapping[str, Any], arguments: Mapping[str, Any]
) -> list[str]:
    """Check mandate value bounds against the arguments actually received (control C-8).

    A constraint naming a field that was not supplied is a violation, not a pass. The
    alternative -- ignoring bounds whose field is absent -- means an agent can escape every
    value limit by omitting the field it is limited on.
    """
    violations: list[str] = []
    for key, bound in constraints.items():
        if key.endswith("_max") or key.endswith("_min"):
            field = key[:-4]
            if field not in arguments:
                violations.append(f"{key} names absent field {field!r}")
                continue
            try:
                value = Decimal(str(arguments[field]))
                limit = Decimal(str(bound))
            except (InvalidOperation, TypeError, ValueError):
                violations.append(f"{key} is not comparable to {arguments[field]!r}")
                continue
            if key.endswith("_max") and value > limit:
                violations.append(f"{field}={value} exceeds {key}={limit}")
            elif key.endswith("_min") and value < limit:
                violations.append(f"{field}={value} below {key}={limit}")
            continue

        if key not in arguments:
            violations.append(f"constraint {key!r} names an absent field")
        elif isinstance(bound, list):
            if arguments[key] not in bound:
                violations.append(f"{key}={arguments[key]!r} not in {bound}")
        elif arguments[key] != bound:
            violations.append(f"{key}={arguments[key]!r} != {bound!r}")
    return violations
