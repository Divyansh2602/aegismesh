"""Concrete policies. The treasury policy is docs/SPEC.md section 6, corrected.

Two policies are defined because the architecture needs two: an operator-side policy the
issuer applies, and a relying-party policy the PEP applies. They are deliberately not the
same policy, and ``permissive_operator_policy`` exists so the difference can be exercised
in a test -- an issuer that says ``permit`` must not be able to talk the payment API into
honouring an action its own rules refuse.

**Why "corrected".** SPEC.md section 6 wrote the human-intent rule as an unconditional
threshold::

    deny if per_argument.destination_account.P0 < 0.70

Enforcing that denied the *legitimate* invoice payment. In the clean case the destination
account appears in both the human's mandate and Acme's own ledger, so removing either one
leaves the other and leave-one-out ablation measures no pivotal cause at all -- P0 is not
0.70, it is zero, because nothing was pivotal. The rule as written demands positive human
causation for a value that is legitimately overdetermined, which no correctly attributed
redundant field can ever satisfy.

The rule now guards on ``argument_status``: it applies when the field *was* attributed to
some class and that class was not the human. A field no class was pivotal for is handled by
the rules about untrusted influence and unattributability instead. The threat model calls
agent utility asset A6 for this reason -- a control that blocks legitimate work gets turned
off, and then protects nothing.
"""

from __future__ import annotations

from aegis.policy.engine import Condition, Policy, Rule

#: Below this, an action is treated as unattributable and denied (control C-16).
MIN_CONFIDENCE = "0.6000"

#: Any measurable untrusted influence on where money goes is too much. 0.05 rather than 0
#: because ablation is a measurement and measurements have a floor, not because a little
#: attacker control over the destination account is acceptable.
MAX_UNTRUSTED_ON_DESTINATION = "0.0500"

#: Above this value a transfer must not be attributed to anyone but the human.
HIGH_VALUE_THRESHOLD = "10000"

MIN_HUMAN_ON_DESTINATION = "0.7000"

MAX_CHAIN_DEPTH = "3"

DESTINATION = "attribution.per_argument.destination_account"
DESTINATION_STATUS = "attribution.argument_status.destination_account"


def _no_untrusted_influence() -> Rule:
    return Rule(
        id="no_untrusted_influence_on_destination",
        description="untrusted external content must not influence the destination account",
        conditions=[
            Condition(path=f"{DESTINATION}.P3", op="gt", value=MAX_UNTRUSTED_ON_DESTINATION),
        ],
    )


def _destination_unattributable() -> Rule:
    """Fail closed when nothing at all could be measured about the destination.

    ``unknown`` means every ablation cancelled the action, so no counterfactual existed to
    compare against. That is control C-16: an attacker who defeats the measurement gets a
    denial rather than a bypass. It is deliberately *not* triggered by ``invariant``, which
    is a measurement, not the absence of one.
    """
    return Rule(
        id="destination_not_attributable",
        description="nothing could be measured about what set the destination account",
        conditions=[
            Condition(path="action.operation", op="eq", value="execute_transfer"),
            Condition(path=DESTINATION_STATUS, op="eq", value="unknown"),
        ],
    )


def _confidence_floor() -> Rule:
    return Rule(
        id="attribution_confidence_too_low",
        description="action-level attribution confidence below the policy floor",
        conditions=[
            Condition(path="attribution.confidence", op="lt", value=MIN_CONFIDENCE),
        ],
    )


def acme_treasury_policy() -> Policy:
    """The relying party's policy: a payment API that does not trust the agent's operator."""
    return Policy(
        policy_id="acme.treasury",
        policy_version="4.3.0",
        rules=[
            _no_untrusted_influence(),
            _destination_unattributable(),
            Rule(
                id="require_human_intent_on_destination",
                description=(
                    "a high-value destination that was attributed to something other than "
                    "the human principal"
                ),
                conditions=[
                    # Guards first: conditions short-circuit, so a rule that does not apply
                    # never reaches the value lookups below it.
                    Condition(path="action.operation", op="eq", value="execute_transfer"),
                    Condition(
                        path="action.arguments.amount", op="gt", value=HIGH_VALUE_THRESHOLD
                    ),
                    # Only meaningful once some class was measurably pivotal. Without this
                    # guard the rule denies every legitimate transfer whose destination is
                    # corroborated by more than one trusted source.
                    Condition(path=DESTINATION_STATUS, op="eq", value="attributed"),
                    Condition(path=f"{DESTINATION}.P0", op="lt", value=MIN_HUMAN_ON_DESTINATION),
                ],
            ),
            _confidence_floor(),
            Rule(
                id="chain_too_deep",
                description="delegation chain exceeds the permitted depth (control C-17)",
                conditions=[
                    Condition(path="delegation_chain.length", op="gt", value=MAX_CHAIN_DEPTH),
                ],
            ),
        ],
    )


def operator_issuer_policy() -> Policy:
    """The operator's own policy, applied by the issuer before it signs.

    Narrower than the relying party's on purpose. The issuer knows what it measured but not
    what the payment API's risk appetite is, so it enforces the rules that hold regardless
    of the counterparty and leaves value thresholds to whoever holds the money.
    """
    return Policy(
        policy_id="aegis.operator.default",
        policy_version="1.1.0",
        rules=[_no_untrusted_influence(), _destination_unattributable(), _confidence_floor()],
    )


def permissive_operator_policy() -> Policy:
    """An issuer policy that permits everything.

    Not a strawman -- it is the shape of a misconfigured deployment, and of a dishonest
    operator's deployment (ADV-4). It exists so the test suite can assert the property the
    whole architecture rests on: the relying party denies anyway, because it evaluates its
    own policy against evidence it verified rather than trusting the issuer's verdict.
    """
    return Policy(
        policy_id="operator.permissive",
        policy_version="0.0.1",
        rules=[],
        default_decision="permit",
    )
