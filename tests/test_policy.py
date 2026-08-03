"""Policy evaluation semantics.

The rules here are data, and these tests are mostly about the edge cases where a policy
engine quietly does the wrong thing: a path that does not resolve, a comparison that goes
through float, a guard that should have short-circuited but did not.
"""

from decimal import Decimal

import pytest

from aegis.policy.engine import ENGINE_VERSION, Condition, Policy, Rule
from aegis.policy.evidence import evidence_from_parts
from aegis.policy.library import acme_treasury_policy, permissive_operator_policy


def evidence(**overrides) -> dict:
    base = dict(
        tool="treasury.payments",
        operation="execute_transfer",
        arguments={"amount": 2000000.0, "currency": "USD", "destination_account": "GB29"},
        influence={"P0": "1.0000"},
        necessity={"P0": "1.0000"},
        per_argument={"destination_account": {}},
        confidence="1.0000",
        argument_status={"destination_account": "invariant"},
        per_argument_confidence={"destination_account": "0.0000"},
        delegation_chain=[{"hop": 0}, {"hop": 1}, {"hop": 2}],
        mandate={"id": "mnd_1"},
    )
    base.update(overrides)
    return evidence_from_parts(**base)


class TestTreasuryPolicy:
    def test_an_overdetermined_destination_is_permitted(self):
        """The regression this policy version exists for.

        The previous rule demanded ``P0 >= 0.70`` on the destination unconditionally. A
        destination named by both the human and the operator's own ledger is invariant
        under leave-one-out, so P0 is zero -- and the legitimate payment was denied.
        """
        assert acme_treasury_policy().evaluate(evidence()).decision == "permit"

    def test_untrusted_influence_on_the_destination_denies(self):
        result = acme_treasury_policy().evaluate(
            evidence(
                per_argument={"destination_account": {"P3": "1.0000"}},
                argument_status={"destination_account": "attributed"},
            )
        )
        assert result.decision == "deny"
        assert "no_untrusted_influence_on_destination" in result.rules_fired

    def test_an_unmeasurable_destination_fails_closed(self):
        """Control C-16: defeating the measurement yields a denial, not a bypass."""
        result = acme_treasury_policy().evaluate(
            evidence(argument_status={"destination_account": "unknown"})
        )
        assert "destination_not_attributable" in result.rules_fired

    def test_human_intent_rule_only_applies_to_an_attributed_destination(self):
        attributed_elsewhere = acme_treasury_policy().evaluate(
            evidence(
                per_argument={"destination_account": {"P2": "1.0000"}},
                argument_status={"destination_account": "attributed"},
            )
        )
        assert "require_human_intent_on_destination" in attributed_elsewhere.rules_fired
        assert "require_human_intent_on_destination" not in (
            acme_treasury_policy().evaluate(evidence()).rules_fired
        )

    def test_high_value_guard_short_circuits_on_small_transfers(self):
        result = acme_treasury_policy().evaluate(
            evidence(
                arguments={"amount": 500, "currency": "USD", "destination_account": "GB29"},
                per_argument={"destination_account": {"P2": "1.0000"}},
                argument_status={"destination_account": "attributed"},
            )
        )
        assert "require_human_intent_on_destination" not in result.rules_fired

    def test_deep_chain_denies(self):
        result = acme_treasury_policy().evaluate(
            evidence(delegation_chain=[{"hop": i} for i in range(5)])
        )
        assert "chain_too_deep" in result.rules_fired

    def test_low_confidence_denies(self):
        result = acme_treasury_policy().evaluate(evidence(confidence="0.4000"))
        assert "attribution_confidence_too_low" in result.rules_fired


class TestEvaluationSemantics:
    def test_missing_influence_paths_default_to_zero(self):
        """An influence distribution omits classes below the noise floor, so an absent
        class is the encoding of "caused nothing" rather than "unknown"."""
        rule = Rule(
            id="r",
            conditions=[
                Condition(path="attribution.per_argument.nowhere.P3", op="gt", value="0.0000")
            ],
        )
        assert not rule.evaluate(evidence())

    def test_an_unresolvable_path_makes_a_rule_fire(self):
        """A rule that applies but cannot be evaluated denies. Skipping it would let a
        malformed input turn a control off silently."""
        rule = Rule(
            id="r", conditions=[Condition(path="action.arguments.missing", op="gt", value="1")]
        )
        assert rule.evaluate(evidence())

    def test_argument_status_does_not_get_a_zero_default(self):
        """It is not one of the numeric maps. Defaulting a missing status to zero would
        make a guard on it silently fail to match."""
        rule = Rule(
            id="r",
            conditions=[
                Condition(
                    path="attribution.argument_status.absent_field", op="eq", value="attributed"
                )
            ],
        )
        assert rule.evaluate(evidence())

    def test_conditions_short_circuit_in_order(self):
        """Guards first. A later condition that cannot resolve must not deny an action the
        guard already excluded."""
        rule = Rule(
            id="r",
            conditions=[
                Condition(path="action.operation", op="eq", value="read_balance"),
                Condition(path="action.arguments.nonexistent", op="gt", value="1"),
            ],
        )
        assert not rule.evaluate(evidence())

    def test_numeric_comparison_does_not_round_trip_through_float(self):
        """Comparing at the enforcement point via float would undo the point of encoding
        scores as fixed-precision strings, one layer below where anyone looks."""
        built = evidence(per_argument={"destination_account": {"P3": "0.0500"}})
        value = built["attribution"]["per_argument"]["destination_account"]["P3"]
        assert isinstance(value, Decimal)
        rule = Rule(
            id="r",
            conditions=[
                Condition(
                    path="attribution.per_argument.destination_account.P3",
                    op="gt",
                    value="0.0500",
                )
            ],
        )
        assert not rule.evaluate(built), "0.0500 is not greater than 0.0500"

    def test_a_numeric_rule_against_a_non_numeric_value_denies(self):
        rule = Rule(
            id="r", conditions=[Condition(path="action.arguments.currency", op="gt", value="1")]
        )
        assert rule.evaluate(evidence())

    def test_list_length_is_addressable(self):
        rule = Rule(
            id="r", conditions=[Condition(path="delegation_chain.length", op="eq", value="3")]
        )
        assert rule.evaluate(evidence())

    @pytest.mark.parametrize(
        ("op", "value", "expected"),
        [("lt", "2.0", True), ("le", "1.0", True), ("gt", "0.5", True), ("ge", "1.5", False)],
    )
    def test_operators(self, op, value, expected):
        rule = Rule(
            id="r", conditions=[Condition(path="attribution.confidence", op=op, value=value)]
        )
        assert rule.evaluate(evidence()) is expected


class TestPolicyHash:
    def test_hash_covers_thresholds(self):
        """A warrant records the policy hash so a decision can be replayed against the
        exact policy that produced it. That only holds if the hash covers the rules."""
        original = acme_treasury_policy()
        loosened = acme_treasury_policy()
        loosened.rules[0].conditions[0].value = "0.9000"
        assert original.policy_hash() != loosened.policy_hash()

    def test_hash_covers_rule_order_and_membership(self):
        original = acme_treasury_policy()
        shortened = acme_treasury_policy()
        shortened.rules.pop()
        assert original.policy_hash() != shortened.policy_hash()

    def test_hash_covers_the_engine_version(self, monkeypatch):
        """A policy hash names the rules, not the code that runs them.

        Replay against a different engine could therefore produce a different decision from
        an identical-looking policy. Folding the engine version into the hashed material
        does not fix that, but it makes the mismatch visible instead of silent.
        """
        from aegis.policy import engine

        before = acme_treasury_policy().policy_hash()
        monkeypatch.setattr(engine, "ENGINE_VERSION", ENGINE_VERSION + "-next")
        assert acme_treasury_policy().policy_hash() != before


class TestDefaults:
    def test_a_rule_free_deny_by_default_policy_denies(self):
        result = Policy(policy_id="empty", policy_version="1").evaluate(evidence())
        assert result.decision == "deny"
        assert "no rules" in result.reasons[0]

    def test_the_permissive_policy_permits(self):
        assert permissive_operator_policy().evaluate(evidence()).decision == "permit"
