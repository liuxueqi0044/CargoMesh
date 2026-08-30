from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from cargomesh.ir.enums import RiskClass, VerificationLevel
from cargomesh.policy import (
    DataClassification,
    EmbeddedPolicyEvaluator,
    EmbeddedPolicyProvider,
    ExecutionChannel,
    PolicyEffect,
    PolicyInput,
    PolicyRule,
    PolicySet,
    StaticPolicyProvider,
)

NOW = datetime(2040, 1, 2, 3, 4, 5, tzinfo=UTC)


def policy_input(**overrides: object) -> PolicyInput:
    values: dict[str, object] = {
        "tenant_id": "tenant-a",
        "environment_id": "production",
        "principal_ref": "principal-a",
        "capability": "shipment.track.read",
        "risk_class": RiskClass.READ_ONLY,
        "data_classification": DataClassification.INTERNAL,
        "requested_verification_level": VerificationLevel.L1,
        "route": "shipment.track",
        "channel": ExecutionChannel.API,
        "adapter": "synthetic.api.track",
        "evaluated_at": NOW,
    }
    values.update(overrides)
    return PolicyInput.issue(**values)


def rule(
    rule_id: str,
    priority: int,
    effect: PolicyEffect,
    **overrides: object,
) -> PolicyRule:
    values: dict[str, object] = {
        "rule_id": rule_id,
        "priority": priority,
        "effect": effect,
        "reason_code": "policy.rule",
    }
    if effect is PolicyEffect.REQUIRE_APPROVAL:
        values["approval_requirement"] = "human.approver"
    values.update(overrides)
    return PolicyRule.issue(**values)


def policy(*rules: PolicyRule) -> PolicySet:
    return PolicySet.issue(policy_id="tenant-policy", version="1.2.3", rules=rules)


@pytest.mark.parametrize(
    "effect", [PolicyEffect.ALLOW, PolicyEffect.DENY, PolicyEffect.REQUIRE_APPROVAL]
)
def test_first_matching_effect_is_frozen_and_digest_bound(effect: PolicyEffect) -> None:
    match = rule("match", 10, effect)
    decision = EmbeddedPolicyEvaluator().evaluate(policy(match), policy_input())

    assert decision.effect is effect
    assert decision.result is effect
    assert decision.matched_rule_id == "match"
    assert decision.matched_rule_digest == match.rule_digest
    assert decision.approval_requirement == (
        "human.approver" if effect is PolicyEffect.REQUIRE_APPROVAL else None
    )
    assert decision.decision_digest.startswith("sha256:")


def test_priority_then_rule_id_is_a_stable_first_match_tie_break() -> None:
    lower_priority = rule("later", 20, PolicyEffect.DENY, reason_code="later.rule")
    first_tie = rule("a-first", 10, PolicyEffect.ALLOW, reason_code="first.rule")
    second_tie = rule("z-second", 10, PolicyEffect.DENY, reason_code="second.rule")
    # Input order deliberately differs from evaluation order.
    decision = EmbeddedPolicyEvaluator().evaluate(
        policy(lower_priority, second_tie, first_tie), policy_input()
    )

    assert decision.effect is PolicyEffect.ALLOW
    assert decision.matched_rule_id == "a-first"
    assert decision.reason_code == "first.rule"


def test_selector_predicates_and_no_match_default_deny_are_deterministic() -> None:
    selected = rule(
        "selected",
        1,
        PolicyEffect.ALLOW,
        tenant_ids=("tenant-b",),
        channels=(ExecutionChannel.BROWSER,),
    )
    policies = policy(selected)
    no_match = EmbeddedPolicyEvaluator().evaluate(policies, policy_input())
    matching = EmbeddedPolicyEvaluator().evaluate(
        policies,
        policy_input(tenant_id="tenant-b", channel=ExecutionChannel.BROWSER),
    )

    assert no_match.effect is PolicyEffect.DENY
    assert no_match.matched_rule_id is None
    assert no_match.reason_code == "policy_no_matching_rule"
    assert matching.effect is PolicyEffect.ALLOW
    assert matching.matched_rule_id == "selected"
    assert no_match.decision_digest != matching.decision_digest


def test_policy_models_reject_tampering_and_invalid_approval_shapes() -> None:
    item = policy_input()
    with pytest.raises(ValidationError, match="input digest does not match"):
        PolicyInput.model_validate({**item.model_dump(), "tenant_id": "other"})

    with pytest.raises(ValidationError, match="approval effect requires"):
        PolicyRule.issue(
            rule_id="approval",
            priority=1,
            effect=PolicyEffect.REQUIRE_APPROVAL,
            reason_code="approval.required",
        )
    with pytest.raises(ValidationError, match="must be unique"):
        PolicyRule.issue(
            rule_id="duplicate",
            priority=1,
            effect=PolicyEffect.ALLOW,
            reason_code="allowed",
            tenant_ids=("tenant-a", "tenant-a"),
        )


def test_static_and_embedded_providers_are_equivalent_and_fail_closed() -> None:
    policy_set = policy(rule("allow", 1, PolicyEffect.ALLOW))
    request = policy_input()
    import asyncio

    assert asyncio.run(StaticPolicyProvider(policy_set).evaluate(request)) == asyncio.run(
        EmbeddedPolicyProvider(policy_set).evaluate(request)
    )

    class BrokenEvaluator(EmbeddedPolicyEvaluator):
        def evaluate(self, policy_set: PolicySet, policy_input: PolicyInput):
            del policy_set, policy_input
            raise RuntimeError("not exposed")

    denied = asyncio.run(
        EmbeddedPolicyProvider(policy_set, evaluator=BrokenEvaluator()).evaluate(request)
    )
    assert denied.effect is PolicyEffect.DENY
    assert denied.reason_code == "policy_provider_error"
