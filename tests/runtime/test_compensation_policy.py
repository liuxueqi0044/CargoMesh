from __future__ import annotations

import asyncio
from datetime import UTC, datetime

import pytest

from cargomesh.ir.enums import RiskClass, VerificationLevel
from cargomesh.policy import (
    PolicyDecision,
    PolicyEffect,
    PolicyInput,
    PolicyRule,
    PolicySet,
)
from cargomesh.runtime.models import CompensationSpec, ExecutionPlan, ExecutionStep
from cargomesh.runtime.policy import PolicyPlanningError, apply_execution_policy


class Provider:
    def __init__(self, effect: PolicyEffect) -> None:
        self.inputs: list[PolicyInput] = []
        self.rule = PolicyRule.issue(
            rule_id="test.rule",
            priority=1,
            effect=effect,
            approval_requirement=(
                "human.approver" if effect is PolicyEffect.REQUIRE_APPROVAL else None
            ),
            reason_code="test.result",
        )
        self.policy_set = PolicySet.issue(
            policy_id="test-policy", version="1.0.0", rules=(self.rule,)
        )

    async def evaluate(self, policy_input: PolicyInput) -> PolicyDecision:
        self.inputs.append(policy_input)
        return PolicyDecision.issue(
            input=policy_input,
            policy_id=self.policy_set.policy_id,
            policy_version=self.policy_set.version,
            policy_digest=self.policy_set.policy_digest,
            effect=self.rule.effect,
            matched_rule_id=self.rule.rule_id,
            matched_rule_digest=self.rule.rule_digest,
            approval_requirement=self.rule.approval_requirement,
            reason_code=self.rule.reason_code,
            evaluated_at=policy_input.evaluated_at,
        )


def plan() -> ExecutionPlan:
    return ExecutionPlan(
        transaction_id="txn-1",
        tenant_id="tenant-a",
        business_digest="sha256:" + "a" * 64,
        risk_class=RiskClass.CONSEQUENTIAL_WRITE,
        verification_level=VerificationLevel.L2,
        steps=(
            ExecutionStep(
                step_id="submit-booking",
                capability="booking.submit",
                adapter="synthetic.booking.api",
                operation="create",
                risk_class=RiskClass.CONSEQUENTIAL_WRITE,
                compensation=CompensationSpec(
                    adapter="synthetic.booking.api",
                    operation="cancel",
                    capability="booking.cancel",
                    include_effect_reference=True,
                ),
            ),
        ),
    )


def test_compensation_gets_an_independent_frozen_policy_decision() -> None:
    provider = Provider(PolicyEffect.ALLOW)

    frozen = asyncio.run(
        apply_execution_policy(
            plan(),
            provider,
            environment_id="production",
            principal_ref="principal.sha256.test",
            clock=lambda: datetime(2040, 1, 1, tzinfo=UTC),
        )
    )

    assert [item.capability for item in provider.inputs] == [
        "booking.submit",
        "booking.cancel",
    ]
    assert len(frozen.policy_decisions) == 2
    assert frozen.policy_decisions[1].input.risk_class is RiskClass.REVERSIBLE_WRITE


def test_compensation_policy_cannot_defer_to_an_unmodelled_approval() -> None:
    with pytest.raises(PolicyPlanningError) as caught:
        asyncio.run(
            apply_execution_policy(
                plan(),
                Provider(PolicyEffect.REQUIRE_APPROVAL),
                environment_id="production",
                principal_ref="principal.sha256.test",
                clock=lambda: datetime(2040, 1, 1, tzinfo=UTC),
            )
        )

    assert caught.value.code == "compensation_approval_unsupported"
