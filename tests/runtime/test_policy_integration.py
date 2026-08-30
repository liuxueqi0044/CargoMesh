from __future__ import annotations

import asyncio
import hashlib
from datetime import UTC, datetime, timedelta

import pytest

from cargomesh.api.main import _policy_principal_ref
from cargomesh.application.compile import CompilationResult
from cargomesh.application.transactions import TransactionService, TransactionServiceError
from cargomesh.controlplane.models import Principal, PrincipalType
from cargomesh.ir import ShipmentSubject, TransactionCommand
from cargomesh.policy import (
    DataClassification,
    ExecutionChannel,
    PolicyDecision,
    PolicyEffect,
    PolicyInput,
    PolicyRule,
    PolicySet,
)
from cargomesh.runtime.idempotency import SQLiteSubmissionStore
from cargomesh.runtime.planner import synthetic_tracking_planner
from cargomesh.runtime.policy import PolicyPlanningError, apply_execution_policy

NOW = datetime(2040, 1, 2, 3, 4, 5, tzinfo=UTC)


def command() -> TransactionCommand:
    return TransactionCommand(
        tenant_id="tenant-a",
        external_reference="customer-1",
        subject=ShipmentSubject(carrier_booking_reference="CBR-1"),
    )


def plan():
    return synthetic_tracking_planner().build(
        command(), transaction_id="txn-1", business_digest="sha256:" + "a" * 64
    )


def compilation() -> CompilationResult:
    return CompilationResult(
        command=command(),
        canonical_json='{"transaction":"policy-contract"}',
        digest="sha256:" + "a" * 64,
        diagnostics=[],
        source_schema_version="cargomesh.transaction/v1",
    )


class Gateway:
    def __init__(self) -> None:
        self.started = []

    async def start(self, execution_plan, *, workflow_id: str) -> None:
        self.started.append((execution_plan, workflow_id))

    async def get_snapshot(self, workflow_id: str):
        raise AssertionError(f"unexpected snapshot request: {workflow_id}")

    async def approve(self, workflow_id: str, decision) -> None:
        raise AssertionError(f"unexpected approval: {workflow_id} {decision}")

    async def cancel(self, workflow_id: str) -> None:
        raise AssertionError(f"unexpected cancellation: {workflow_id}")


class PolicyStub:
    def __init__(self, effect: PolicyEffect) -> None:
        self.effect = effect
        self.inputs: list[PolicyInput] = []
        self.rule = PolicyRule.issue(
            rule_id="contract.rule",
            priority=1,
            effect=effect,
            approval_requirement=(
                "human.approver" if effect is PolicyEffect.REQUIRE_APPROVAL else None
            ),
            reason_code="contract.result",
        )
        self.policy_set = PolicySet.issue(
            policy_id="contract-policy", version="1.0.0", rules=(self.rule,)
        )

    async def evaluate(self, policy_input: PolicyInput) -> PolicyDecision:
        self.inputs.append(policy_input)
        return PolicyDecision.issue(
            input=policy_input,
            policy_id=self.policy_set.policy_id,
            policy_version=self.policy_set.version,
            policy_digest=self.policy_set.policy_digest,
            effect=self.effect,
            matched_rule_id=self.rule.rule_id,
            matched_rule_digest=self.rule.rule_digest,
            approval_requirement=self.rule.approval_requirement,
            reason_code=self.rule.reason_code,
            evaluated_at=policy_input.evaluated_at,
        )


def apply(effect: PolicyEffect):
    provider = PolicyStub(effect)
    frozen = asyncio.run(
        apply_execution_policy(
            plan(),
            provider,
            environment_id="production",
            principal_ref="principal:sha256:opaque",
            clock=lambda: NOW,
        )
    )
    return frozen, provider


def test_allow_is_frozen_into_the_execution_plan_without_transaction_payload() -> None:
    frozen, provider = apply(PolicyEffect.ALLOW)

    assert len(provider.inputs) == 1
    assert frozen.environment_id == "production"
    assert frozen.policy_decisions[0].effect is PolicyEffect.ALLOW
    assert frozen.policy_decisions[0].input == provider.inputs[0]
    assert frozen.policy_decisions[0].input.principal_ref == "principal:sha256:opaque"
    policy_json = frozen.policy_decisions[0].model_dump_json()
    assert "CBR-1" not in policy_json
    assert "customer-1" not in policy_json
    assert provider.inputs[0].data_classification is DataClassification.INTERNAL
    assert provider.inputs[0].channel is ExecutionChannel.API


def test_deny_prevents_a_plan_from_being_issued() -> None:
    provider = PolicyStub(PolicyEffect.DENY)

    with pytest.raises(PolicyPlanningError) as caught:
        asyncio.run(
            apply_execution_policy(
                plan(),
                provider,
                environment_id="production",
                principal_ref="principal:sha256:opaque",
                clock=lambda: NOW,
            )
        )

    assert caught.value.code == "policy_denied"
    assert caught.value.status_code == 403
    assert str(caught.value) == "Execution policy denied this transaction"


def test_provider_failure_is_bounded_as_unavailable() -> None:
    class BrokenProvider:
        async def evaluate(self, policy_input: PolicyInput) -> PolicyDecision:
            del policy_input
            raise RuntimeError("provider internals must not escape")

    with pytest.raises(PolicyPlanningError) as caught:
        asyncio.run(
            apply_execution_policy(
                plan(),
                BrokenProvider(),
                environment_id="production",
                principal_ref="principal:sha256:opaque",
                clock=lambda: NOW,
            )
        )

    assert caught.value.code == "policy_unavailable"
    assert caught.value.status_code == 503
    assert "provider internals" not in str(caught.value)


def test_policy_approval_is_frozen_with_default_timeout() -> None:
    frozen, _ = apply(PolicyEffect.REQUIRE_APPROVAL)

    step = frozen.steps[0]
    assert frozen.policy_decisions[0].effect is PolicyEffect.REQUIRE_APPROVAL
    assert step.requires_approval is True
    assert step.approval_timeout_seconds == 86_400


def test_allow_is_frozen_before_the_gateway_is_started() -> None:
    gateway = Gateway()
    service = TransactionService(
        planner=synthetic_tracking_planner(),
        submissions=SQLiteSubmissionStore(),
        gateway=gateway,
        policy_provider=PolicyStub(PolicyEffect.ALLOW),
        policy_environment_id="production",
    )

    result = asyncio.run(
        service.submit_with_context(
            compilation(), "policy-allow", principal_ref="principal:sha256:opaque"
        )
    )

    assert result.created is True
    assert len(gateway.started) == 1
    frozen = gateway.started[0][0]
    assert frozen.policy_decisions[0].effect is PolicyEffect.ALLOW
    assert frozen.policy_decisions[0].input.principal_ref == "principal:sha256:opaque"


@pytest.mark.parametrize(
    ("provider", "expected_code", "expected_status"),
    [
        (PolicyStub(PolicyEffect.DENY), "policy_denied", 403),
    ],
)
def test_policy_rejection_prevents_gateway_start(
    provider: PolicyStub,
    expected_code: str,
    expected_status: int,
) -> None:
    gateway = Gateway()
    service = TransactionService(
        planner=synthetic_tracking_planner(),
        submissions=SQLiteSubmissionStore(),
        gateway=gateway,
        policy_provider=provider,
        policy_environment_id="production",
    )

    with pytest.raises(TransactionServiceError) as caught:
        asyncio.run(
            service.submit_with_context(
                compilation(), "policy-denied", principal_ref="principal:sha256:opaque"
            )
        )

    assert caught.value.code == expected_code
    assert caught.value.status_code == expected_status
    assert gateway.started == []


def test_policy_provider_failure_returns_503_before_gateway_start() -> None:
    class BrokenProvider:
        async def evaluate(self, policy_input: PolicyInput) -> PolicyDecision:
            del policy_input
            raise RuntimeError("untrusted provider failure")

    gateway = Gateway()
    service = TransactionService(
        planner=synthetic_tracking_planner(),
        submissions=SQLiteSubmissionStore(),
        gateway=gateway,
        policy_provider=BrokenProvider(),
        policy_environment_id="production",
    )

    with pytest.raises(TransactionServiceError) as caught:
        asyncio.run(
            service.submit_with_context(
                compilation(), "policy-fault", principal_ref="principal:sha256:opaque"
            )
        )

    assert caught.value.code == "policy_unavailable"
    assert caught.value.status_code == 503
    assert "untrusted provider failure" not in str(caught.value)
    assert gateway.started == []


def test_policy_approval_is_frozen_before_gateway_start() -> None:
    gateway = Gateway()
    service = TransactionService(
        planner=synthetic_tracking_planner(),
        submissions=SQLiteSubmissionStore(),
        gateway=gateway,
        policy_provider=PolicyStub(PolicyEffect.REQUIRE_APPROVAL),
        policy_environment_id="production",
    )

    asyncio.run(
        service.submit_with_context(
            compilation(), "policy-approval", principal_ref="principal:sha256:opaque"
        )
    )

    step = gateway.started[0][0].steps[0]
    assert step.requires_approval is True
    assert step.approval_timeout_seconds == 86_400


def test_api_principal_reference_is_stable_and_opaque() -> None:
    principal = Principal(
        issuer="https://identity.example.test",
        subject="human-subject-123",
        principal_type=PrincipalType.HUMAN,
        audiences=("cargomesh",),
        token_id_digest="sha256:" + "1" * 64,
        issued_at=NOW - timedelta(minutes=1),
        expires_at=NOW + timedelta(minutes=1),
        authenticated_at=NOW,
    )

    reference = _policy_principal_ref(principal)

    expected = hashlib.sha256(
        b"https://identity.example.test\0human-subject-123"
    ).hexdigest()
    assert reference == f"principal.sha256.{expected}"
    assert principal.issuer not in reference
    assert principal.subject not in reference
    assert principal.token_id_digest not in reference
