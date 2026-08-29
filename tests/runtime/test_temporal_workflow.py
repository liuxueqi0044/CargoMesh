from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from temporalio.exceptions import ActivityError, ApplicationError

from cargomesh.ir.enums import RiskClass, VerificationLevel
from cargomesh.runtime.models import (
    AdapterInvocation,
    AdapterResult,
    ApprovalDecision,
    CompensationSpec,
    ExecutionPlan,
    ExecutionStatus,
    ExecutionStep,
)
from cargomesh.runtime.temporal import CargoMeshTransactionWorkflow


def plan(*steps: ExecutionStep, risk: RiskClass = RiskClass.READ_ONLY) -> ExecutionPlan:
    return ExecutionPlan(
        transaction_id="txn-1",
        tenant_id="tenant-a",
        business_digest="sha256:" + "a" * 64,
        risk_class=risk,
        verification_level=VerificationLevel.L1,
        steps=steps,
    )


def step(
    step_id: str,
    operation: str,
    *,
    requires_approval: bool = False,
    compensation: str | None = None,
) -> ExecutionStep:
    return ExecutionStep(
        step_id=step_id,
        capability="shipment.track.read",
        adapter="test.adapter",
        operation=operation,
        risk_class=(
            RiskClass.REVERSIBLE_WRITE
            if compensation is not None
            else RiskClass.READ_ONLY
        ),
        requires_approval=requires_approval,
        compensation=(
            CompensationSpec(adapter="test.adapter", operation=compensation)
            if compensation is not None
            else None
        ),
    )


def test_approved_step_executes_but_never_claims_verified() -> None:
    workflow_instance = CargoMeshTransactionWorkflow()
    workflow_instance.approve(
        ApprovalDecision(step_id="read", approved=True, decided_by="operator-a")
    )
    execute = AsyncMock(return_value=AdapterResult(output={"events": []}))
    wait = AsyncMock(return_value=None)
    workflow_info = SimpleNamespace(workflow_id="wf-1")

    with (
        patch("cargomesh.runtime.temporal.workflow.info", return_value=workflow_info),
        patch("cargomesh.runtime.temporal.workflow.wait_condition", wait),
        patch("cargomesh.runtime.temporal.workflow.execute_activity", execute),
    ):
        result = asyncio.run(
            workflow_instance.run(plan(step("read", "fetch", requires_approval=True)))
        )

    assert result.status is ExecutionStatus.EXECUTED_UNVERIFIED
    assert result.completed_step_ids == ("read",)
    assert result.status.value not in {"SUCCESS", "VERIFIED"}
    execute.assert_awaited_once()


def test_rejected_approval_is_terminal_without_adapter_invocation() -> None:
    workflow_instance = CargoMeshTransactionWorkflow()
    workflow_instance.approve(
        ApprovalDecision(
            step_id="read", approved=False, decided_by="operator-a", reason="policy rejected"
        )
    )
    execute = AsyncMock(return_value=AdapterResult())
    workflow_info = SimpleNamespace(workflow_id="wf-1")

    with (
        patch("cargomesh.runtime.temporal.workflow.info", return_value=workflow_info),
        patch(
            "cargomesh.runtime.temporal.workflow.wait_condition",
            AsyncMock(return_value=None),
        ),
        patch("cargomesh.runtime.temporal.workflow.execute_activity", execute),
    ):
        result = asyncio.run(
            workflow_instance.run(plan(step("read", "fetch", requires_approval=True)))
        )

    assert result.status is ExecutionStatus.REJECTED
    execute.assert_not_awaited()


def test_failed_step_compensates_completed_steps_in_reverse_order() -> None:
    workflow_instance = CargoMeshTransactionWorkflow()
    operations: list[str] = []

    async def invoke(
        _activity: str, invocation: AdapterInvocation, **_options: object
    ) -> AdapterResult:
        operation = invocation.operation
        operations.append(operation)
        if operation == "write-3":
            raise ActivityError(
                "failed",
                scheduled_event_id=1,
                started_event_id=2,
                identity="test",
                activity_type="adapter",
                activity_id="step-3",
                retry_state=None,
            )
        return AdapterResult(effect_reference=f"effect-{operation}")

    execution_plan = plan(
        step("one", "write-1", compensation="undo-1"),
        step("two", "write-2", compensation="undo-2"),
        step("three", "write-3", compensation="undo-3"),
        risk=RiskClass.REVERSIBLE_WRITE,
    )
    workflow_info = SimpleNamespace(workflow_id="wf-1")
    with (
        patch("cargomesh.runtime.temporal.workflow.info", return_value=workflow_info),
        patch("cargomesh.runtime.temporal.workflow.execute_activity", side_effect=invoke),
    ):
        result = asyncio.run(workflow_instance.run(execution_plan))

    assert operations == [
        "write-1",
        "write-2",
        "write-3",
        "undo-3",
        "undo-2",
        "undo-1",
    ]
    assert result.status is ExecutionStatus.COMPENSATED
    assert result.completed_step_ids == ("one", "two")
    assert result.compensated_step_ids == ("three", "two", "one")
    assert result.failure_code == "activity_failed"


def test_safe_adapter_failure_code_survives_the_activity_boundary() -> None:
    activity_error = ActivityError(
        "failed",
        scheduled_event_id=1,
        started_event_id=2,
        identity="test",
        activity_type="adapter",
        activity_id="read",
        retry_state=None,
    )
    activity_error.__cause__ = ApplicationError(
        "Portal signature no longer matches the certified adapter",
        type="portal_drift_detected",
        non_retryable=True,
    )
    workflow_instance = CargoMeshTransactionWorkflow()
    workflow_info = SimpleNamespace(workflow_id="wf-1")

    with (
        patch("cargomesh.runtime.temporal.workflow.info", return_value=workflow_info),
        patch(
            "cargomesh.runtime.temporal.workflow.execute_activity",
            AsyncMock(side_effect=activity_error),
        ),
    ):
        result = asyncio.run(workflow_instance.run(plan(step("read", "fetch"))))

    assert result.status is ExecutionStatus.HALTED
    assert result.failure_code == "portal_drift_detected"
