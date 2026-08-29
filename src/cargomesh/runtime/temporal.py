"""Temporal implementation of CargoMesh's durable transaction runtime."""

from __future__ import annotations

from datetime import timedelta

from temporalio import workflow
from temporalio.client import Client
from temporalio.common import RetryPolicy, WorkflowIDReusePolicy
from temporalio.contrib.pydantic import pydantic_data_converter
from temporalio.exceptions import ActivityError, WorkflowAlreadyStartedError

with workflow.unsafe.imports_passed_through():
    from cargomesh.ir.enums import RiskClass
    from cargomesh.runtime.adapters import EXECUTE_ADAPTER_ACTIVITY
    from cargomesh.runtime.models import (
        AdapterInvocation,
        AdapterResult,
        ApprovalDecision,
        ExecutionPlan,
        ExecutionSnapshot,
        ExecutionStatus,
        ExecutionStep,
        StepOutput,
    )
    from cargomesh.runtime.state_machine import transition


def _temporal_retry_policy(step: ExecutionStep) -> RetryPolicy:
    spec = step.retry
    return RetryPolicy(
        initial_interval=timedelta(seconds=spec.initial_interval_seconds),
        backoff_coefficient=spec.backoff_coefficient,
        maximum_interval=timedelta(seconds=spec.maximum_interval_seconds),
        maximum_attempts=spec.maximum_attempts,
        non_retryable_error_types=list(spec.non_retryable_error_types),
    )


@workflow.defn(name="CargoMeshTransactionWorkflow")
class CargoMeshTransactionWorkflow:
    """Durable, deterministic execution with explicit approval and compensation."""

    def __init__(self) -> None:
        self._snapshot: ExecutionSnapshot | None = None
        self._approvals: dict[str, ApprovalDecision] = {}
        self._approval_conflict = False
        self._cancel_requested = False

    @workflow.run
    async def run(self, plan: ExecutionPlan) -> ExecutionSnapshot:
        self._snapshot = ExecutionSnapshot(
            transaction_id=plan.transaction_id,
            workflow_id=workflow.info().workflow_id,
        )
        self._set_status(ExecutionStatus.RUNNING)
        completed_steps: list[ExecutionStep] = []

        for step in plan.steps:
            if self._cancel_requested:
                return await self._finish_with_compensation(
                    plan, completed_steps, ExecutionStatus.CANCELLED, "cancelled"
                )
            if step.requires_approval:
                decision = await self._wait_for_approval(step)
                if decision is None:
                    terminal = (
                        ExecutionStatus.CANCELLED
                        if self._cancel_requested
                        else ExecutionStatus.HALTED
                    )
                    failure_code = "cancelled" if self._cancel_requested else "approval_timeout"
                    return await self._finish_with_compensation(
                        plan, completed_steps, terminal, failure_code
                    )
                if self._approval_conflict:
                    return await self._finish_with_compensation(
                        plan, completed_steps, ExecutionStatus.HALTED, "approval_conflict"
                    )
                if not decision.approved:
                    return await self._finish_with_compensation(
                        plan, completed_steps, ExecutionStatus.REJECTED, None
                    )

            self._replace(current_step_id=step.step_id, awaiting_approval_step_id=None)
            try:
                result = await self._execute_step(plan, step)
            except ActivityError:
                possibly_effectful = (
                    [*completed_steps, step]
                    if step.risk_class is not RiskClass.READ_ONLY
                    else completed_steps
                )
                terminal = (
                    ExecutionStatus.COMPENSATED
                    if step.risk_class is not RiskClass.READ_ONLY
                    else ExecutionStatus.HALTED
                )
                return await self._finish_with_compensation(
                    plan, possibly_effectful, terminal, "activity_failed"
                )
            completed_steps.append(step)
            snapshot = self._require_snapshot()
            self._replace(
                completed_step_ids=(*snapshot.completed_step_ids, step.step_id),
                outputs=(
                    *snapshot.outputs,
                    StepOutput(
                        step_id=step.step_id,
                        output=result.output,
                        effect_reference=result.effect_reference,
                    ),
                ),
            )

        if self._cancel_requested:
            return await self._finish_with_compensation(
                plan, completed_steps, ExecutionStatus.CANCELLED, "cancelled"
            )
        self._replace(current_step_id=None)
        self._set_status(ExecutionStatus.EXECUTED_UNVERIFIED)
        return self._require_snapshot()

    async def _wait_for_approval(self, step: ExecutionStep) -> ApprovalDecision | None:
        self._replace(current_step_id=step.step_id, awaiting_approval_step_id=step.step_id)
        self._set_status(ExecutionStatus.WAITING_APPROVAL)
        try:
            await workflow.wait_condition(
                lambda: step.step_id in self._approvals or self._cancel_requested,
                timeout=(
                    timedelta(seconds=step.approval_timeout_seconds)
                    if step.approval_timeout_seconds is not None
                    else None
                ),
            )
        except TimeoutError:
            return None
        if self._cancel_requested:
            return None
        decision = self._approvals[step.step_id]
        if decision.approved:
            self._set_status(ExecutionStatus.RUNNING)
        return decision

    async def _execute_step(
        self, plan: ExecutionPlan, step: ExecutionStep
    ) -> AdapterResult:
        invocation = AdapterInvocation(
            transaction_id=plan.transaction_id,
            tenant_id=plan.tenant_id,
            step_id=step.step_id,
            adapter=step.adapter,
            operation=step.operation,
            input=step.input,
        )
        result = await workflow.execute_activity(
            EXECUTE_ADAPTER_ACTIVITY,
            invocation,
            result_type=AdapterResult,
            start_to_close_timeout=timedelta(seconds=step.timeout_seconds),
            retry_policy=_temporal_retry_policy(step),
        )
        return result  # type: ignore[no-any-return]

    async def _finish_with_compensation(
        self,
        plan: ExecutionPlan,
        completed_steps: list[ExecutionStep],
        requested_terminal: ExecutionStatus,
        failure_code: str | None,
    ) -> ExecutionSnapshot:
        compensatable = [step for step in completed_steps if step.compensation is not None]
        unresolved_effect = any(
            step.risk_class is not RiskClass.READ_ONLY and step.compensation is None
            for step in completed_steps
        )
        if compensatable:
            self._set_status(ExecutionStatus.COMPENSATING)
            for step in reversed(compensatable):
                compensation = step.compensation
                assert compensation is not None
                invocation = AdapterInvocation(
                    transaction_id=plan.transaction_id,
                    tenant_id=plan.tenant_id,
                    step_id=step.step_id,
                    adapter=compensation.adapter,
                    operation=compensation.operation,
                    input=compensation.input,
                )
                try:
                    await workflow.execute_activity(
                        EXECUTE_ADAPTER_ACTIVITY,
                        invocation,
                        result_type=AdapterResult,
                        start_to_close_timeout=timedelta(seconds=compensation.timeout_seconds),
                        retry_policy=RetryPolicy(
                            initial_interval=timedelta(
                                seconds=compensation.retry.initial_interval_seconds
                            ),
                            backoff_coefficient=compensation.retry.backoff_coefficient,
                            maximum_interval=timedelta(
                                seconds=compensation.retry.maximum_interval_seconds
                            ),
                            maximum_attempts=compensation.retry.maximum_attempts,
                            non_retryable_error_types=list(
                                compensation.retry.non_retryable_error_types
                            ),
                        ),
                    )
                except ActivityError:
                    self._replace(failure_code="compensation_failed", current_step_id=None)
                    self._set_status(ExecutionStatus.HALTED)
                    return self._require_snapshot()
                snapshot = self._require_snapshot()
                self._replace(
                    compensated_step_ids=(*snapshot.compensated_step_ids, step.step_id)
                )

        terminal = requested_terminal
        if unresolved_effect:
            terminal = ExecutionStatus.HALTED
            failure_code = "uncompensated_effect"
        elif requested_terminal is ExecutionStatus.COMPENSATED and not compensatable:
            terminal = ExecutionStatus.HALTED
        self._replace(
            current_step_id=None,
            awaiting_approval_step_id=None,
            failure_code=failure_code,
        )
        self._set_status(terminal)
        return self._require_snapshot()

    @workflow.signal(name="approve")
    def approve(self, decision: ApprovalDecision) -> None:
        existing = self._approvals.get(decision.step_id)
        if existing is None:
            self._approvals[decision.step_id] = decision
        elif existing != decision:
            self._approval_conflict = True

    @workflow.signal(name="request_cancel")
    def request_cancel(self) -> None:
        self._cancel_requested = True

    @workflow.query(name="status")
    def status(self) -> ExecutionSnapshot:
        return self._require_snapshot()

    def _set_status(self, target: ExecutionStatus) -> None:
        snapshot = self._require_snapshot()
        self._replace(status=transition(snapshot.status, target))

    def _replace(self, **updates: object) -> None:
        self._snapshot = self._require_snapshot().model_copy(update=updates)

    def _require_snapshot(self) -> ExecutionSnapshot:
        if self._snapshot is None:
            raise RuntimeError("workflow has not started")
        return self._snapshot


class TemporalExecutionGateway:
    """Client-side adapter used by the application service."""

    def __init__(self, client: Client, *, task_queue: str) -> None:
        self._client = client
        self._task_queue = task_queue

    async def start(self, plan: ExecutionPlan, *, workflow_id: str) -> None:
        try:
            await self._client.start_workflow(
                CargoMeshTransactionWorkflow.run,
                plan,
                id=workflow_id,
                task_queue=self._task_queue,
                id_reuse_policy=WorkflowIDReusePolicy.REJECT_DUPLICATE,
            )
        except WorkflowAlreadyStartedError:
            return

    async def get_snapshot(self, workflow_id: str) -> ExecutionSnapshot:
        handle = self._client.get_workflow_handle(workflow_id)
        return await handle.query(CargoMeshTransactionWorkflow.status)

    async def approve(self, workflow_id: str, decision: ApprovalDecision) -> None:
        handle = self._client.get_workflow_handle(workflow_id)
        await handle.signal(CargoMeshTransactionWorkflow.approve, decision)

    async def cancel(self, workflow_id: str) -> None:
        handle = self._client.get_workflow_handle(workflow_id)
        await handle.signal(CargoMeshTransactionWorkflow.request_cancel)


async def connect_temporal(target: str, *, namespace: str = "default") -> Client:
    return await Client.connect(
        target,
        namespace=namespace,
        data_converter=pydantic_data_converter,
    )
