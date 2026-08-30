"""Idempotent application service for durable transaction execution."""

from __future__ import annotations

import hashlib
import uuid
from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict

from cargomesh.application.compile import CompilationResult
from cargomesh.credentials import CredentialBindingStore
from cargomesh.ir import TransactionCommand
from cargomesh.policy import PolicyProvider
from cargomesh.runtime.idempotency import (
    IdempotencyConflict,
    SubmissionReservation,
    SubmissionState,
    SubmissionStore,
)
from cargomesh.runtime.models import ApprovalDecision, ExecutionPlan, ExecutionSnapshot
from cargomesh.runtime.policy import PolicyPlanningError, apply_execution_policy


class ExecutionPlanner(Protocol):
    def build(
        self,
        command: TransactionCommand,
        *,
        transaction_id: str,
        business_digest: str,
    ) -> ExecutionPlan: ...


class ExecutionGateway(Protocol):
    async def start(self, plan: ExecutionPlan, *, workflow_id: str) -> None: ...

    async def get_snapshot(self, workflow_id: str) -> ExecutionSnapshot: ...

    async def approve(self, workflow_id: str, decision: ApprovalDecision) -> None: ...

    async def cancel(self, workflow_id: str) -> None: ...


class TransactionServiceError(RuntimeError):
    """Bounded application failure safe for the HTTP error normalizer."""

    def __init__(self, code: str, message: str, *, status_code: int) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code


class TransactionSubmission(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_id: str
    transaction_id: str
    workflow_id: str
    submission_state: SubmissionState
    created: bool


class TransactionView(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_id: str
    transaction_id: str
    workflow_id: str
    submission_state: SubmissionState
    start_error_code: str | None = None
    execution: ExecutionSnapshot | None = None


class TransactionService:
    """Coordinates compilation output, idempotency storage, planning, and Temporal."""

    def __init__(
        self,
        *,
        planner: ExecutionPlanner,
        submissions: SubmissionStore,
        gateway: ExecutionGateway,
        policy_provider: PolicyProvider | None = None,
        policy_environment_id: str = "local",
        credential_bindings: CredentialBindingStore | None = None,
        default_approval_timeout_seconds: int = 86_400,
    ) -> None:
        self._planner = planner
        self._submissions = submissions
        self._gateway = gateway
        self._policy_provider = policy_provider
        self._policy_environment_id = policy_environment_id
        self._credential_bindings = credential_bindings
        self._default_approval_timeout_seconds = default_approval_timeout_seconds

    async def submit(
        self, compilation: CompilationResult, idempotency_key: str
    ) -> TransactionSubmission:
        return await self.submit_with_context(
            compilation,
            idempotency_key,
            principal_ref="runtime.service",
        )

    async def submit_with_context(
        self,
        compilation: CompilationResult,
        idempotency_key: str,
        *,
        principal_ref: str,
    ) -> TransactionSubmission:
        command = compilation.command
        if not isinstance(command, TransactionCommand):
            raise TransactionServiceError(
                "invalid_compilation",
                "Compilation did not produce supported Transaction IR",
                status_code=422,
            )
        candidate_transaction_id = str(uuid.uuid4())
        candidate_workflow_id = _workflow_id(command.tenant_id, candidate_transaction_id)
        try:
            reservation = self._submissions.reserve(
                command.tenant_id,
                idempotency_key,
                candidate_transaction_id,
                candidate_workflow_id,
                compilation.digest,
            )
        except IdempotencyConflict as exc:
            raise TransactionServiceError(
                "idempotency_conflict",
                "Idempotency-Key is already bound to another business request",
                status_code=409,
            ) from exc

        if reservation.state is SubmissionState.STARTED:
            return _submission_result(reservation)

        try:
            plan = self._planner.build(
                command,
                transaction_id=reservation.transaction_id,
                business_digest=reservation.business_digest,
            )
            if self._policy_provider is not None:
                plan = await apply_execution_policy(
                    plan,
                    self._policy_provider,
                    environment_id=self._policy_environment_id,
                    principal_ref=principal_ref,
                    credential_bindings=self._credential_bindings,
                    default_approval_timeout_seconds=(
                        self._default_approval_timeout_seconds
                    ),
                )
        except PolicyPlanningError as exc:
            self._mark_start_failed(reservation, exc.code)
            raise TransactionServiceError(
                exc.code,
                exc.message,
                status_code=exc.status_code,
            ) from exc
        except Exception as exc:
            self._mark_start_failed(reservation, "planning_failed")
            raise TransactionServiceError(
                "runtime_configuration_error",
                "No valid execution plan is configured for this transaction",
                status_code=503,
            ) from exc

        try:
            await self._gateway.start(plan, workflow_id=reservation.workflow_id)
        except Exception as exc:
            self._mark_start_failed(reservation, "workflow_start_failed")
            raise TransactionServiceError(
                "runtime_unavailable",
                "Transaction workflow could not be started",
                status_code=503,
            ) from exc

        started = self._submissions.mark_started(reservation.transaction_id)
        return TransactionSubmission(
            tenant_id=started.tenant_id,
            transaction_id=started.transaction_id,
            workflow_id=started.workflow_id,
            submission_state=started.state,
            created=reservation.created,
        )

    async def get(self, transaction_id: str) -> TransactionView:
        reservation = self._lookup(transaction_id)
        if reservation.state is not SubmissionState.STARTED:
            return _view(reservation)
        try:
            snapshot = await self._gateway.get_snapshot(reservation.workflow_id)
        except Exception as exc:
            raise TransactionServiceError(
                "runtime_unavailable",
                "Transaction status is temporarily unavailable",
                status_code=503,
            ) from exc
        return _view(reservation, snapshot=snapshot)

    async def approve(self, transaction_id: str, decision: Any) -> TransactionView:
        reservation = self._require_started(transaction_id)
        try:
            normalized = _approval_decision(decision)
        except Exception as exc:
            raise TransactionServiceError(
                "invalid_approval", "Approval decision is invalid", status_code=422
            ) from exc
        try:
            await self._gateway.approve(reservation.workflow_id, normalized)
        except Exception as exc:
            raise TransactionServiceError(
                "runtime_unavailable",
                "Approval could not be delivered",
                status_code=503,
            ) from exc
        return await self.get(transaction_id)

    async def cancel(self, transaction_id: str) -> TransactionView:
        reservation = self._require_started(transaction_id)
        try:
            await self._gateway.cancel(reservation.workflow_id)
        except Exception as exc:
            raise TransactionServiceError(
                "runtime_unavailable",
                "Cancellation could not be delivered",
                status_code=503,
            ) from exc
        return await self.get(transaction_id)

    def _lookup(self, transaction_id: str) -> SubmissionReservation:
        reservation = self._submissions.lookup_by_transaction_id(transaction_id)
        if reservation is None:
            raise TransactionServiceError(
                "transaction_not_found", "Transaction was not found", status_code=404
            )
        return reservation

    def _require_started(self, transaction_id: str) -> SubmissionReservation:
        reservation = self._lookup(transaction_id)
        if reservation.state is not SubmissionState.STARTED:
            raise TransactionServiceError(
                "transaction_not_started",
                "Transaction workflow has not started",
                status_code=409,
            )
        return reservation

    def _mark_start_failed(
        self, reservation: SubmissionReservation, error_code: str
    ) -> None:
        try:
            self._submissions.mark_start_failed(reservation.transaction_id, error_code)
        except Exception:
            # Another concurrent caller may already have successfully started the
            # deterministic workflow. Never overwrite that stronger state.
            return


def _workflow_id(tenant_id: str, transaction_id: str) -> str:
    tenant_hash = hashlib.sha256(tenant_id.encode("utf-8")).hexdigest()[:16]
    return f"cargomesh-{tenant_hash}-{transaction_id}"


def _submission_result(reservation: SubmissionReservation) -> TransactionSubmission:
    return TransactionSubmission(
        tenant_id=reservation.tenant_id,
        transaction_id=reservation.transaction_id,
        workflow_id=reservation.workflow_id,
        submission_state=reservation.state,
        created=reservation.created,
    )


def _view(
    reservation: SubmissionReservation, *, snapshot: ExecutionSnapshot | None = None
) -> TransactionView:
    return TransactionView(
        tenant_id=reservation.tenant_id,
        transaction_id=reservation.transaction_id,
        workflow_id=reservation.workflow_id,
        submission_state=reservation.state,
        start_error_code=reservation.start_error_code,
        execution=snapshot,
    )


def _approval_decision(value: Any) -> ApprovalDecision:
    if isinstance(value, ApprovalDecision):
        return value
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json")
    return ApprovalDecision.model_validate(value)
