from __future__ import annotations

import asyncio
from typing import Any

import pytest

from cargomesh.application.compile import CompileService
from cargomesh.application.transactions import (
    TransactionService,
    TransactionServiceError,
)
from cargomesh.ir import ShipmentSubject, TransactionCommand
from cargomesh.runtime import (
    ApprovalDecision,
    ExecutionSnapshot,
    ExecutionStatus,
    synthetic_tracking_planner,
)
from cargomesh.runtime.idempotency import SQLiteSubmissionStore, SubmissionState


class FakeGateway:
    def __init__(self) -> None:
        self.starts: list[tuple[Any, str]] = []
        self.approvals: list[tuple[str, ApprovalDecision]] = []
        self.cancellations: list[str] = []
        self.fail_start = False

    async def start(self, plan: Any, *, workflow_id: str) -> None:
        self.starts.append((plan, workflow_id))
        if self.fail_start:
            raise OSError("internal network details")

    async def get_snapshot(self, workflow_id: str) -> ExecutionSnapshot:
        transaction_id = self.starts[-1][0].transaction_id
        return ExecutionSnapshot(
            transaction_id=transaction_id,
            workflow_id=workflow_id,
            status=ExecutionStatus.RUNNING,
        )

    async def approve(self, workflow_id: str, decision: ApprovalDecision) -> None:
        self.approvals.append((workflow_id, decision))

    async def cancel(self, workflow_id: str) -> None:
        self.cancellations.append(workflow_id)


def compilation(*, external_reference: str = "customer-1") -> Any:
    command = TransactionCommand(
        tenant_id="tenant-a",
        external_reference=external_reference,
        subject=ShipmentSubject(carrier_booking_reference="CBR-1"),
    )
    return CompileService().compile("cargomesh.transaction/v1", command.model_dump(mode="json"))


def service(gateway: FakeGateway) -> TransactionService:
    return TransactionService(
        planner=synthetic_tracking_planner(),
        submissions=SQLiteSubmissionStore(),
        gateway=gateway,
    )


def test_submit_is_idempotent_and_does_not_start_twice_after_acknowledgement() -> None:
    gateway = FakeGateway()
    transactions = service(gateway)

    first = asyncio.run(transactions.submit(compilation(), "same-key"))
    replay = asyncio.run(transactions.submit(compilation(), "same-key"))

    assert first.created is True
    assert replay.created is False
    assert first.transaction_id == replay.transaction_id
    assert first.workflow_id == replay.workflow_id
    assert first.submission_state is SubmissionState.STARTED
    assert len(gateway.starts) == 1


def test_digest_conflict_fails_closed() -> None:
    gateway = FakeGateway()
    transactions = service(gateway)
    asyncio.run(transactions.submit(compilation(), "same-key"))

    with pytest.raises(TransactionServiceError) as error:
        asyncio.run(
            transactions.submit(compilation(external_reference="another-request"), "same-key")
        )
    assert error.value.code == "idempotency_conflict"
    assert error.value.status_code == 409


def test_failed_start_retries_same_transaction_and_workflow_ids() -> None:
    gateway = FakeGateway()
    transactions = service(gateway)
    gateway.fail_start = True

    with pytest.raises(TransactionServiceError) as failure:
        asyncio.run(transactions.submit(compilation(), "retry-key"))
    assert failure.value.code == "runtime_unavailable"
    first_plan, first_workflow_id = gateway.starts[0]

    gateway.fail_start = False
    retried = asyncio.run(transactions.submit(compilation(), "retry-key"))

    assert retried.created is False
    assert retried.transaction_id == first_plan.transaction_id
    assert retried.workflow_id == first_workflow_id
    assert gateway.starts[1][0].transaction_id == first_plan.transaction_id
    assert gateway.starts[1][1] == first_workflow_id


def test_get_approve_cancel_and_not_found_use_safe_contracts() -> None:
    gateway = FakeGateway()
    transactions = service(gateway)
    submitted = asyncio.run(transactions.submit(compilation(), "key"))

    view = asyncio.run(transactions.get(submitted.transaction_id))
    approved = asyncio.run(
        transactions.approve(
            submitted.transaction_id,
            {
                "step_id": "execute-1-shipment-track-read",
                "approved": True,
                "decided_by": "operator-a",
            },
        )
    )
    cancelled = asyncio.run(transactions.cancel(submitted.transaction_id))

    assert view.execution is not None and view.execution.status is ExecutionStatus.RUNNING
    assert approved.execution is not None
    assert cancelled.execution is not None
    assert gateway.approvals[0][1].decided_by == "operator-a"
    assert gateway.cancellations == [submitted.workflow_id]

    with pytest.raises(TransactionServiceError) as missing:
        asyncio.run(transactions.get("missing"))
    assert missing.value.code == "transaction_not_found"
    assert missing.value.status_code == 404
