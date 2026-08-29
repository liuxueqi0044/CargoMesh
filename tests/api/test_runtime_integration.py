from __future__ import annotations

from fastapi.testclient import TestClient

from cargomesh.api.main import create_app
from cargomesh.application.transactions import TransactionService
from cargomesh.runtime import (
    ApprovalDecision,
    ExecutionPlan,
    ExecutionSnapshot,
    ExecutionStatus,
)
from cargomesh.runtime.idempotency import SQLiteSubmissionStore
from cargomesh.runtime.planner import synthetic_tracking_planner


class Gateway:
    def __init__(self) -> None:
        self.transaction_id = ""
        self.approvals: list[ApprovalDecision] = []

    async def start(self, plan: ExecutionPlan, *, workflow_id: str) -> None:
        del workflow_id
        self.transaction_id = plan.transaction_id

    async def get_snapshot(self, workflow_id: str) -> ExecutionSnapshot:
        return ExecutionSnapshot(
            transaction_id=self.transaction_id,
            workflow_id=workflow_id,
            status=ExecutionStatus.WAITING_APPROVAL,
            current_step_id="execute-1-shipment-track-read",
            awaiting_approval_step_id="execute-1-shipment-track-read",
        )

    async def approve(self, workflow_id: str, decision: ApprovalDecision) -> None:
        del workflow_id
        self.approvals.append(decision)

    async def cancel(self, workflow_id: str) -> None:
        del workflow_id


def test_compiler_submission_store_runtime_and_http_are_wired_end_to_end() -> None:
    gateway = Gateway()
    service = TransactionService(
        planner=synthetic_tracking_planner(),
        submissions=SQLiteSubmissionStore(),
        gateway=gateway,
    )
    client = TestClient(create_app(transaction_service=service))
    body = {
        "sourceSchemaVersion": "cargomesh.transaction/v1",
        "payload": {
            "tenant_id": "tenant-a",
            "external_reference": "customer-1",
            "subject": {"carrier_booking_reference": "CBR-1"},
        },
    }

    created = client.post(
        "/v1/transactions", json=body, headers={"Idempotency-Key": "customer-request-1"}
    )
    replay = client.post(
        "/v1/transactions", json=body, headers={"Idempotency-Key": "customer-request-1"}
    )
    transaction_id = created.json()["transaction_id"]
    status = client.get(f"/v1/transactions/{transaction_id}")
    approval = client.post(
        f"/v1/transactions/{transaction_id}/approval",
        json={
            "step_id": "execute-1-shipment-track-read",
            "approved": True,
            "decided_by": "operator-a",
        },
    )

    assert created.status_code == 202
    assert replay.status_code == 200
    assert replay.json()["transaction_id"] == transaction_id
    assert status.json()["execution"]["status"] == "WAITING_APPROVAL"
    assert approval.status_code == 200
    assert gateway.approvals[0].decided_by == "operator-a"
