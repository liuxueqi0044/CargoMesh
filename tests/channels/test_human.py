from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from cargomesh.channels.human import (
    AttendedTask,
    AttendedTaskConflict,
    AttendedTaskError,
    AttendedTaskStatus,
    SQLiteAttendedTaskStore,
    to_evidence_observation,
)

NOW = datetime(2040, 1, 2, 3, 4, 5, tzinfo=UTC)


def task(**overrides: object) -> AttendedTask:
    values: dict[str, object] = {
        "task_id": "human-task-1",
        "tenant_id": "tenant-a",
        "environment_id": "production",
        "transaction_id": "txn-1",
        "step_id": "attended.check",
        "capability": "booking.review",
        "instructions": {"instruction": "Confirm the booking status."},
        "required_claim_names": ("booking.status",),
        "created_at": NOW,
    }
    values.update(overrides)
    return AttendedTask.issue(**values)


def test_create_idempotency_and_cross_tenant_hiding() -> None:
    store = SQLiteAttendedTaskStore()
    first = store.create(task())
    replay = store.create(task())

    assert first == replay
    assert store.get("human-task-1", tenant_id="tenant-b", environment_id="production") is None
    with pytest.raises(AttendedTaskError) as cross_tenant:
        store.claim(
            "human-task-1",
            tenant_id="tenant-b",
            environment_id="production",
            principal_ref="principal-b",
            now=NOW,
        )
    assert cross_tenant.value.code == "attended_task_not_found"
    with pytest.raises(AttendedTaskConflict):
        store.create(task(instructions={"instruction": "changed"}))


def test_claim_competition_expiry_and_fencing() -> None:
    store = SQLiteAttendedTaskStore(lease_seconds=2)
    store.create(task())
    first = store.claim(
        "human-task-1",
        tenant_id="tenant-a",
        environment_id="production",
        principal_ref="principal-a",
        now=NOW,
    )
    with pytest.raises(AttendedTaskError) as busy:
        store.claim(
            "human-task-1",
            tenant_id="tenant-a",
            environment_id="production",
            principal_ref="principal-b",
            now=NOW + timedelta(seconds=1),
        )
    second = store.claim(
        "human-task-1",
        tenant_id="tenant-a",
        environment_id="production",
        principal_ref="principal-b",
        now=NOW + timedelta(seconds=2),
    )

    assert busy.value.code == "attended_task_claimed"
    assert second.fencing_token == first.fencing_token + 1
    with pytest.raises(AttendedTaskError) as stale:
        store.complete(first, {"booking.status": "RECEIVED"}, now=NOW + timedelta(seconds=2))
    assert stale.value.code == "attended_task_stale_lease"


def test_completion_replay_conflict_and_evidence_projection() -> None:
    store = SQLiteAttendedTaskStore()
    store.create(task())
    lease = store.claim(
        "human-task-1",
        tenant_id="tenant-a",
        environment_id="production",
        principal_ref="principal-a",
        now=NOW,
    )
    complete = store.complete(
        lease, {"booking.status": "RECEIVED"}, note="reviewed", now=NOW + timedelta(seconds=1)
    )
    replay = store.complete(
        lease, {"booking.status": "RECEIVED"}, note="reviewed", now=NOW + timedelta(seconds=2)
    )
    evidence = to_evidence_observation(complete, evidence_id="evidence-1")

    assert complete.status is AttendedTaskStatus.COMPLETED
    assert replay == complete
    assert complete.note_digest is not None
    assert "reviewed" not in complete.model_dump_json()
    assert evidence.channel.value == "SYSTEM_RECORD"
    assert evidence.synthetic is True
    assert evidence.source_system == "attended.human"
    assert evidence.claims == {"booking.status": "RECEIVED"}
    with pytest.raises(AttendedTaskError) as conflict:
        store.complete(lease, {"booking.status": "CANCELLED"}, now=NOW + timedelta(seconds=2))
    assert conflict.value.code == "attended_task_completion_conflict"


def test_rejection_and_secret_like_material_fail_closed() -> None:
    with pytest.raises(ValueError):
        task(instructions={"api_token": "do not accept"})
    store = SQLiteAttendedTaskStore()
    store.create(task())
    lease = store.claim(
        "human-task-1",
        tenant_id="tenant-a",
        environment_id="production",
        principal_ref="principal-a",
        now=NOW,
    )
    rejected = store.complete(
        lease, {"booking.status": "DECLINED"}, rejected=True, now=NOW + timedelta(seconds=1)
    )
    assert rejected.status is AttendedTaskStatus.REJECTED
    with pytest.raises(AttendedTaskError) as content_output:
        store.complete(
            lease,
            {"attachment.body": "not permitted"},
            rejected=True,
            now=NOW + timedelta(seconds=2),
        )
    assert content_output.value.code == "attended_task_claims_invalid"
    with pytest.raises(AttendedTaskError):
        to_evidence_observation(rejected, evidence_id="evidence-2")
