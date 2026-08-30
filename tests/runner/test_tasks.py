from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest

from cargomesh.runner.task_store import (
    SQLiteTaskStore,
    TaskConflict,
    TaskLeaseError,
)
from cargomesh.runner.tasks import (
    RecoveryAction,
    RunnerHeartbeat,
    RunnerResultReceipt,
    RunnerTask,
)

BASE = datetime(2026, 1, 1, tzinfo=UTC)
DIGEST = "sha256:" + "1" * 64
RESULT = "sha256:" + "2" * 64
CHECKPOINT = "sha256:" + "3" * 64


class Authorizer:
    def __init__(self, allowed: bool = True) -> None:
        self.allowed = allowed
        self.calls: list[tuple[str, str, str, str, str]] = []

    def authorize(
        self, runner_id: str, tenant_id: str, environment_id: str, runner_pool: str, capability: str
    ) -> bool:
        self.calls.append((runner_id, tenant_id, environment_id, runner_pool, capability))
        return self.allowed


def task(
    *, payload: dict[str, object] | None = None, deadline: datetime | None = None
) -> RunnerTask:
    return RunnerTask.issue(
        task_id="task-1",
        tenant_id="tenant-a",
        environment_id="production",
        runner_pool="private",
        capability="shipment.read",
        execution_id="execution-1",
        adapter_digest=DIGEST,
        policy_digest=DIGEST,
        input_digest=DIGEST,
        created_at=BASE,
        deadline=deadline or BASE + timedelta(hours=1),
        payload=payload or {"reference": "safe"},
    )


def receipt(token: int, *, result_digest: str = RESULT) -> RunnerResultReceipt:
    return RunnerResultReceipt.issue(
        task_id="task-1",
        runner_id="runner-1",
        fencing_token=token,
        result_digest=result_digest,
        completed_at=BASE + timedelta(seconds=2),
    )


def heartbeat(
    token: int, *, effect: bool | None, checkpoint: str | None = CHECKPOINT
) -> RunnerHeartbeat:
    return RunnerHeartbeat.issue(
        task_id="task-1",
        runner_id="runner-1",
        fencing_token=token,
        step_id="step-1",
        effect_boundary=effect,
        checkpoint_digest=checkpoint,
        occurred_at=BASE + timedelta(seconds=1),
    )


@pytest.mark.parametrize("key", ["password", "api_token", "nested"])
def test_task_payload_rejects_secret_like_keys(key: str) -> None:
    payload: dict[str, object] = {key: "not persisted"}
    if key == "nested":
        payload = {"nested": {"authorization": "value"}}
    with pytest.raises(ValueError):
        task(payload=payload)


def test_task_and_lease_are_digest_bound_and_authorized() -> None:
    authorizer = Authorizer()
    with SQLiteTaskStore(authorizer=authorizer, lease_seconds=10) as store:
        original = task()
        assert store.enqueue(original) == original
        assert store.enqueue(original) == original
        lease = store.acquire("runner-1", now=BASE)
        assert lease is not None
        assert lease.fencing_token == 1
        assert authorizer.calls == [
            ("runner-1", "tenant-a", "production", "private", "shipment.read")
        ]
        assert store.renew(lease, now=BASE + timedelta(seconds=1)).fencing_token == 1


def test_concurrent_acquisition_has_one_winner() -> None:
    authorizer = Authorizer()
    store = SQLiteTaskStore(authorizer=authorizer, lease_seconds=10)
    store.enqueue(task())
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(
            pool.map(lambda _: store.acquire("runner-1", now=BASE), range(2))
        )
    assert sum(result is not None for result in results) == 1
    store.close()


def test_expiry_reacquire_fences_stale_lease() -> None:
    with SQLiteTaskStore(authorizer=Authorizer(), lease_seconds=1) as store:
        store.enqueue(task())
        first = store.acquire("runner-1", now=BASE)
        assert first is not None
        store.heartbeat(heartbeat(1, effect=False), now=BASE + timedelta(milliseconds=1))
        store.recover(first, now=BASE + timedelta(seconds=2))
        second = store.acquire("runner-1", now=BASE + timedelta(seconds=2))
        assert second is not None
        assert second.fencing_token == 2
        with pytest.raises(TaskLeaseError) as raised:
            store.renew(first, now=BASE + timedelta(seconds=2))
        assert raised.value.code in {"stale_lease", "lease_expired"}


def test_recovery_is_deterministic_before_effect_and_after_effect() -> None:
    with SQLiteTaskStore(authorizer=Authorizer(), lease_seconds=1) as store:
        store.enqueue(task())
        first = store.acquire("runner-1", now=BASE)
        assert first is not None
        store.heartbeat(heartbeat(1, effect=False), now=BASE + timedelta(milliseconds=1))
        directive = store.recover("task-1", now=BASE + timedelta(seconds=2))
        assert directive.action is RecoveryAction.RETRY_FROM_CHECKPOINT
        assert directive.checkpoint_digest == CHECKPOINT
        reacquired = store.acquire("runner-1", now=BASE + timedelta(seconds=3))
        assert reacquired is not None and reacquired.fencing_token == 2

        store.heartbeat(heartbeat(2, effect=True), now=BASE + timedelta(seconds=3, milliseconds=1))
        post_effect = store.recover("task-1", now=BASE + timedelta(seconds=5))
        assert post_effect.action is RecoveryAction.VERIFY_OR_RECONCILE


def test_ambiguous_expiry_requires_verification() -> None:
    with SQLiteTaskStore(authorizer=Authorizer(), lease_seconds=1) as store:
        store.enqueue(task())
        lease = store.acquire("runner-1", now=BASE)
        assert lease is not None
        directive = store.recover(lease, now=BASE + timedelta(seconds=2))
        assert directive.action is RecoveryAction.VERIFY_OR_RECONCILE


def test_result_receipt_is_idempotent_but_conflicting_results_fail() -> None:
    with SQLiteTaskStore(authorizer=Authorizer(), lease_seconds=10) as store:
        store.enqueue(task())
        lease = store.acquire("runner-1", now=BASE)
        assert lease is not None
        expected = receipt(lease.fencing_token)
        assert store.complete(expected) == expected
        assert store.complete(expected) == expected
        with pytest.raises(TaskConflict):
            store.complete(receipt(lease.fencing_token, result_digest=DIGEST))


def test_wrong_scope_authorization_and_missing_authorizer_fail_closed() -> None:
    with SQLiteTaskStore(authorizer=Authorizer(allowed=False)) as store:
        store.enqueue(task())
        with pytest.raises(TaskLeaseError) as raised:
            store.acquire("runner-1", now=BASE)
        assert raised.value.code == "runner_unauthorized"

    with SQLiteTaskStore() as store:
        store.enqueue(task())
        with pytest.raises(TaskLeaseError) as raised:
            store.acquire("runner-1", now=BASE)
        assert raised.value.code == "runner_authorization_unavailable"


def test_expired_completion_and_stale_heartbeat_are_rejected_without_secret_echo() -> None:
    with SQLiteTaskStore(authorizer=Authorizer(), lease_seconds=1) as store:
        store.enqueue(task())
        lease = store.acquire("runner-1", now=BASE)
        assert lease is not None
        with pytest.raises(TaskLeaseError) as raised:
            store.complete(receipt(lease.fencing_token))
        assert "integration-only-secret" not in str(raised.value)
        assert "integration-only-secret" not in repr(raised.value)
        with pytest.raises(TaskLeaseError):
            store.heartbeat(
                heartbeat(lease.fencing_token, effect=False),
                now=BASE + timedelta(seconds=2),
            )
