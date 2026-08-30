from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from cargomesh.runner.registry import SQLiteRunnerRegistry
from cargomesh.runner.task_store import SQLiteTaskStore, TaskLeaseError
from cargomesh.runner.tasks import RecoveryAction, RunnerHeartbeat, RunnerTask

NOW = datetime(2040, 1, 2, tzinfo=UTC)
DIGEST = "sha256:" + "a" * 64


def enrolled_runner(registry: SQLiteRunnerRegistry):
    issue = registry.issue_challenge(
        "tenant-a", "production", "private", now=NOW
    )
    return registry.enroll(
        issue.challenge.challenge_id,
        issue.token,
        tenant_id="tenant-a",
        environment_id="production",
        runner_pool="private",
        public_key_digest=DIGEST,
        capabilities=("shipment.track.read",),
        platform="linux.amd64",
        version="0.8.0",
        now=NOW,
    )


def task(task_id: str = "task-1") -> RunnerTask:
    return RunnerTask.issue(
        task_id=task_id,
        tenant_id="tenant-a",
        environment_id="production",
        runner_pool="private",
        capability="shipment.track.read",
        execution_id="execution-1",
        adapter_digest=DIGEST,
        policy_digest=DIGEST,
        input_digest=DIGEST,
        created_at=NOW,
        deadline=NOW + timedelta(minutes=10),
        payload={"business_digest": DIGEST},
    )


def test_registry_authorizes_exact_active_scope_for_task_leasing() -> None:
    registry = SQLiteRunnerRegistry()
    runner = enrolled_runner(registry)
    store = SQLiteTaskStore(authorizer=registry, lease_seconds=10)
    store.enqueue(task())

    lease = store.acquire(runner.runner_id, now=NOW)
    assert lease is not None
    assert lease.fencing_token == 1

    registry.mark_offline(
        runner.runner_id,
        tenant_id="tenant-a",
        environment_id="production",
        runner_pool="private",
        now=NOW + timedelta(seconds=1),
    )
    store.enqueue(task("task-2"))
    with pytest.raises(TaskLeaseError) as caught:
        store.acquire(runner.runner_id, now=NOW + timedelta(seconds=1))
    assert caught.value.code == "runner_unauthorized"


def test_unknown_or_post_effect_expiry_never_silently_reexecutes() -> None:
    registry = SQLiteRunnerRegistry()
    runner = enrolled_runner(registry)
    store = SQLiteTaskStore(authorizer=registry, lease_seconds=1)
    store.enqueue(task())
    lease = store.acquire(runner.runner_id, now=NOW)
    assert lease is not None
    heartbeat = RunnerHeartbeat.issue(
        task_id="task-1",
        runner_id=runner.runner_id,
        fencing_token=lease.fencing_token,
        step_id="submit",
        effect_boundary=True,
        checkpoint_digest=DIGEST,
        occurred_at=NOW + timedelta(milliseconds=100),
    )
    store.heartbeat(heartbeat, now=NOW + timedelta(milliseconds=100))

    assert store.acquire(runner.runner_id, now=NOW + timedelta(seconds=2)) is None
    directive = store.recover(lease, now=NOW + timedelta(seconds=2))
    assert directive.action is RecoveryAction.VERIFY_OR_RECONCILE
    assert directive.reason_code == "lease_expired_post_effect"
    assert store.acquire(runner.runner_id, now=NOW + timedelta(seconds=3)) is None
