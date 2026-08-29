from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC
from pathlib import Path

import pytest

from cargomesh.runtime.idempotency import (
    IdempotencyConflict,
    SQLiteSubmissionStore,
    SubmissionReservation,
    SubmissionState,
)

DIGEST = "sha256:" + "a" * 64


def _reserve(
    store: SQLiteSubmissionStore,
    *,
    transaction_id: str = "transaction-1",
    workflow_id: str = "workflow-1",
) -> SubmissionReservation:
    return store.reserve("tenant-1", "idem-1", transaction_id, workflow_id, DIGEST)


def test_reserve_replay_conflict_and_utc_timestamps() -> None:
    store = SQLiteSubmissionStore()

    first = _reserve(store)
    replay = _reserve(store, transaction_id="transaction-new", workflow_id="workflow-new")

    assert first.created
    assert first.state is SubmissionState.RESERVED
    assert first.created_at.tzinfo is UTC
    assert first.updated_at.tzinfo is UTC
    assert not replay.created
    assert replay.transaction_id == "transaction-1"
    assert replay.workflow_id == "workflow-1"
    with pytest.raises(IdempotencyConflict, match="different request") as error:
        store.reserve("tenant-1", "idem-1", "transaction-2", "workflow-2", "sha256:" + "b" * 64)
    assert "SELECT" not in str(error.value)


def test_state_changes_lookup_and_failed_start_retry_retains_ids() -> None:
    store = SQLiteSubmissionStore()
    first = _reserve(store)

    failed = store.mark_start_failed(first.transaction_id, "temporal_unavailable")
    retried = _reserve(store, transaction_id="transaction-new", workflow_id="workflow-new")
    started = store.mark_started(retried.transaction_id)
    lookup = store.lookup_by_transaction_id(first.transaction_id)

    assert failed.state is SubmissionState.START_FAILED
    assert failed.start_error_code == "temporal_unavailable"
    assert retried.state is SubmissionState.RESERVED
    assert not retried.created
    assert retried.transaction_id == first.transaction_id
    assert retried.workflow_id == first.workflow_id
    assert started.state is SubmissionState.STARTED
    assert lookup == started


def test_concurrent_reservations_create_only_one_stable_submission() -> None:
    store = SQLiteSubmissionStore()

    def reserve(index: int) -> SubmissionReservation:
        return _reserve(
            store,
            transaction_id=f"transaction-{index}",
            workflow_id=f"workflow-{index}",
        )

    with ThreadPoolExecutor(max_workers=8) as pool:
        reservations = list(pool.map(reserve, range(8)))

    assert sum(reservation.created for reservation in reservations) == 1
    assert len({reservation.transaction_id for reservation in reservations}) == 1
    assert len({reservation.workflow_id for reservation in reservations}) == 1
    assert {reservation.state for reservation in reservations} == {SubmissionState.RESERVED}


def test_file_store_persists_across_reopen(tmp_path: Path) -> None:
    database = tmp_path / "submission-index.sqlite3"
    first_store = SQLiteSubmissionStore(database)
    first = _reserve(first_store)
    first_store.mark_started(first.transaction_id)
    first_store.close()

    reopened = SQLiteSubmissionStore(database)
    persisted = reopened.lookup(first.transaction_id)

    assert persisted is not None
    assert persisted.transaction_id == first.transaction_id
    assert persisted.workflow_id == first.workflow_id
    assert persisted.business_digest == DIGEST
    assert persisted.state is SubmissionState.STARTED
    reopened.close()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("tenant_id", ""),
        ("idempotency_key", " " * 257),
        ("transaction_id", " transaction"),
        ("workflow_id", "w" * 257),
    ],
)
def test_reserve_validates_identifiers_and_key_lengths(field: str, value: str) -> None:
    store = SQLiteSubmissionStore()
    arguments = {
        "tenant_id": "tenant",
        "idempotency_key": "key",
        "transaction_id": "transaction",
        "workflow_id": "workflow",
        "business_digest": DIGEST,
    }
    arguments[field] = value

    with pytest.raises(ValueError):
        store.reserve(**arguments)
