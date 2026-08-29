import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from cargomesh.routing.models import (
    RouteCandidate,
    RouteHealthStatus,
    RouteOutcome,
    RouteOutcomeKind,
    RoutingPolicy,
)
from cargomesh.routing.store import (
    RouteOutcomeConflict,
    RouteOutcomeStoreError,
    SQLiteRouteOutcomeStore,
)


def _candidate() -> RouteCandidate:
    return RouteCandidate.issue(
        candidate_id="api-main",
        capability="shipment",
        adapter="api",
        operation="lookup",
        channel="API",
        baseline_success_bps=9000,
        expected_latency_ms=100,
        cost_micros=1,
        maximum_risk_class="READ_ONLY",
        maximum_data_classification="INTERNAL",
        maximum_verification_level="L2",
    )


def _policy(**values: object) -> RoutingPolicy:
    return RoutingPolicy.issue(policy_id="default", version="1.0.0", **values)


def test_empty_health_is_unknown_without_fabricated_metrics() -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    with SQLiteRouteOutcomeStore() as store:
        snapshot = store.health_snapshot("tenant-a", _candidate(), _policy(), now)
    assert snapshot.status.value == "UNKNOWN"
    assert snapshot.sample_count == 0
    assert snapshot.observed_success_bps is None
    assert snapshot.p95_latency_ms is None
    assert snapshot.last_outcome_at is None
    assert snapshot.circuit_open_until is None


def test_close_rejects_operations() -> None:
    store = SQLiteRouteOutcomeStore()
    store.close()
    with pytest.raises(RouteOutcomeStoreError) as error:
        store.get("tenant", "event")
    assert error.value.code == "store_closed"


def test_conflict_type_is_public() -> None:
    assert RouteOutcomeConflict.code == "route_outcome_conflict"


def _outcome(
    event_id: str,
    *,
    occurred_at: datetime,
    kind: RouteOutcomeKind = RouteOutcomeKind.RETRYABLE_FAILURE,
    latency_ms: int = 10,
    tenant_id: str = "tenant-a",
) -> RouteOutcome:
    return RouteOutcome.issue(
        event_id=event_id,
        tenant_id=tenant_id,
        transaction_id=f"txn-{event_id}",
        step_id="read",
        candidate_id="api-main",
        temporal_attempt=1,
        kind=kind,
        latency_ms=latency_ms,
        failure_code=None if kind is RouteOutcomeKind.SUCCESS else "api_timeout",
        occurred_at=occurred_at,
    )


def test_append_is_idempotent_tenant_scoped_and_conflict_safe() -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    with SQLiteRouteOutcomeStore() as store:
        original = _outcome("event-1", occurred_at=now)
        assert store.append(original) == original
        assert store.append(original) == original
        assert store.get("tenant-a", "event-1") == original
        assert store.get("tenant-b", "event-1") is None
        different = _outcome("event-1", occurred_at=now, latency_ms=11)
        with pytest.raises(RouteOutcomeConflict):
            store.append(different)


def test_health_uses_minimum_samples_nearest_rank_p95_and_cooldown() -> None:
    now = datetime(2026, 1, 1, 0, 1, tzinfo=UTC)
    policy = _policy(
        minimum_history_samples=3,
        circuit_failure_threshold=3,
        circuit_cooldown_seconds=60,
    )
    with SQLiteRouteOutcomeStore() as store:
        for index, latency in enumerate((10, 20, 30), start=1):
            store.append(
                _outcome(
                    f"failure-{index}",
                    occurred_at=now - timedelta(seconds=4 - index),
                    latency_ms=latency,
                )
            )
        opened = store.health_snapshot("tenant-a", _candidate(), policy, now)
        assert opened.status is RouteHealthStatus.UNAVAILABLE
        assert opened.consecutive_failures == 3
        assert opened.p95_latency_ms == 30
        assert opened.observed_success_bps == 0
        assert opened.circuit_open_until == now + timedelta(seconds=59)

        cooled = store.health_snapshot(
            "tenant-a", _candidate(), policy, now + timedelta(seconds=61)
        )
        assert cooled.status is RouteHealthStatus.DEGRADED
        assert cooled.circuit_open_until is None

        insufficient = store.health_snapshot(
            "tenant-a",
            _candidate(),
            _policy(
                minimum_history_samples=4,
                circuit_failure_threshold=3,
                circuit_cooldown_seconds=60,
            ),
            now,
        )
        assert insufficient.status is RouteHealthStatus.UNKNOWN
        assert insufficient.circuit_open_until is None


def test_database_triggers_are_append_only_and_reads_detect_tampering(
    tmp_path: Path,
) -> None:
    database = tmp_path / "routing.sqlite3"
    now = datetime(2026, 1, 1, tzinfo=UTC)
    with SQLiteRouteOutcomeStore(database) as store:
        store.append(_outcome("event-1", occurred_at=now))
        connection = sqlite3.connect(database)
        try:
            with pytest.raises(sqlite3.IntegrityError, match="append-only"):
                connection.execute(
                    "UPDATE route_outcomes SET latency_ms=99 WHERE event_id='event-1'"
                )
            with pytest.raises(sqlite3.IntegrityError, match="append-only"):
                connection.execute("DELETE FROM route_outcomes WHERE event_id='event-1'")
            connection.execute("DROP TRIGGER route_outcomes_no_update")
            connection.execute(
                "UPDATE route_outcomes SET outcome_json='{}' WHERE event_id='event-1'"
            )
            connection.commit()
        finally:
            connection.close()
        with pytest.raises(RouteOutcomeStoreError) as error:
            store.get("tenant-a", "event-1")
        assert error.value.code == "route_outcome_integrity_error"
