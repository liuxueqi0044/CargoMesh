"""Append-only SQLite route outcome ledger and health aggregation."""

from __future__ import annotations

import sqlite3
from contextlib import suppress
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Protocol

from cargomesh.routing.models import (
    RouteCandidate,
    RouteHealthSnapshot,
    RouteHealthStatus,
    RouteOutcome,
    RouteOutcomeKind,
    RoutingPolicy,
)


class RouteOutcomeConflict(RuntimeError):
    code = "route_outcome_conflict"


class RouteOutcomeStoreError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code, self.message = code, message


class RouteOutcomeStore(Protocol):
    def append(self, outcome: RouteOutcome) -> RouteOutcome: ...
    def get(self, tenant_id: str, event_id: str) -> RouteOutcome | None: ...
    def replay(
        self, tenant_id: str, candidate: RouteCandidate, limit: int
    ) -> tuple[RouteOutcome, ...]: ...
    def health_snapshot(
        self,
        tenant_id: str,
        candidate: RouteCandidate,
        policy: RoutingPolicy,
        evaluated_at: datetime,
    ) -> RouteHealthSnapshot: ...
    def close(self) -> None: ...


class SQLiteRouteOutcomeStore:
    def __init__(self, database: str | Path = ":memory:") -> None:
        self._closed = False
        self._connection = sqlite3.connect(str(database), isolation_level=None)
        self._connection.row_factory = sqlite3.Row
        if str(database) != ":memory:":
            self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute("PRAGMA foreign_keys=ON")
        self._connection.execute(
            "CREATE TABLE IF NOT EXISTS route_outcomes ("
            "tenant_id TEXT NOT NULL,event_id TEXT NOT NULL,"
            "candidate_id TEXT NOT NULL,occurred_at TEXT NOT NULL,"
            "kind TEXT NOT NULL,latency_ms INTEGER NOT NULL,"
            "outcome_digest TEXT NOT NULL,outcome_json TEXT NOT NULL,"
            "PRIMARY KEY(tenant_id,event_id))"
        )
        self._connection.executescript(
            "CREATE TRIGGER IF NOT EXISTS route_outcomes_no_update "
            "BEFORE UPDATE ON route_outcomes BEGIN SELECT RAISE(ABORT,"
            "'route outcomes are append-only'); END; "
            "CREATE TRIGGER IF NOT EXISTS route_outcomes_no_delete "
            "BEFORE DELETE ON route_outcomes BEGIN SELECT RAISE(ABORT,"
            "'route outcomes are append-only'); END;"
        )

    def append(self, outcome: RouteOutcome) -> RouteOutcome:
        self._ensure_open()
        try:
            payload = outcome.model_dump_json(exclude_none=True)
            c = self._connection
            c.execute("BEGIN IMMEDIATE")
            row = c.execute(
                "SELECT outcome_digest,outcome_json FROM route_outcomes "
                "WHERE tenant_id=? AND event_id=?",
                (outcome.tenant_id, outcome.event_id),
            ).fetchone()
            if row is not None:
                if row["outcome_digest"] != outcome.outcome_digest:
                    raise RouteOutcomeConflict(
                        "route outcome event id already contains different content"
                    )
                c.commit()
                return self._decode(row["outcome_json"], row["outcome_digest"])
            c.execute(
                "INSERT INTO route_outcomes VALUES (?,?,?,?,?,?,?,?)",
                (
                    outcome.tenant_id,
                    outcome.event_id,
                    outcome.candidate_id,
                    outcome.occurred_at.isoformat(),
                    outcome.kind.value,
                    outcome.latency_ms,
                    outcome.outcome_digest,
                    payload,
                ),
            )
            c.commit()
            return outcome
        except RouteOutcomeConflict:
            _rollback(self._connection)
            raise
        except sqlite3.Error as exc:
            _rollback(self._connection)
            raise RouteOutcomeStoreError(
                "route_outcome_store_unavailable", "Route outcome store is unavailable"
            ) from exc
        except Exception as exc:
            _rollback(self._connection)
            raise RouteOutcomeStoreError(
                "invalid_route_outcome", "Route outcome is invalid"
            ) from exc

    def get(self, tenant_id: str, event_id: str) -> RouteOutcome | None:
        self._ensure_open()
        try:
            row = self._connection.execute(
                "SELECT outcome_digest,outcome_json FROM route_outcomes "
                "WHERE tenant_id=? AND event_id=?",
                (tenant_id, event_id),
            ).fetchone()
        except sqlite3.Error as exc:
            raise RouteOutcomeStoreError(
                "route_outcome_store_unavailable", "Route outcome store is unavailable"
            ) from exc
        return None if row is None else self._decode(row["outcome_json"], row["outcome_digest"])

    def replay(
        self, tenant_id: str, candidate: RouteCandidate, limit: int
    ) -> tuple[RouteOutcome, ...]:
        self._ensure_open()
        try:
            rows = self._connection.execute(
                "SELECT outcome_digest,outcome_json FROM route_outcomes "
                "WHERE tenant_id=? AND candidate_id=? "
                "ORDER BY occurred_at DESC,event_id DESC LIMIT ?",
                (tenant_id, candidate.candidate_id, max(0, limit)),
            ).fetchall()
        except sqlite3.Error as exc:
            raise RouteOutcomeStoreError(
                "route_outcome_store_unavailable", "Route outcome store is unavailable"
            ) from exc
        return tuple(self._decode(row["outcome_json"], row["outcome_digest"]) for row in rows)

    def health_snapshot(
        self,
        tenant_id: str,
        candidate: RouteCandidate,
        policy: RoutingPolicy,
        evaluated_at: datetime,
    ) -> RouteHealthSnapshot:
        outcomes = self.replay(tenant_id, candidate, policy.history_window_size)
        sample = len(outcomes)
        success = sum(x.kind is RouteOutcomeKind.SUCCESS for x in outcomes)
        retryable = sum(x.kind is RouteOutcomeKind.RETRYABLE_FAILURE for x in outcomes)
        terminal = sum(x.kind is RouteOutcomeKind.TERMINAL_FAILURE for x in outcomes)
        if not outcomes:
            return RouteHealthSnapshot(
                tenant_id=tenant_id,
                candidate_id=candidate.candidate_id,
                evaluated_at=evaluated_at,
                status=RouteHealthStatus.UNKNOWN,
                sample_count=0,
                success_count=0,
                retryable_failure_count=0,
                terminal_failure_count=0,
                consecutive_failures=0,
            )
        latencies = sorted(x.latency_ms for x in outcomes)
        p95 = latencies[(len(latencies) * 95 + 99) // 100 - 1]
        last = outcomes[0].occurred_at
        consecutive = 0
        for item in outcomes:
            if item.kind is RouteOutcomeKind.SUCCESS:
                break
            consecutive += 1
        expiry = last + timedelta(seconds=policy.circuit_cooldown_seconds)
        in_cooldown = expiry > evaluated_at
        if sample < policy.minimum_history_samples:
            status = RouteHealthStatus.UNKNOWN
        elif consecutive >= policy.circuit_failure_threshold and in_cooldown:
            status = RouteHealthStatus.UNAVAILABLE
        elif retryable or terminal:
            status = RouteHealthStatus.DEGRADED
        else:
            status = RouteHealthStatus.HEALTHY
        return RouteHealthSnapshot(
            tenant_id=tenant_id,
            candidate_id=candidate.candidate_id,
            evaluated_at=evaluated_at,
            status=status,
            sample_count=sample,
            success_count=success,
            retryable_failure_count=retryable,
            terminal_failure_count=terminal,
            consecutive_failures=consecutive,
            observed_success_bps=success * 10000 // sample,
            p95_latency_ms=p95,
            last_outcome_at=last,
            circuit_open_until=(
                expiry if status is RouteHealthStatus.UNAVAILABLE else None
            ),
        )

    def _decode(self, payload: str, digest: str) -> RouteOutcome:
        try:
            outcome = RouteOutcome.model_validate_json(payload)
            if outcome.outcome_digest != digest:
                raise ValueError("outcome digest mismatch")
            return outcome
        except Exception as exc:
            raise RouteOutcomeStoreError(
                "route_outcome_integrity_error", "Stored route outcome is invalid"
            ) from exc

    def close(self) -> None:
        if not self._closed:
            self._connection.close()
            self._closed = True

    def __enter__(self) -> SQLiteRouteOutcomeStore:
        self._ensure_open()
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

    def _ensure_open(self) -> None:
        if self._closed:
            raise RouteOutcomeStoreError("store_closed", "Route outcome store is closed")


def _rollback(connection: sqlite3.Connection) -> None:
    with suppress(sqlite3.Error):
        connection.rollback()
