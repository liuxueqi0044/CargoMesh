"""Atomic SQLite task queue, lease fencing, heartbeat, and result receipts."""

from __future__ import annotations

import sqlite3
import threading
from contextlib import suppress
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

from .tasks import (
    RecoveryAction,
    RecoveryDirective,
    RunnerAuthorizer,
    RunnerHeartbeat,
    RunnerResultReceipt,
    RunnerTask,
    TaskLease,
)


class TaskConflict(RuntimeError):
    code = "task_conflict"


class TaskNotFound(RuntimeError):
    code = "task_not_found"


class TaskLeaseError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class TaskStoreError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class SQLiteTaskStore:
    """Single-node reference transport; SQLite contains no secret material."""

    SCHEMA_VERSION = 1

    def __init__(
        self,
        database: str | Path = ":memory:",
        *,
        authorizer: RunnerAuthorizer | None = None,
        lease_seconds: float = 30.0,
    ) -> None:
        if lease_seconds <= 0 or lease_seconds > 3600:
            raise ValueError("lease_seconds is out of bounds")
        self._closed = False
        self._lock = threading.RLock()
        self._database = str(database)
        self._authorizer = authorizer
        self._lease_seconds = lease_seconds
        try:
            self._connection = sqlite3.connect(
                self._database, isolation_level=None, check_same_thread=False, timeout=10
            )
            self._connection.row_factory = sqlite3.Row
            if self._database != ":memory:":
                self._connection.execute("PRAGMA journal_mode=WAL")
            self._connection.execute("PRAGMA foreign_keys=ON")
            self._connection.execute("PRAGMA busy_timeout=10000")
            self._initialize_schema()
        except sqlite3.Error as exc:
            raise TaskStoreError("task_store_unavailable", "Task store is unavailable") from exc

    def _initialize_schema(self) -> None:
        c = self._connection
        c.execute(
            "CREATE TABLE IF NOT EXISTS runner_task_schema_version "
            "(component TEXT PRIMARY KEY, version INTEGER NOT NULL)"
        )
        row = c.execute(
            "SELECT version FROM runner_task_schema_version WHERE component=?",
            ("cargomesh.runner-task-store/v1",),
        ).fetchone()
        if row is not None and row["version"] != self.SCHEMA_VERSION:
            raise TaskStoreError("task_schema_unsupported", "Unsupported task schema")
        c.execute(
            "INSERT OR IGNORE INTO runner_task_schema_version(component,version) VALUES (?,?)",
            ("cargomesh.runner-task-store/v1", self.SCHEMA_VERSION),
        )
        c.execute(
            """CREATE TABLE IF NOT EXISTS runner_tasks (
                task_id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                environment_id TEXT NOT NULL,
                runner_pool TEXT NOT NULL,
                capability TEXT NOT NULL,
                task_digest TEXT NOT NULL,
                task_json TEXT NOT NULL,
                state TEXT NOT NULL,
                runner_id TEXT,
                fencing_token INTEGER NOT NULL DEFAULT 0,
                lease_acquired_at TEXT,
                lease_expires_at TEXT,
                heartbeat_json TEXT,
                receipt_json TEXT
            )"""
        )

    def enqueue(self, task: RunnerTask) -> RunnerTask:
        self._ensure_open()
        value = self._validate_task(task)
        with self._lock:
            c = self._connection
            try:
                c.execute("BEGIN IMMEDIATE")
                row = c.execute(
                    "SELECT * FROM runner_tasks WHERE task_id=?", (value.task_id,)
                ).fetchone()
                if row is not None:
                    current = self._decode_task(row)
                    if current.task_digest != value.task_digest:
                        raise TaskConflict("task id already contains different content")
                    c.commit()
                    return current
                c.execute(
                    """INSERT INTO runner_tasks
                    (task_id,tenant_id,environment_id,runner_pool,capability,task_digest,
                     task_json,state,runner_id,fencing_token,lease_expires_at,heartbeat_json,receipt_json)
                    VALUES (?,?,?,?,?,?,?,'QUEUED',NULL,0,NULL,NULL,NULL)""",
                    (
                        value.task_id,
                        value.tenant_id,
                        value.environment_id,
                        value.runner_pool,
                        value.capability,
                        value.task_digest,
                        value.model_dump_json(),
                    ),
                )
                c.commit()
                return value
            except (TaskConflict, TaskStoreError):
                _rollback(c)
                raise
            except sqlite3.Error as exc:
                _rollback(c)
                raise TaskStoreError("task_store_unavailable", "Task store is unavailable") from exc

    put = enqueue

    def acquire(
        self, runner_id: str, *, now: datetime | None = None
    ) -> TaskLease | None:
        self._ensure_open()
        acquired_at = _clock(now)
        with self._lock:
            c = self._connection
            try:
                c.execute("BEGIN IMMEDIATE")
                row = c.execute(
                    "SELECT * FROM runner_tasks WHERE state='QUEUED' "
                    "ORDER BY task_id LIMIT 1",
                ).fetchone()
                if row is None:
                    c.commit()
                    return None
                task = self._decode_task(row)
                if task.deadline <= acquired_at:
                    c.execute(
                        "UPDATE runner_tasks SET state='EXPIRED' WHERE task_id=?",
                        (task.task_id,),
                    )
                    c.commit()
                    return None
                if self._authorizer is None:
                    raise TaskLeaseError(
                        "runner_authorization_unavailable", "Runner authorization is unavailable"
                    )
                try:
                    authorized = self._authorizer.authorize(
                        runner_id,
                        task.tenant_id,
                        task.environment_id,
                        task.runner_pool,
                        task.capability,
                    )
                except Exception as exc:
                    raise TaskLeaseError(
                        "runner_authorization_unavailable", "Runner authorization is unavailable"
                    ) from exc
                if not authorized:
                    raise TaskLeaseError("runner_unauthorized", "Runner is not authorized")
                token = int(row["fencing_token"]) + 1
                lease = TaskLease.issue(
                    task_id=task.task_id,
                    runner_id=runner_id,
                    fencing_token=token,
                    acquired_at=acquired_at,
                    lease_expires_at=acquired_at + timedelta(seconds=self._lease_seconds),
                )
                c.execute(
                    "UPDATE runner_tasks SET state='LEASED',runner_id=?,fencing_token=?,"
                    "lease_acquired_at=?,lease_expires_at=?,heartbeat_json=NULL WHERE task_id=?",
                    (
                        runner_id,
                        token,
                        _format(lease.acquired_at),
                        _format(lease.lease_expires_at),
                        task.task_id,
                    ),
                )
                c.commit()
                return lease
            except (TaskLeaseError, TaskStoreError):
                _rollback(c)
                raise
            except sqlite3.Error as exc:
                _rollback(c)
                raise TaskStoreError("task_store_unavailable", "Task store is unavailable") from exc

    def renew(self, lease: TaskLease, *, now: datetime | None = None) -> TaskLease:
        self._ensure_open()
        lease = self._validate_lease(lease)
        timestamp = _clock(now)
        with self._lock:
            c = self._connection
            try:
                c.execute("BEGIN IMMEDIATE")
                row = self._require_row(c, lease.task_id)
                self._check_lease(row, lease, timestamp)
                renewed = TaskLease.issue(
                    task_id=lease.task_id,
                    runner_id=lease.runner_id,
                    fencing_token=lease.fencing_token,
                    acquired_at=lease.acquired_at,
                    lease_expires_at=timestamp + timedelta(seconds=self._lease_seconds),
                )
                c.execute(
                    "UPDATE runner_tasks SET lease_expires_at=? WHERE task_id=?",
                    (_format(renewed.lease_expires_at), lease.task_id),
                )
                c.commit()
                return renewed
            except (TaskLeaseError, TaskNotFound, TaskStoreError):
                _rollback(c)
                raise
            except sqlite3.Error as exc:
                _rollback(c)
                raise TaskStoreError("task_store_unavailable", "Task store is unavailable") from exc

    def heartbeat(
        self, heartbeat: RunnerHeartbeat, *, now: datetime | None = None
    ) -> RunnerHeartbeat:
        self._ensure_open()
        value = self._validate_heartbeat(heartbeat)
        timestamp = _clock(now)
        with self._lock:
            c = self._connection
            try:
                c.execute("BEGIN IMMEDIATE")
                row = self._require_row(c, value.task_id)
                lease = self._lease_from_row(row)
                self._check_lease(
                    row,
                    lease,
                    timestamp,
                    runner_id=value.runner_id,
                    token=value.fencing_token,
                )
                c.execute(
                    "UPDATE runner_tasks SET heartbeat_json=? WHERE task_id=?",
                    (value.model_dump_json(), value.task_id),
                )
                c.commit()
                return value
            except (TaskLeaseError, TaskNotFound, TaskStoreError):
                _rollback(c)
                raise
            except sqlite3.Error as exc:
                _rollback(c)
                raise TaskStoreError("task_store_unavailable", "Task store is unavailable") from exc

    def complete(
        self, receipt: RunnerResultReceipt, *, now: datetime | None = None
    ) -> RunnerResultReceipt:
        self._ensure_open()
        value = self._validate_receipt(receipt)
        timestamp = value.completed_at if now is None else _clock(now)
        with self._lock:
            c = self._connection
            try:
                c.execute("BEGIN IMMEDIATE")
                row = self._require_row(c, value.task_id)
                if row["receipt_json"] is not None:
                    existing = self._decode_receipt(row["receipt_json"])
                    if existing == value:
                        c.commit()
                        return existing
                    raise TaskConflict("task already contains a different result")
                lease = self._lease_from_row(row)
                self._check_lease(
                    row,
                    lease,
                    timestamp,
                    runner_id=value.runner_id,
                    token=value.fencing_token,
                )
                c.execute(
                    "UPDATE runner_tasks SET state='COMPLETED',receipt_json=?,"
                    "lease_expires_at=NULL "
                    "WHERE task_id=?",
                    (value.model_dump_json(), value.task_id),
                )
                c.commit()
                return value
            except (TaskConflict, TaskLeaseError, TaskNotFound, TaskStoreError):
                _rollback(c)
                raise
            except sqlite3.Error as exc:
                _rollback(c)
                raise TaskStoreError("task_store_unavailable", "Task store is unavailable") from exc

    def recover(
        self, task: str | TaskLease, *, now: datetime | None = None
    ) -> RecoveryDirective:
        self._ensure_open()
        task_id = task if isinstance(task, str) else task.task_id
        supplied_lease = None if isinstance(task, str) else self._validate_lease(task)
        timestamp = _clock(now)
        with self._lock:
            c = self._connection
            try:
                c.execute("BEGIN IMMEDIATE")
                row = self._require_row(c, task_id)
                if row["state"] != "LEASED":
                    raise TaskLeaseError("task_not_recoverable", "Task is not recoverable")
                lease = self._lease_from_row(row)
                if supplied_lease is not None and (
                    supplied_lease.runner_id != lease.runner_id
                    or supplied_lease.fencing_token != lease.fencing_token
                ):
                    raise TaskLeaseError("stale_lease", "Task lease is stale")
                if lease.lease_expires_at > timestamp:
                    raise TaskLeaseError("lease_active", "Task lease is still active")
                heartbeat = (
                    None
                    if row["heartbeat_json"] is None
                    else self._decode_heartbeat(row["heartbeat_json"])
                )
                if heartbeat is not None and heartbeat.effect_boundary is False:
                    action = RecoveryAction.RETRY_FROM_CHECKPOINT
                    checkpoint = heartbeat.checkpoint_digest
                    if checkpoint is None:
                        action = RecoveryAction.VERIFY_OR_RECONCILE
                else:
                    action = RecoveryAction.VERIFY_OR_RECONCILE
                    checkpoint = None
                directive = RecoveryDirective.issue(
                    task_id=task_id,
                    action=action,
                    checkpoint_digest=checkpoint,
                    reason_code=(
                        "lease_expired_pre_effect"
                        if action is RecoveryAction.RETRY_FROM_CHECKPOINT
                        else (
                            "lease_expired_post_effect"
                            if heartbeat is not None and heartbeat.effect_boundary is True
                            else "lease_expired_effect_unknown"
                        )
                    ),
                )
                state = "QUEUED" if action is RecoveryAction.RETRY_FROM_CHECKPOINT else "VERIFYING"
                c.execute(
                    "UPDATE runner_tasks SET state=?,lease_expires_at=NULL WHERE task_id=?",
                    (state, task_id),
                )
                c.commit()
                return directive
            except (TaskLeaseError, TaskNotFound, TaskStoreError):
                _rollback(c)
                raise
            except sqlite3.Error as exc:
                _rollback(c)
                raise TaskStoreError("task_store_unavailable", "Task store is unavailable") from exc

    def get(self, task_id: str) -> RunnerTask | None:
        self._ensure_open()
        with self._lock:
            try:
                row = self._connection.execute(
                    "SELECT * FROM runner_tasks WHERE task_id=?", (task_id,)
                ).fetchone()
            except sqlite3.Error as exc:
                raise TaskStoreError("task_store_unavailable", "Task store is unavailable") from exc
            return None if row is None else self._decode_task(row)

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._connection.close()
                self._closed = True

    def __enter__(self) -> SQLiteTaskStore:
        self._ensure_open()
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

    @staticmethod
    def _validate_task(value: RunnerTask) -> RunnerTask:
        try:
            return RunnerTask.model_validate(value.model_dump())
        except Exception as exc:
            raise TaskStoreError("invalid_task", "Task is invalid") from exc

    @staticmethod
    def _validate_lease(value: TaskLease) -> TaskLease:
        try:
            return TaskLease.model_validate(value.model_dump())
        except Exception as exc:
            raise TaskLeaseError("invalid_lease", "Task lease is invalid") from exc

    @staticmethod
    def _validate_heartbeat(value: RunnerHeartbeat) -> RunnerHeartbeat:
        try:
            return RunnerHeartbeat.model_validate(value.model_dump())
        except Exception as exc:
            raise TaskLeaseError("invalid_heartbeat", "Heartbeat is invalid") from exc

    @staticmethod
    def _validate_receipt(value: RunnerResultReceipt) -> RunnerResultReceipt:
        try:
            return RunnerResultReceipt.model_validate(value.model_dump())
        except Exception as exc:
            raise TaskLeaseError("invalid_result_receipt", "Result receipt is invalid") from exc

    @staticmethod
    def _decode_task(row: sqlite3.Row) -> RunnerTask:
        try:
            task = RunnerTask.model_validate_json(row["task_json"])
            if task.task_digest != row["task_digest"] or task.task_id != row["task_id"]:
                raise ValueError("stored task fields mismatch")
            if (
                task.tenant_id != row["tenant_id"]
                or task.environment_id != row["environment_id"]
                or task.runner_pool != row["runner_pool"]
                or task.capability != row["capability"]
            ):
                raise ValueError("stored task scope mismatch")
            return task
        except Exception as exc:
            raise TaskStoreError("task_integrity_error", "Stored task is invalid") from exc

    @staticmethod
    def _decode_heartbeat(payload: str) -> RunnerHeartbeat:
        try:
            return RunnerHeartbeat.model_validate_json(payload)
        except Exception as exc:
            raise TaskLeaseError(
                "heartbeat_integrity_error", "Stored heartbeat is invalid"
            ) from exc

    @staticmethod
    def _decode_receipt(payload: str) -> RunnerResultReceipt:
        try:
            return RunnerResultReceipt.model_validate_json(payload)
        except Exception as exc:
            raise TaskStoreError("receipt_integrity_error", "Stored receipt is invalid") from exc

    @staticmethod
    def _lease_from_row(row: sqlite3.Row) -> TaskLease:
        try:
            if row["runner_id"] is None or row["lease_expires_at"] is None:
                raise ValueError("lease is missing")
            acquired_at = row["lease_acquired_at"]
            if acquired_at is None:
                raise ValueError("lease acquisition time is missing")
            return TaskLease.issue(
                task_id=row["task_id"],
                runner_id=row["runner_id"],
                fencing_token=int(row["fencing_token"]),
                acquired_at=datetime.fromisoformat(acquired_at).astimezone(UTC),
                lease_expires_at=datetime.fromisoformat(row["lease_expires_at"]).astimezone(UTC),
            )
        except Exception as exc:
            raise TaskLeaseError("lease_integrity_error", "Stored lease is invalid") from exc

    @staticmethod
    def _check_lease(
        row: sqlite3.Row,
        lease: TaskLease,
        now: datetime,
        *,
        runner_id: str | None = None,
        token: int | None = None,
    ) -> None:
        if row["state"] != "LEASED":
            raise TaskLeaseError("stale_lease", "Task lease is stale")
        if runner_id is not None and row["runner_id"] != runner_id:
            raise TaskLeaseError("stale_lease", "Task lease is stale")
        if token is not None and int(row["fencing_token"]) != token:
            raise TaskLeaseError("stale_lease", "Task lease is stale")
        if row["runner_id"] != lease.runner_id or int(row["fencing_token"]) != lease.fencing_token:
            raise TaskLeaseError("stale_lease", "Task lease is stale")
        if lease.lease_expires_at <= now:
            raise TaskLeaseError("lease_expired", "Task lease has expired")

    @staticmethod
    def _require_row(connection: sqlite3.Connection, task_id: str) -> sqlite3.Row:
        row = cast(
            sqlite3.Row | None,
            connection.execute(
                "SELECT * FROM runner_tasks WHERE task_id=?", (task_id,)
            ).fetchone(),
        )
        if row is None:
            raise TaskNotFound("Task was not found")
        return row

    def _ensure_open(self) -> None:
        if self._closed:
            raise TaskStoreError("store_closed", "Task store is closed")


def _clock(value: datetime | None) -> datetime:
    result = datetime.now(UTC) if value is None else value
    return _aware(result)


def _aware(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("task clock must include a timezone")
    return value.astimezone(UTC)


def _format(value: datetime) -> str:
    return _aware(value).isoformat(timespec="microseconds")


def _rollback(connection: sqlite3.Connection) -> None:
    with suppress(sqlite3.Error):
        connection.rollback()


__all__ = [
    "SQLiteTaskStore",
    "TaskConflict",
    "TaskLeaseError",
    "TaskNotFound",
    "TaskStoreError",
]
