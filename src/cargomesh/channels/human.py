"""Digest-bound attended-human task contracts and a fenced local SQLite store.

This module intentionally schedules no work and sends no notification. A caller
must provide a principal reference verified by its identity boundary.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import sqlite3
import threading
from collections.abc import Mapping, Sequence
from contextlib import suppress
from datetime import UTC, datetime, timedelta
from enum import Enum, StrEnum
from pathlib import Path
from typing import Annotated, Literal, Protocol, cast

from pydantic import BaseModel, ConfigDict, Field, JsonValue, StringConstraints, model_validator

from cargomesh.verification.models import EvidenceChannel, EvidenceObservation

ATTENDED_TASK_SCHEMA_VERSION: Literal["cargomesh.attended-task/v1"] = "cargomesh.attended-task/v1"

_NAME_PATTERN = r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$"
_SECRET_RE = re.compile(
    r"(?:^|[._-])(?:authorization|cookie|credential|password|secret|token|api[_-]?key)"
    r"(?:$|[._-])",
    re.IGNORECASE,
)
_OUTPUT_CONTENT_RE = re.compile(
    r"(?:^|[._-])(?:attachment|body|content|document|payload|raw)(?:$|[._-])",
    re.IGNORECASE,
)

TaskIdentifier = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=1, max_length=256),
]
TaskName = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=128,
        pattern=_NAME_PATTERN,
    ),
]
Sha256Digest = Annotated[str, StringConstraints(pattern=r"^sha256:[0-9a-f]{64}$")]
ClaimScalar = str | int | float | bool | None


class HumanModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class AttendedTaskStatus(StrEnum):
    PENDING = "PENDING"
    CLAIMED = "CLAIMED"
    COMPLETED = "COMPLETED"
    REJECTED = "REJECTED"


class AttendedTask(HumanModel):
    """An immutable, digest-bound request for an attended human operation."""

    schema_version: Literal["cargomesh.attended-task/v1"] = ATTENDED_TASK_SCHEMA_VERSION
    task_id: TaskIdentifier
    tenant_id: TaskIdentifier
    environment_id: TaskIdentifier
    transaction_id: TaskIdentifier
    step_id: TaskName
    capability: TaskName
    instructions: dict[TaskName, JsonValue] = Field(max_length=16)
    required_claim_names: tuple[TaskName, ...] = Field(min_length=1, max_length=32)
    status: Literal[AttendedTaskStatus.PENDING] = AttendedTaskStatus.PENDING
    created_at: datetime
    task_digest: Sha256Digest

    @model_validator(mode="after")
    def validate_task(self) -> AttendedTask:
        _safe_instruction_value(self.instructions)
        if len(self.required_claim_names) != len(set(self.required_claim_names)):
            raise ValueError("required claim names must be unique")
        _aware_timestamp(self.created_at)
        if self.task_digest != _model_digest(self, exclude={"task_digest"}):
            raise ValueError("attended task digest does not match")
        return self

    @classmethod
    def issue(cls, **values: object) -> AttendedTask:
        return cast(
            AttendedTask,
            _issue_model(cls, values, "task_digest", ATTENDED_TASK_SCHEMA_VERSION),
        )


class HumanTaskLease(HumanModel):
    """A short-lived, non-transferable fencing lease for one verified principal."""

    task_id: TaskIdentifier
    tenant_id: TaskIdentifier
    environment_id: TaskIdentifier
    principal_ref: TaskIdentifier
    fencing_token: int = Field(ge=1, le=2**63 - 1)
    acquired_at: datetime
    expires_at: datetime
    lease_digest: Sha256Digest

    @model_validator(mode="after")
    def validate_lease(self) -> HumanTaskLease:
        acquired_at = _aware_timestamp(self.acquired_at)
        expires_at = _aware_timestamp(self.expires_at)
        if expires_at <= acquired_at:
            raise ValueError("attended task lease has invalid lifetime")
        _validate_principal_ref(self.principal_ref)
        if self.lease_digest != _model_digest(self, exclude={"lease_digest"}):
            raise ValueError("attended task lease digest does not match")
        return self

    @classmethod
    def issue(cls, **values: object) -> HumanTaskLease:
        return cast(HumanTaskLease, _issue_model(cls, values, "lease_digest"))


class AttendedTaskRecord(HumanModel):
    """Durable state, retaining no note body or attachment content."""

    task: AttendedTask
    status: AttendedTaskStatus
    fencing_token: int = Field(default=0, ge=0, le=2**63 - 1)
    principal_ref: TaskIdentifier | None = None
    lease_expires_at: datetime | None = None
    claims: dict[TaskName, ClaimScalar] | None = None
    note_digest: Sha256Digest | None = None
    completion_digest: Sha256Digest | None = None
    updated_at: datetime
    record_digest: Sha256Digest

    @model_validator(mode="after")
    def validate_record(self) -> AttendedTaskRecord:
        _aware_timestamp(self.updated_at)
        if self.status is AttendedTaskStatus.CLAIMED and (
            self.principal_ref is None or self.lease_expires_at is None
        ):
            raise ValueError("claimed attended task requires a lease")
        if self.status in {AttendedTaskStatus.COMPLETED, AttendedTaskStatus.REJECTED} and (
            self.claims is None or self.completion_digest is None
        ):
            raise ValueError("terminal attended task requires a bounded result")
        if self.claims is not None:
            _safe_claims(self.claims)
        if self.record_digest != _model_digest(self, exclude={"record_digest"}):
            raise ValueError("attended task record digest does not match")
        return self

    @classmethod
    def issue(cls, **values: object) -> AttendedTaskRecord:
        return cast(AttendedTaskRecord, _issue_model(cls, values, "record_digest"))


class AttendedTaskError(RuntimeError):
    """A bounded error that never contains instructions or output material."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(message)


class AttendedTaskConflict(AttendedTaskError):
    def __init__(self) -> None:
        super().__init__("attended_task_conflict", "Attended task conflicts with existing task")


class AttendedTaskProvider(Protocol):
    """A local task provider contract; it deliberately has no delivery/UI method."""

    def create(self, task: AttendedTask) -> AttendedTaskRecord: ...

    def get(
        self, task_id: str, *, tenant_id: str, environment_id: str
    ) -> AttendedTaskRecord | None: ...

    def claim(
        self,
        task_id: str,
        *,
        tenant_id: str,
        environment_id: str,
        principal_ref: str,
        now: datetime | None = None,
    ) -> HumanTaskLease: ...

    def complete(
        self,
        lease: HumanTaskLease,
        claims: Mapping[str, ClaimScalar],
        *,
        rejected: bool = False,
        note: str | None = None,
        now: datetime | None = None,
    ) -> AttendedTaskRecord: ...


class SQLiteAttendedTaskStore:
    """Reference SQLite store with one connection and transaction-level fencing."""

    def __init__(self, database: str | Path = ":memory:", *, lease_seconds: int = 300) -> None:
        if not 1 <= lease_seconds <= 3600:
            raise ValueError("attended task lease must be between 1 and 3600 seconds")
        self._closed = False
        self._lease_seconds = lease_seconds
        self._lock = threading.RLock()
        try:
            self._connection = sqlite3.connect(
                str(database),
                isolation_level=None,
                check_same_thread=False,
                timeout=10,
            )
            self._connection.row_factory = sqlite3.Row
            if str(database) != ":memory:":
                self._connection.execute("PRAGMA journal_mode=WAL")
            self._connection.execute("PRAGMA busy_timeout=10000")
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS attended_tasks (
                    task_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    environment_id TEXT NOT NULL,
                    task_digest TEXT NOT NULL,
                    record_json TEXT NOT NULL
                )
                """
            )
        except sqlite3.Error as exc:
            raise _unavailable_error() from exc

    def create(self, task: AttendedTask) -> AttendedTaskRecord:
        value = _validate_task(task)
        record = AttendedTaskRecord.issue(
            task=value,
            status=AttendedTaskStatus.PENDING,
            updated_at=value.created_at,
        )
        with self._lock:
            self._ensure_open()
            try:
                row = self._connection.execute(
                    "SELECT task_digest, record_json FROM attended_tasks WHERE task_id = ?",
                    (value.task_id,),
                ).fetchone()
                if row is not None:
                    existing_digest = row["task_digest"]
                    if not isinstance(existing_digest, str) or existing_digest != value.task_digest:
                        raise AttendedTaskConflict()
                    return _decode_record(_row_text(row, "record_json"))
                self._connection.execute(
                    """
                    INSERT INTO attended_tasks (
                        task_id, tenant_id, environment_id, task_digest, record_json
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        value.task_id,
                        value.tenant_id,
                        value.environment_id,
                        value.task_digest,
                        record.model_dump_json(),
                    ),
                )
                return record
            except AttendedTaskError:
                raise
            except sqlite3.Error as exc:
                raise _unavailable_error() from exc

    def get(
        self, task_id: str, *, tenant_id: str, environment_id: str
    ) -> AttendedTaskRecord | None:
        with self._lock:
            self._ensure_open()
            try:
                row = self._connection.execute(
                    """
                    SELECT record_json FROM attended_tasks
                    WHERE task_id = ? AND tenant_id = ? AND environment_id = ?
                    """,
                    (task_id, tenant_id, environment_id),
                ).fetchone()
            except sqlite3.Error as exc:
                raise _unavailable_error() from exc
        if row is None:
            return None
        return _decode_record(_row_text(row, "record_json"))

    def claim(
        self,
        task_id: str,
        *,
        tenant_id: str,
        environment_id: str,
        principal_ref: str,
        now: datetime | None = None,
    ) -> HumanTaskLease:
        timestamp = _now(now)
        _validate_principal_ref(principal_ref)
        with self._lock:
            connection = self._connection
            self._ensure_open()
            try:
                connection.execute("BEGIN IMMEDIATE")
                record = self._load_scoped_record(
                    connection,
                    task_id,
                    tenant_id,
                    environment_id,
                )
                if record.status in {
                    AttendedTaskStatus.COMPLETED,
                    AttendedTaskStatus.REJECTED,
                }:
                    raise AttendedTaskError(
                        "attended_task_terminal", "Attended task is already terminal"
                    )
                if _active_lease(record, timestamp):
                    raise AttendedTaskError(
                        "attended_task_claimed", "Attended task is already claimed"
                    )
                lease = HumanTaskLease.issue(
                    task_id=task_id,
                    tenant_id=tenant_id,
                    environment_id=environment_id,
                    principal_ref=principal_ref,
                    fencing_token=record.fencing_token + 1,
                    acquired_at=timestamp,
                    expires_at=timestamp + timedelta(seconds=self._lease_seconds),
                )
                updated = AttendedTaskRecord.issue(
                    task=record.task,
                    status=AttendedTaskStatus.CLAIMED,
                    fencing_token=lease.fencing_token,
                    principal_ref=principal_ref,
                    lease_expires_at=lease.expires_at,
                    updated_at=timestamp,
                )
                self._save(connection, updated)
                connection.commit()
                return lease
            except AttendedTaskError:
                _rollback(connection)
                raise
            except sqlite3.Error as exc:
                _rollback(connection)
                raise _unavailable_error() from exc

    def complete(
        self,
        lease: HumanTaskLease,
        claims: Mapping[str, ClaimScalar],
        *,
        rejected: bool = False,
        note: str | None = None,
        now: datetime | None = None,
    ) -> AttendedTaskRecord:
        value = _validate_lease(lease)
        timestamp = _now(now)
        claim_values = _claim_values(claims)
        note_digest = _note_digest(note)
        with self._lock:
            connection = self._connection
            self._ensure_open()
            try:
                connection.execute("BEGIN IMMEDIATE")
                current = self._load_scoped_record(
                    connection,
                    value.task_id,
                    value.tenant_id,
                    value.environment_id,
                )
                required_claims = _require_exact_claims(
                    claim_values,
                    current.task.required_claim_names,
                )
                completion_digest = _completion_digest(
                    claims=required_claims,
                    note_digest=note_digest,
                    rejected=rejected,
                    lease=value,
                )
                if current.status in {
                    AttendedTaskStatus.COMPLETED,
                    AttendedTaskStatus.REJECTED,
                }:
                    if _is_same_completion(current, value, completion_digest):
                        connection.commit()
                        return current
                    raise AttendedTaskError(
                        "attended_task_completion_conflict",
                        "Attended task completion conflicts",
                    )
                _validate_current_lease(current, value, timestamp)
                updated = AttendedTaskRecord.issue(
                    task=current.task,
                    status=(
                        AttendedTaskStatus.REJECTED
                        if rejected
                        else AttendedTaskStatus.COMPLETED
                    ),
                    fencing_token=value.fencing_token,
                    principal_ref=value.principal_ref,
                    claims=required_claims,
                    note_digest=note_digest,
                    completion_digest=completion_digest,
                    updated_at=timestamp,
                )
                self._save(connection, updated)
                connection.commit()
                return updated
            except AttendedTaskError:
                _rollback(connection)
                raise
            except sqlite3.Error as exc:
                _rollback(connection)
                raise _unavailable_error() from exc

    def reject(
        self,
        lease: HumanTaskLease,
        claims: Mapping[str, ClaimScalar],
        *,
        note: str | None = None,
        now: datetime | None = None,
    ) -> AttendedTaskRecord:
        """Reject using the same fenced one-time completion boundary."""

        return self.complete(lease, claims, rejected=True, note=note, now=now)

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._connection.close()
                self._closed = True

    def _load_scoped_record(
        self,
        connection: sqlite3.Connection,
        task_id: str,
        tenant_id: str,
        environment_id: str,
    ) -> AttendedTaskRecord:
        row = connection.execute(
            """
            SELECT record_json FROM attended_tasks
            WHERE task_id = ? AND tenant_id = ? AND environment_id = ?
            """,
            (task_id, tenant_id, environment_id),
        ).fetchone()
        if row is None:
            raise AttendedTaskError("attended_task_not_found", "Attended task was not found")
        return _decode_record(_row_text(row, "record_json"))

    def _save(self, connection: sqlite3.Connection, record: AttendedTaskRecord) -> None:
        connection.execute(
            "UPDATE attended_tasks SET record_json = ? WHERE task_id = ?",
            (record.model_dump_json(), record.task.task_id),
        )

    def _ensure_open(self) -> None:
        if self._closed:
            raise _unavailable_error()


def to_evidence_observation(
    record: AttendedTaskRecord,
    *,
    evidence_id: str,
    collector_id: str = "attended.human",
    collection_id: str | None = None,
) -> EvidenceObservation:
    """Project completed human output into explicitly synthetic SYSTEM_RECORD evidence."""

    if record.status is not AttendedTaskStatus.COMPLETED or record.claims is None:
        raise AttendedTaskError(
            "attended_task_not_completed", "Attended task has no completed evidence"
        )
    return EvidenceObservation.issue(
        evidence_id=evidence_id,
        tenant_id=record.task.tenant_id,
        transaction_id=record.task.transaction_id,
        source_record_id=record.task.task_id,
        source_system="attended.human",
        channel=EvidenceChannel.SYSTEM_RECORD,
        collector_id=collector_id,
        collection_id=collection_id or record.task.task_id,
        observed_at=record.updated_at,
        claims=record.claims,
        synthetic=True,
    )


def _validate_task(value: AttendedTask) -> AttendedTask:
    try:
        return AttendedTask.model_validate(value.model_dump())
    except Exception as exc:
        raise AttendedTaskError("attended_task_invalid", "Attended task is invalid") from exc


def _validate_lease(value: HumanTaskLease) -> HumanTaskLease:
    try:
        return HumanTaskLease.model_validate(value.model_dump())
    except Exception as exc:
        raise AttendedTaskError(
            "attended_task_lease_invalid", "Attended task lease is invalid"
        ) from exc


def _decode_record(value: str) -> AttendedTaskRecord:
    try:
        return AttendedTaskRecord.model_validate_json(value)
    except Exception as exc:
        raise AttendedTaskError(
            "attended_task_integrity_error", "Stored attended task is invalid"
        ) from exc


def _row_text(row: sqlite3.Row, key: str) -> str:
    value = row[key]
    if not isinstance(value, str):
        raise AttendedTaskError(
            "attended_task_integrity_error", "Stored attended task is invalid"
        )
    return value


def _claim_values(value: Mapping[str, ClaimScalar]) -> dict[str, ClaimScalar]:
    if len(value) > 32:
        raise AttendedTaskError(
            "attended_task_claims_invalid", "Attended task claims are invalid"
        )
    result = dict(value)
    try:
        _safe_claims(result)
    except (TypeError, ValueError) as exc:
        raise AttendedTaskError(
            "attended_task_claims_invalid", "Attended task claims are invalid"
        ) from exc
    return result


def _require_exact_claims(
    claims: dict[str, ClaimScalar],
    required_claim_names: tuple[str, ...],
) -> dict[str, ClaimScalar]:
    if tuple(sorted(claims)) != tuple(sorted(required_claim_names)):
        raise AttendedTaskError(
            "attended_task_claims_invalid", "Attended task claims are invalid"
        )
    return claims


def _safe_claims(claims: Mapping[str, ClaimScalar]) -> None:
    for key, item in claims.items():
        if not isinstance(key, str) or not re.fullmatch(_NAME_PATTERN, key):
            raise ValueError("claim name is invalid")
        if _SECRET_RE.search(key):
            raise ValueError("claim name is secret-like")
        if _OUTPUT_CONTENT_RE.search(key):
            raise ValueError("claim name could carry content")
        if isinstance(item, str) and len(item) > 1024:
            raise ValueError("claim string is too long")
        if isinstance(item, float) and not math.isfinite(item):
            raise ValueError("claim number is not finite")


def _safe_instruction_value(value: object, *, depth: int = 0) -> None:
    if depth > 8:
        raise ValueError("instruction nesting is too deep")
    if isinstance(value, Mapping):
        if len(value) > 32:
            raise ValueError("instruction map is too large")
        for key, item in value.items():
            if _SECRET_RE.search(str(key)):
                raise ValueError("instructions must not contain secret-like fields")
            _safe_instruction_value(item, depth=depth + 1)
        return
    if isinstance(value, list):
        if len(value) > 64:
            raise ValueError("instruction list is too large")
        for item in value:
            _safe_instruction_value(item, depth=depth + 1)
        return
    if isinstance(value, str) and len(value) > 2048:
        raise ValueError("instruction string is too long")


def _validate_principal_ref(value: str) -> None:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 256
        or _SECRET_RE.search(value)
    ):
        raise AttendedTaskError(
            "attended_task_principal_invalid",
            "Verified principal reference is invalid",
        )


def _note_digest(value: str | None) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or len(value) > 1024 or _SECRET_RE.search(value):
        raise AttendedTaskError(
            "attended_task_note_invalid", "Attended task note is invalid"
        )
    return _value_digest(value)


def _active_lease(record: AttendedTaskRecord, now: datetime) -> bool:
    return (
        record.status is AttendedTaskStatus.CLAIMED
        and record.lease_expires_at is not None
        and record.lease_expires_at > now
    )


def _validate_current_lease(
    record: AttendedTaskRecord, lease: HumanTaskLease, now: datetime
) -> None:
    if (
        record.status is not AttendedTaskStatus.CLAIMED
        or record.principal_ref != lease.principal_ref
        or record.fencing_token != lease.fencing_token
    ):
        raise AttendedTaskError("attended_task_stale_lease", "Attended task lease is stale")
    if record.lease_expires_at is None or record.lease_expires_at <= now:
        raise AttendedTaskError(
            "attended_task_lease_expired", "Attended task lease has expired"
        )


def _is_same_completion(
    record: AttendedTaskRecord,
    lease: HumanTaskLease,
    completion_digest: str,
) -> bool:
    return (
        record.fencing_token == lease.fencing_token
        and record.principal_ref == lease.principal_ref
        and record.completion_digest == completion_digest
    )


def _completion_digest(
    *,
    claims: Mapping[str, ClaimScalar],
    note_digest: str | None,
    rejected: bool,
    lease: HumanTaskLease,
) -> str:
    return _value_digest(
        {
            "claims": claims,
            "note_digest": note_digest,
            "rejected": rejected,
            "fencing_token": lease.fencing_token,
            "principal_ref": lease.principal_ref,
        }
    )


def _issue_model(
    model_type: type[AttendedTask] | type[HumanTaskLease] | type[AttendedTaskRecord],
    values: Mapping[str, object],
    digest_field: str,
    schema_version: str | None = None,
) -> AttendedTask | HumanTaskLease | AttendedTaskRecord:
    payload = dict(values)
    if schema_version is not None:
        payload.setdefault("schema_version", schema_version)
    unsigned = model_type.model_construct(_fields_set=set(payload), **payload)
    payload[digest_field] = _model_digest(unsigned, exclude={digest_field})
    return model_type.model_validate(payload)


def _model_digest(model: BaseModel, *, exclude: set[str]) -> str:
    return _value_digest(model.model_dump(mode="python", exclude=exclude, warnings=False))


def _value_digest(value: object) -> str:
    canonical = json.dumps(
        _canonical(value),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def _canonical(value: object) -> object:
    if isinstance(value, BaseModel):
        return _canonical(value.model_dump(mode="python"))
    if isinstance(value, datetime):
        return _aware_timestamp(value).isoformat(timespec="microseconds")
    if isinstance(value, Enum):
        return _canonical(value.value)
    if isinstance(value, Mapping):
        return {str(key): _canonical(item) for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        return [_canonical(item) for item in value]
    return value


def _now(value: datetime | None) -> datetime:
    return _aware_timestamp(datetime.now(UTC) if value is None else value)


def _aware_timestamp(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("attended task timestamp must include a timezone")
    return value.astimezone(UTC)


def _rollback(connection: sqlite3.Connection) -> None:
    with suppress(sqlite3.Error):
        connection.rollback()


def _unavailable_error() -> AttendedTaskError:
    return AttendedTaskError("attended_task_unavailable", "Attended task store is unavailable")


__all__ = [
    "ATTENDED_TASK_SCHEMA_VERSION",
    "AttendedTask",
    "AttendedTaskConflict",
    "AttendedTaskError",
    "AttendedTaskProvider",
    "AttendedTaskRecord",
    "AttendedTaskStatus",
    "ClaimScalar",
    "HumanTaskLease",
    "SQLiteAttendedTaskStore",
    "to_evidence_observation",
]
