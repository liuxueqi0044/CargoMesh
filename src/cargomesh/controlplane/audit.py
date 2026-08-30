"""Tenant-independent append-only audit hash chains backed by SQLite."""

from __future__ import annotations

import sqlite3
import threading
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from .models import AUDIT_RECORD_SCHEMA_VERSION, AuditEvent, AuditRecord


class AuditConflict(RuntimeError):
    code = "audit_conflict"


class AuditStoreError(RuntimeError):
    def __init__(self, code: str, message: str, *, sequence: int | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.sequence = sequence


@dataclass(frozen=True, slots=True)
class ChainVerification:
    """Result of verifying one tenant's complete chain.

    ``bool(result)`` is convenient for callers that only need a pass/fail,
    while ``first_broken_sequence`` identifies the first damaged row.
    """

    valid: bool
    checked_count: int
    first_broken_sequence: int | None = None
    reason: str | None = None

    def __bool__(self) -> bool:
        return self.valid

    @property
    def is_valid(self) -> bool:
        return self.valid

    @property
    def broken_sequence(self) -> int | None:
        return self.first_broken_sequence


class AuditStore(Protocol):
    def append(self, event: AuditEvent) -> AuditRecord: ...
    def get(self, tenant_id: str, event_id: str) -> AuditRecord | None: ...
    def list(
        self, tenant_id: str, environment_id: str | None = None, limit: int = 100
    ) -> tuple[AuditRecord, ...]: ...
    def verify_chain(self, tenant_id: str) -> ChainVerification: ...
    def close(self) -> None: ...


class SQLiteAuditStore:
    """A durable per-tenant append-only event ledger.

    Every insert is serialized with ``BEGIN IMMEDIATE``.  The event itself is
    validated again at this boundary, preventing callers that used Pydantic's
    low-level construction helpers from bypassing digest and secret checks.
    """

    SCHEMA_VERSION = 1
    MAX_LIST_LIMIT = 1000

    def __init__(self, database: str | Path = ":memory:") -> None:
        self._closed = False
        self._lock = threading.RLock()
        self._database = str(database)
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
            raise AuditStoreError("audit_store_unavailable", "Audit store is unavailable") from exc

    def _initialize_schema(self) -> None:
        c = self._connection
        c.execute(
            "CREATE TABLE IF NOT EXISTS audit_schema_version "
            "(component TEXT PRIMARY KEY, version INTEGER NOT NULL)"
        )
        row = c.execute(
            "SELECT version FROM audit_schema_version WHERE component=?",
            (AUDIT_RECORD_SCHEMA_VERSION,),
        ).fetchone()
        if row is not None and row["version"] != self.SCHEMA_VERSION:
            raise AuditStoreError("audit_schema_unsupported", "Unsupported audit schema")
        c.execute(
            "INSERT OR IGNORE INTO audit_schema_version(component,version) VALUES (?,?)",
            (AUDIT_RECORD_SCHEMA_VERSION, self.SCHEMA_VERSION),
        )
        c.execute(
            """CREATE TABLE IF NOT EXISTS audit_records (
                tenant_id TEXT NOT NULL,
                sequence INTEGER NOT NULL,
                event_id TEXT NOT NULL,
                event_digest TEXT NOT NULL,
                previous_record_digest TEXT,
                record_digest TEXT NOT NULL,
                event_json TEXT NOT NULL,
                record_json TEXT NOT NULL,
                PRIMARY KEY(tenant_id, sequence),
                UNIQUE(tenant_id, event_id)
            )"""
        )
        c.executescript(
            "CREATE TRIGGER IF NOT EXISTS audit_records_no_update BEFORE UPDATE ON audit_records "
            "BEGIN SELECT RAISE(ABORT, 'audit records are append-only'); END; "
            "CREATE TRIGGER IF NOT EXISTS audit_records_no_delete BEFORE DELETE ON audit_records "
            "BEGIN SELECT RAISE(ABORT, 'audit records are append-only'); END;"
        )

    def append(self, event: AuditEvent) -> AuditRecord:
        self._ensure_open()
        value = self._validate_event(event)
        with self._lock:
            c = self._connection
            try:
                c.execute("BEGIN IMMEDIATE")
                existing = c.execute(
                    "SELECT event_digest,event_json,record_digest,record_json FROM audit_records "
                    "WHERE tenant_id=? AND event_id=?",
                    (value.tenant_id, value.event_id),
                ).fetchone()
                if existing is not None:
                    old = self._decode_record(existing["record_json"], existing["record_digest"])
                    old_event = self._decode_event(existing["event_json"], existing["event_digest"])
                    if (
                        old.event.event_id != value.event_id
                        or old.event.event_digest != old_event.event_digest
                        or old.event.event_digest != value.event_digest
                    ):
                        raise AuditConflict("event id already contains different content")
                    c.commit()
                    return old

                latest = c.execute(
                    "SELECT sequence,record_digest FROM audit_records WHERE tenant_id=? "
                    "ORDER BY sequence DESC LIMIT 1",
                    (value.tenant_id,),
                ).fetchone()
                sequence = 1 if latest is None else int(latest["sequence"]) + 1
                previous = None if latest is None else latest["record_digest"]
                record = AuditRecord.issue(
                    sequence=sequence,
                    event=value,
                    previous_record_digest=previous,
                )
                c.execute(
                    "INSERT INTO audit_records VALUES (?,?,?,?,?,?,?,?)",
                    (
                        value.tenant_id,
                        record.sequence,
                        value.event_id,
                        value.event_digest,
                        record.previous_record_digest,
                        record.record_digest,
                        value.model_dump_json(exclude_none=True),
                        record.model_dump_json(exclude_none=True),
                    ),
                )
                c.commit()
                return record
            except (AuditConflict, AuditStoreError):
                _rollback(c)
                raise
            except sqlite3.Error as exc:
                _rollback(c)
                raise AuditStoreError(
                    "audit_store_unavailable", "Audit store is unavailable"
                ) from exc
            except Exception as exc:
                _rollback(c)
                raise AuditStoreError("invalid_audit_event", "Audit event is invalid") from exc

    def get(self, tenant_id: str, event_id: str) -> AuditRecord | None:
        self._ensure_open()
        with self._lock:
            try:
                row = self._connection.execute(
                    "SELECT record_digest,record_json FROM audit_records "
                    "WHERE tenant_id=? AND event_id=?",
                    (tenant_id, event_id),
                ).fetchone()
            except sqlite3.Error as exc:
                raise AuditStoreError(
                    "audit_store_unavailable", "Audit store is unavailable"
                ) from exc
            return (
                None
                if row is None
                else self._decode_record(row["record_json"], row["record_digest"])
            )

    def list(
        self, tenant_id: str, environment_id: str | None = None, limit: int = 100
    ) -> tuple[AuditRecord, ...]:
        self._ensure_open()
        # Also accept the natural ``list(tenant_id, limit)`` spelling while
        # retaining the environment filter as a keyword-friendly argument.
        if isinstance(environment_id, int) and not isinstance(environment_id, bool):
            if limit != 100:
                raise AuditStoreError("invalid_limit", "Audit list limit is ambiguous")
            limit, environment_id = environment_id, None
        if (
            not isinstance(limit, int)
            or isinstance(limit, bool)
            or not 0 <= limit <= self.MAX_LIST_LIMIT
        ):
            raise AuditStoreError("invalid_limit", "Audit list limit is out of bounds")
        with self._lock:
            query = "SELECT record_digest,record_json FROM audit_records WHERE tenant_id=?"
            params: list[str | int] = [tenant_id]
            if environment_id is not None:
                query += " AND json_extract(event_json, '$.environment_id')=?"
                params.append(environment_id)
            query += " ORDER BY sequence ASC LIMIT ?"
            params.append(limit)
            try:
                rows = self._connection.execute(query, params).fetchall()
            except sqlite3.Error as exc:
                raise AuditStoreError(
                    "audit_store_unavailable", "Audit store is unavailable"
                ) from exc
            return tuple(
                self._decode_record(row["record_json"], row["record_digest"])
                for row in rows
            )

    def verify_chain(self, tenant_id: str) -> ChainVerification:
        self._ensure_open()
        with self._lock:
            try:
                rows = self._connection.execute(
                    "SELECT sequence,event_id,event_digest,event_json,previous_record_digest,"
                    "record_digest,record_json FROM audit_records "
                    "WHERE tenant_id=? ORDER BY sequence ASC",
                    (tenant_id,),
                ).fetchall()
            except sqlite3.Error as exc:
                raise AuditStoreError(
                    "audit_store_unavailable", "Audit store is unavailable"
                ) from exc
            previous: str | None = None
            expected = 1
            for index, row in enumerate(rows):
                sequence = int(row["sequence"])
                if sequence != expected:
                    return ChainVerification(False, index, sequence, "sequence_gap")
                try:
                    record = self._decode_record(row["record_json"], row["record_digest"])
                except AuditStoreError as exc:
                    return ChainVerification(False, index, sequence, exc.code)
                try:
                    event = self._decode_event(row["event_json"], row["event_digest"])
                except AuditStoreError as exc:
                    return ChainVerification(False, index, sequence, exc.code)
                if (
                    record.sequence != sequence
                    or record.event.event_digest != row["event_digest"]
                    or row["event_id"] != record.event.event_id
                    or event != record.event
                    or row["previous_record_digest"] != record.previous_record_digest
                ):
                    return ChainVerification(False, index, sequence, "stored_fields_mismatch")
                if record.previous_record_digest != previous:
                    return ChainVerification(False, index, sequence, "previous_digest_mismatch")
                if record.event.tenant_id != tenant_id:
                    return ChainVerification(False, index, sequence, "tenant_mismatch")
                previous = record.record_digest
                expected += 1
            return ChainVerification(True, len(rows))

    verify = verify_chain

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._connection.close()
                self._closed = True

    def __enter__(self) -> SQLiteAuditStore:
        self._ensure_open()
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

    @staticmethod
    def _validate_event(event: AuditEvent) -> AuditEvent:
        try:
            return AuditEvent.model_validate(event.model_dump())
        except Exception as exc:
            raise AuditStoreError("invalid_audit_event", "Audit event is invalid") from exc

    @staticmethod
    def _decode_record(serialized: str, stored_digest: str | None) -> AuditRecord:
        try:
            record = AuditRecord.model_validate_json(serialized)
            if stored_digest is not None and record.record_digest != stored_digest:
                raise ValueError("record digest mismatch")
            return record
        except Exception as exc:
            raise AuditStoreError(
                "audit_integrity_error", "Stored audit record is invalid"
            ) from exc

    @staticmethod
    def _decode_event(serialized: str, stored_digest: str | None) -> AuditEvent:
        try:
            event = AuditEvent.model_validate_json(serialized)
            if stored_digest is not None and event.event_digest != stored_digest:
                raise ValueError("event digest mismatch")
            return event
        except Exception as exc:
            raise AuditStoreError(
                "audit_integrity_error", "Stored audit event is invalid"
            ) from exc

    def _ensure_open(self) -> None:
        if self._closed:
            raise AuditStoreError("store_closed", "Audit store is closed")


def _rollback(connection: sqlite3.Connection) -> None:
    with suppress(sqlite3.Error):
        connection.rollback()


__all__ = [
    "AuditConflict",
    "AuditRecord",
    "AuditStore",
    "AuditStoreError",
    "ChainVerification",
    "SQLiteAuditStore",
]
