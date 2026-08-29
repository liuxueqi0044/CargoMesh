"""Append-only SQLite receipts for immutable evidence observations."""

from __future__ import annotations

import sqlite3
from contextlib import suppress
from pathlib import Path
from typing import Any, Protocol

from cargomesh.verification.models import EvidenceObservation


class EvidenceConflict(RuntimeError):
    """An evidence id was reused with a different content digest."""

    code = "evidence_conflict"

    def __init__(self, message: str = "Evidence id already contains different content") -> None:
        super().__init__(message)
        self.message = message


class EvidenceStoreError(RuntimeError):
    """Safe storage or receipt-integrity failure."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class EvidenceStore(Protocol):
    def append(self, observation: EvidenceObservation) -> EvidenceObservation: ...

    def get(self, tenant_id: str, evidence_id: str) -> EvidenceObservation | None: ...

    def close(self) -> None: ...


class SQLiteEvidenceStore:
    """Tenant-scoped, append-only SQLite receipt store.

    A duplicate ``(tenant_id, evidence_id)`` with the same digest is a replay
    and returns the original receipt.  A different digest is a hard conflict.
    """

    def __init__(self, database: str | Path = ":memory:") -> None:
        self._database = database
        self._closed = False
        database_value = str(database)
        self._connection = sqlite3.connect(database_value, isolation_level=None)
        self._connection.row_factory = sqlite3.Row
        if database_value != ":memory:":
            self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute("PRAGMA foreign_keys=ON")
        self._connection.execute(
            """
            CREATE TABLE IF NOT EXISTS evidence_receipts (
                tenant_id TEXT NOT NULL,
                evidence_id TEXT NOT NULL,
                digest TEXT NOT NULL,
                observation_json TEXT NOT NULL,
                PRIMARY KEY (tenant_id, evidence_id)
            )
            """
        )
        self._connection.execute(
            """
            CREATE TRIGGER IF NOT EXISTS evidence_receipts_no_update
            BEFORE UPDATE ON evidence_receipts
            BEGIN
                SELECT RAISE(ABORT, 'evidence receipts are append-only');
            END
            """
        )
        self._connection.execute(
            """
            CREATE TRIGGER IF NOT EXISTS evidence_receipts_no_delete
            BEFORE DELETE ON evidence_receipts
            BEGIN
                SELECT RAISE(ABORT, 'evidence receipts are append-only');
            END
            """
        )

    def append(self, observation: EvidenceObservation) -> EvidenceObservation:
        self._ensure_open()
        tenant_id = _required_text(observation, "tenant_id")
        evidence_id = _required_text(observation, "evidence_id")
        digest = _required_text(observation, "content_digest")
        try:
            observation_json = observation.model_dump_json(by_alias=True, exclude_none=True)
        except Exception as exc:
            raise EvidenceStoreError(
                "invalid_observation", "Evidence observation could not be serialized"
            ) from exc

        connection = self._connection
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT digest, observation_json FROM evidence_receipts "
                "WHERE tenant_id = ? AND evidence_id = ?",
                (tenant_id, evidence_id),
            ).fetchone()
            if row is not None:
                if row["digest"] != digest:
                    raise EvidenceConflict()
                connection.commit()
                return self._decode_receipt(row["observation_json"], row["digest"])
            connection.execute(
                "INSERT INTO evidence_receipts "
                "(tenant_id, evidence_id, digest, observation_json) VALUES (?, ?, ?, ?)",
                (tenant_id, evidence_id, digest, observation_json),
            )
            connection.commit()
            return observation
        except EvidenceConflict:
            _rollback(connection)
            raise
        except sqlite3.Error as exc:
            _rollback(connection)
            raise EvidenceStoreError(
                "receipt_store_unavailable", "Evidence receipt store is unavailable"
            ) from exc

    def get(self, tenant_id: str, evidence_id: str) -> EvidenceObservation | None:
        self._ensure_open()
        try:
            row = self._connection.execute(
                "SELECT digest, observation_json FROM evidence_receipts "
                "WHERE tenant_id = ? AND evidence_id = ?",
                (tenant_id, evidence_id),
            ).fetchone()
        except sqlite3.Error as exc:
            raise EvidenceStoreError(
                "receipt_store_unavailable", "Evidence receipt store is unavailable"
            ) from exc
        if row is None:
            return None
        return self._decode_receipt(row["observation_json"], row["digest"])

    def close(self) -> None:
        if not self._closed:
            self._connection.close()
            self._closed = True

    def __enter__(self) -> SQLiteEvidenceStore:
        self._ensure_open()
        return self

    def __exit__(self, exc_type: Any, exc_value: Any, traceback: Any) -> None:
        del exc_type, exc_value, traceback
        self.close()

    def _decode_receipt(self, serialized: str, stored_digest: str) -> EvidenceObservation:
        try:
            observation = EvidenceObservation.model_validate_json(serialized)
            if _required_text(observation, "content_digest") != stored_digest:
                raise EvidenceStoreError(
                    "receipt_integrity_error", "Stored evidence receipt digest is invalid"
                )
            return observation
        except EvidenceStoreError:
            raise
        except Exception as exc:
            raise EvidenceStoreError(
                "receipt_integrity_error", "Stored evidence receipt is invalid"
            ) from exc

    def _ensure_open(self) -> None:
        if self._closed:
            raise EvidenceStoreError("store_closed", "Evidence store is closed")


def _required_text(value: Any, field_name: str) -> str:
    field_value = getattr(value, field_name, None)
    if not isinstance(field_value, str) or not field_value:
        raise EvidenceStoreError(
            "invalid_observation", "Evidence observation is missing required fields"
        )
    return field_value


def _rollback(connection: sqlite3.Connection) -> None:
    with suppress(sqlite3.Error):
        connection.rollback()
