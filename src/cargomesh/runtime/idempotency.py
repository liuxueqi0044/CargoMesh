"""Atomic, local idempotency reservations for transaction submission."""

from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from threading import RLock
from typing import Protocol, cast

_MAX_IDENTIFIER_LENGTH = 256
_MAX_ERROR_CODE_LENGTH = 128
_BUSINESS_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class SubmissionState(StrEnum):
    """Lifecycle of a reserved workflow start request."""

    RESERVED = "RESERVED"
    STARTED = "STARTED"
    START_FAILED = "START_FAILED"


@dataclass(frozen=True, slots=True)
class SubmissionReservation:
    """Immutable result of reserving or looking up a submitted transaction."""

    tenant_id: str
    idempotency_key: str
    transaction_id: str
    workflow_id: str
    business_digest: str
    state: SubmissionState
    created_at: datetime
    updated_at: datetime
    start_error_code: str | None
    created: bool

    @property
    def error_code(self) -> str | None:
        """Compatibility-friendly name for the workflow-start failure code."""

        return self.start_error_code


class IdempotencyConflict(ValueError):
    """A key was replayed for a different immutable business request."""

    def __init__(self) -> None:
        super().__init__("idempotency key is already bound to a different request")


class SubmissionNotFound(LookupError):
    """No submission is indexed for the requested transaction identifier."""

    def __init__(self) -> None:
        super().__init__("submission was not found")


class SubmissionIdentifierConflict(ValueError):
    """A supposedly unique transaction or workflow ID was already reserved."""

    def __init__(self) -> None:
        super().__init__("transaction or workflow identifier is already reserved")


class InvalidSubmissionState(ValueError):
    """A lifecycle mutation was attempted from an incompatible state."""

    def __init__(self, state: SubmissionState) -> None:
        super().__init__(f"submission is in {state.value} state")
        self.state = state


class SubmissionStore(Protocol):
    """Storage boundary for submission reservations, independent of workflows."""

    def reserve(
        self,
        tenant_id: str,
        idempotency_key: str,
        transaction_id: str,
        workflow_id: str,
        business_digest: str,
    ) -> SubmissionReservation:
        """Create or replay a reservation for a tenant-scoped idempotency key."""

    def mark_started(self, transaction_id: str) -> SubmissionReservation:
        """Record a successful workflow start."""

    def mark_start_failed(self, transaction_id: str, error_code: str) -> SubmissionReservation:
        """Record a failed workflow start that can later be retried."""

    def lookup_by_transaction_id(self, transaction_id: str) -> SubmissionReservation | None:
        """Look up an existing reservation by its stable transaction ID."""


class SQLiteSubmissionStore:
    """A sqlite-backed implementation using ``BEGIN IMMEDIATE`` reservations.

    The default ``:memory:`` target supports process-local tests and callers;
    a filesystem path persists reservations across store instances.  SQLite's
    unique primary key protects callers in different processes, while the
    instance lock safely shares one sqlite connection between Python threads.
    """

    def __init__(self, database: str | Path = ":memory:", *, timeout_seconds: float = 5.0) -> None:
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self._connection = sqlite3.connect(
            str(database),
            check_same_thread=False,
            isolation_level=None,
            timeout=timeout_seconds,
        )
        self._connection.row_factory = sqlite3.Row
        self._lock = RLock()
        self._create_schema()

    def reserve(
        self,
        tenant_id: str,
        idempotency_key: str,
        transaction_id: str,
        workflow_id: str,
        business_digest: str,
    ) -> SubmissionReservation:
        """Atomically reserve a key, replay it, or retry a failed start.

        A same-digest replay returns the original IDs.  If its last start
        failed, the replay resets the reservation to ``RESERVED`` while still
        retaining those IDs, so it can safely attempt the same workflow again.
        """

        _validate_identifier("tenant_id", tenant_id)
        _validate_identifier("idempotency_key", idempotency_key)
        _validate_identifier("transaction_id", transaction_id)
        _validate_identifier("workflow_id", workflow_id)
        _validate_business_digest(business_digest)

        with self._lock:
            self._begin()
            try:
                row = self._select_by_key(tenant_id, idempotency_key)
                if row is not None:
                    result = self._replay_or_retry(row, business_digest)
                    self._connection.commit()
                    return result

                now = _utc_now()
                self._connection.execute(
                    """
                    INSERT INTO submission_reservations (
                        tenant_id, idempotency_key, transaction_id, workflow_id,
                        business_digest, state, created_at, updated_at, start_error_code
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)
                    """,
                    (
                        tenant_id,
                        idempotency_key,
                        transaction_id,
                        workflow_id,
                        business_digest,
                        SubmissionState.RESERVED.value,
                        _format_timestamp(now),
                        _format_timestamp(now),
                    ),
                )
                self._connection.commit()
                return SubmissionReservation(
                    tenant_id=tenant_id,
                    idempotency_key=idempotency_key,
                    transaction_id=transaction_id,
                    workflow_id=workflow_id,
                    business_digest=business_digest,
                    state=SubmissionState.RESERVED,
                    created_at=now,
                    updated_at=now,
                    start_error_code=None,
                    created=True,
                )
            except sqlite3.IntegrityError:
                self._rollback_if_needed()
                raise SubmissionIdentifierConflict() from None
            except Exception:
                self._rollback_if_needed()
                raise

    def mark_started(self, transaction_id: str) -> SubmissionReservation:
        """Move a reservation from ``RESERVED`` to ``STARTED`` idempotently."""

        _validate_identifier("transaction_id", transaction_id)
        with self._lock:
            self._begin()
            try:
                row = self._require_by_transaction_id(transaction_id)
                current = self._reservation_from_row(row)
                if current.state is SubmissionState.STARTED:
                    self._connection.commit()
                    return current
                if current.state is not SubmissionState.RESERVED:
                    raise InvalidSubmissionState(current.state)
                updated = _utc_now()
                self._connection.execute(
                    """
                    UPDATE submission_reservations
                    SET state = ?, updated_at = ?, start_error_code = NULL
                    WHERE transaction_id = ?
                    """,
                    (SubmissionState.STARTED.value, _format_timestamp(updated), transaction_id),
                )
                self._connection.commit()
                return _replace_reservation(
                    current,
                    state=SubmissionState.STARTED,
                    updated_at=updated,
                    start_error_code=None,
                )
            except Exception:
                self._rollback_if_needed()
                raise

    def mark_start_failed(self, transaction_id: str, error_code: str) -> SubmissionReservation:
        """Move a reservation from ``RESERVED`` to retryable ``START_FAILED``."""

        _validate_identifier("transaction_id", transaction_id)
        _validate_error_code(error_code)
        with self._lock:
            self._begin()
            try:
                row = self._require_by_transaction_id(transaction_id)
                current = self._reservation_from_row(row)
                if (
                    current.state is SubmissionState.START_FAILED
                    and current.start_error_code == error_code
                ):
                    self._connection.commit()
                    return current
                if current.state is not SubmissionState.RESERVED:
                    raise InvalidSubmissionState(current.state)
                updated = _utc_now()
                self._connection.execute(
                    """
                    UPDATE submission_reservations
                    SET state = ?, updated_at = ?, start_error_code = ?
                    WHERE transaction_id = ?
                    """,
                    (
                        SubmissionState.START_FAILED.value,
                        _format_timestamp(updated),
                        error_code,
                        transaction_id,
                    ),
                )
                self._connection.commit()
                return _replace_reservation(
                    current,
                    state=SubmissionState.START_FAILED,
                    updated_at=updated,
                    start_error_code=error_code,
                )
            except Exception:
                self._rollback_if_needed()
                raise

    def lookup_by_transaction_id(self, transaction_id: str) -> SubmissionReservation | None:
        """Return a stored reservation without changing it."""

        _validate_identifier("transaction_id", transaction_id)
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM submission_reservations WHERE transaction_id = ?", (transaction_id,)
            ).fetchone()
        return None if row is None else self._reservation_from_row(row)

    def lookup(self, transaction_id: str) -> SubmissionReservation | None:
        """Alias for :meth:`lookup_by_transaction_id`."""

        return self.lookup_by_transaction_id(transaction_id)

    def get_by_transaction_id(self, transaction_id: str) -> SubmissionReservation | None:
        """Alias for :meth:`lookup_by_transaction_id`."""

        return self.lookup_by_transaction_id(transaction_id)

    def close(self) -> None:
        """Release the SQLite connection; useful before reopening a file store."""

        with self._lock:
            self._connection.close()

    def _create_schema(self) -> None:
        with self._lock:
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS submission_reservations (
                    tenant_id TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    transaction_id TEXT NOT NULL UNIQUE,
                    workflow_id TEXT NOT NULL UNIQUE,
                    business_digest TEXT NOT NULL,
                    state TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    start_error_code TEXT,
                    PRIMARY KEY (tenant_id, idempotency_key)
                )
                """
            )

    def _begin(self) -> None:
        self._connection.execute("BEGIN IMMEDIATE")

    def _rollback_if_needed(self) -> None:
        if self._connection.in_transaction:
            self._connection.rollback()

    def _select_by_key(self, tenant_id: str, idempotency_key: str) -> sqlite3.Row | None:
        return cast(
            sqlite3.Row | None,
            self._connection.execute(
                """
                SELECT * FROM submission_reservations
                WHERE tenant_id = ? AND idempotency_key = ?
                """,
                (tenant_id, idempotency_key),
            ).fetchone(),
        )

    def _require_by_transaction_id(self, transaction_id: str) -> sqlite3.Row:
        row = cast(
            sqlite3.Row | None,
            self._connection.execute(
                "SELECT * FROM submission_reservations WHERE transaction_id = ?",
                (transaction_id,),
            ).fetchone(),
        )
        if row is None:
            raise SubmissionNotFound()
        return row

    def _replay_or_retry(self, row: sqlite3.Row, business_digest: str) -> SubmissionReservation:
        current = self._reservation_from_row(row)
        if current.business_digest != business_digest:
            raise IdempotencyConflict()
        if current.state is not SubmissionState.START_FAILED:
            return current
        updated = _utc_now()
        self._connection.execute(
            """
            UPDATE submission_reservations
            SET state = ?, updated_at = ?, start_error_code = NULL
            WHERE transaction_id = ?
            """,
            (SubmissionState.RESERVED.value, _format_timestamp(updated), current.transaction_id),
        )
        return _replace_reservation(
            current,
            state=SubmissionState.RESERVED,
            updated_at=updated,
            start_error_code=None,
        )

    @staticmethod
    def _reservation_from_row(row: sqlite3.Row) -> SubmissionReservation:
        return SubmissionReservation(
            tenant_id=str(row["tenant_id"]),
            idempotency_key=str(row["idempotency_key"]),
            transaction_id=str(row["transaction_id"]),
            workflow_id=str(row["workflow_id"]),
            business_digest=str(row["business_digest"]),
            state=SubmissionState(str(row["state"])),
            created_at=_parse_timestamp(str(row["created_at"])),
            updated_at=_parse_timestamp(str(row["updated_at"])),
            start_error_code=None
            if row["start_error_code"] is None
            else str(row["start_error_code"]),
            created=False,
        )


def _replace_reservation(
    reservation: SubmissionReservation,
    *,
    state: SubmissionState,
    updated_at: datetime,
    start_error_code: str | None,
) -> SubmissionReservation:
    return SubmissionReservation(
        tenant_id=reservation.tenant_id,
        idempotency_key=reservation.idempotency_key,
        transaction_id=reservation.transaction_id,
        workflow_id=reservation.workflow_id,
        business_digest=reservation.business_digest,
        state=state,
        created_at=reservation.created_at,
        updated_at=updated_at,
        start_error_code=start_error_code,
        created=False,
    )


def _validate_identifier(name: str, value: str) -> None:
    if not isinstance(value, str) or value != value.strip() or not value:
        raise ValueError(f"{name} must be a non-empty, whitespace-trimmed string")
    if len(value) > _MAX_IDENTIFIER_LENGTH:
        raise ValueError(f"{name} must be at most {_MAX_IDENTIFIER_LENGTH} characters")


def _validate_business_digest(value: str) -> None:
    if not isinstance(value, str) or _BUSINESS_DIGEST_RE.fullmatch(value) is None:
        raise ValueError("business_digest must be a lowercase sha256 digest")


def _validate_error_code(value: str) -> None:
    if not isinstance(value, str) or value != value.strip() or not value:
        raise ValueError("error_code must be a non-empty, whitespace-trimmed string")
    if len(value) > _MAX_ERROR_CODE_LENGTH:
        raise ValueError(f"error_code must be at most {_MAX_ERROR_CODE_LENGTH} characters")


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _format_timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)
