"""Transactional, metadata-only repair budget reservation ledger."""

from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from pydantic import model_validator

from .models import (
    RepairBudget,
    RepairIdentifier,
    RepairModel,
    RepairRequest,
    RepairUsage,
    Sha256Digest,
    _digest,
)


class RepairBudgetError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class BudgetConflict(RepairBudgetError):
    def __init__(self) -> None:
        super().__init__("budget_conflict", "Budget reservation conflicts with existing metadata")


class BudgetExceeded(RepairBudgetError):
    def __init__(self) -> None:
        super().__init__("budget_exceeded", "Repair budget is exhausted")


class BudgetNotFound(RepairBudgetError):
    def __init__(self) -> None:
        super().__init__("budget_reservation_not_found", "Budget reservation was not found")


class BudgetReservation(RepairModel):
    reservation_id: RepairIdentifier
    tenant_id: RepairIdentifier
    environment_id: RepairIdentifier
    job_id: RepairIdentifier
    request_digest: Sha256Digest
    budget_digest: Sha256Digest
    reserved: RepairUsage
    status: Literal["RESERVED", "FINALIZED"]
    actual: RepairUsage | None = None
    reserved_at: datetime
    reservation_digest: Sha256Digest

    @model_validator(mode="after")
    def validate_reservation(self) -> BudgetReservation:
        if self.reserved_at.tzinfo is None or self.reserved_at.utcoffset() is None:
            raise ValueError("budget reservation time must include a timezone")
        if self.status == "RESERVED" and self.actual is not None:
            raise ValueError("reserved budget cannot contain actual usage")
        if self.status == "FINALIZED" and self.actual is None:
            raise ValueError("finalized budget requires actual usage")
        if self.actual is not None and not _usage_leq(self.actual, self.reserved):
            raise ValueError("actual usage cannot exceed reserved usage")
        if self.reservation_digest != _digest(self.model_dump(exclude={"reservation_digest"})):
            raise ValueError("budget reservation digest does not match metadata")
        return self

    @classmethod
    def issue(cls, **values: object) -> BudgetReservation:
        payload = dict(values)
        payload.setdefault("reserved_at", datetime.now(UTC))
        unsigned = cls.model_construct(_fields_set=set(payload), **payload)
        payload["reservation_digest"] = _digest(unsigned.model_dump())
        return cls.model_validate(payload)

    @property
    def digest(self) -> str:
        return self.reservation_digest


class SQLiteRepairBudgetLedger:
    """A tenant/environment/job scoped reserve-before-use SQLite ledger."""

    SCHEMA_VERSION = 1

    def __init__(self, database: str | Path = ":memory:") -> None:
        self._database = str(database)
        self._closed = False
        self._lock = threading.RLock()
        try:
            self._connection = sqlite3.connect(
                self._database, isolation_level=None, check_same_thread=False, timeout=10
            )
            self._connection.row_factory = sqlite3.Row
            self._connection.execute("PRAGMA foreign_keys=ON")
            self._connection.execute("PRAGMA busy_timeout=10000")
            if self._database != ":memory:":
                self._connection.execute("PRAGMA journal_mode=WAL")
            self._initialize_schema()
        except sqlite3.Error as exc:
            raise RepairBudgetError(
                "budget_store_unavailable", "Budget ledger is unavailable"
            ) from exc

    def reserve(
        self,
        request: RepairRequest,
        budget: RepairBudget,
        usage: RepairUsage,
        *,
        reservation_id: str | None = None,
    ) -> BudgetReservation:
        self._ensure_open()
        request = RepairRequest.model_validate(request.model_dump())
        budget = RepairBudget.model_validate(budget.model_dump())
        usage = RepairUsage.model_validate(usage.model_dump())
        _within_budget(usage, budget)
        key = reservation_id or request.request_digest
        with self._lock:
            connection = self._connection
            try:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    "SELECT * FROM repair_budget_reservations WHERE reservation_id=?", (key,)
                ).fetchone()
                if row is not None:
                    existing = _decode_reservation(row)
                    if (
                        existing.tenant_id != request.tenant_id
                        or existing.environment_id != request.environment_id
                        or existing.job_id != request.job_id
                        or existing.request_digest != request.request_digest
                        or existing.budget_digest != budget.budget_digest
                        or existing.reserved != usage
                    ):
                        raise BudgetConflict()
                    connection.commit()
                    return existing
                budget_rows = connection.execute(
                    "SELECT budget_digest,request_digest FROM repair_budget_reservations "
                    "WHERE tenant_id=? AND environment_id=? AND job_id=? LIMIT 1",
                    (request.tenant_id, request.environment_id, request.job_id),
                ).fetchone()
                if budget_rows is not None and (
                    budget_rows["budget_digest"] != budget.budget_digest
                    or budget_rows["request_digest"] != request.request_digest
                ):
                    raise BudgetConflict()
                current = self._scope_usage(connection, request)
                if not _usage_fits_sum(current, usage, budget):
                    raise BudgetExceeded()
                reservation = BudgetReservation.issue(
                    reservation_id=key,
                    tenant_id=request.tenant_id,
                    environment_id=request.environment_id,
                    job_id=request.job_id,
                    request_digest=request.request_digest,
                    budget_digest=budget.budget_digest,
                    reserved=usage,
                    status="RESERVED",
                    actual=None,
                )
                connection.execute(
                    "INSERT INTO repair_budget_reservations "
                    "(reservation_id,tenant_id,environment_id,job_id,request_digest,budget_digest,"
                    "budget_json,reserved_json,status,actual_json,reserved_at,reservation_digest) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        reservation.reservation_id,
                        reservation.tenant_id,
                        reservation.environment_id,
                        reservation.job_id,
                        reservation.request_digest,
                        reservation.budget_digest,
                        budget.model_dump_json(),
                        usage.model_dump_json(),
                        reservation.status,
                        None,
                        reservation.reserved_at.isoformat(),
                        reservation.reservation_digest,
                    ),
                )
                connection.commit()
                return reservation
            except RepairBudgetError:
                _rollback(connection)
                raise
            except sqlite3.Error as exc:
                _rollback(connection)
                raise RepairBudgetError(
                    "budget_store_unavailable", "Budget ledger is unavailable"
                ) from exc

    def reserve_before_use(
        self,
        request: RepairRequest,
        budget: RepairBudget,
        usage: RepairUsage,
        *,
        reservation_id: str | None = None,
    ) -> BudgetReservation:
        return self.reserve(request, budget, usage, reservation_id=reservation_id)

    def finalize(
        self,
        reservation: BudgetReservation,
        actual: RepairUsage,
    ) -> BudgetReservation:
        self._ensure_open()
        actual = RepairUsage.model_validate(actual.model_dump())
        with self._lock:
            connection = self._connection
            try:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    "SELECT * FROM repair_budget_reservations WHERE reservation_id=?",
                    (reservation.reservation_id,),
                ).fetchone()
                if row is None:
                    raise BudgetNotFound()
                existing = _decode_reservation(row)
                if (
                    existing.tenant_id != reservation.tenant_id
                    or existing.environment_id != reservation.environment_id
                    or existing.job_id != reservation.job_id
                    or existing.request_digest != reservation.request_digest
                ):
                    raise BudgetConflict()
                if existing.status == "FINALIZED":
                    if existing.actual != actual:
                        raise BudgetConflict()
                    connection.commit()
                    return existing
                try:
                    budget = RepairBudget.model_validate(json.loads(row["budget_json"]))
                except Exception as exc:
                    raise RepairBudgetError(
                        "budget_record_invalid", "Budget ledger record is invalid"
                    ) from exc
                if budget.budget_digest != existing.budget_digest:
                    raise RepairBudgetError(
                        "budget_record_invalid", "Budget ledger record is invalid"
                    )
                if not _usage_leq(actual, existing.reserved) or not _usage_leq(actual, budget):
                    raise BudgetExceeded()
                finalized = BudgetReservation.issue(
                    reservation_id=existing.reservation_id,
                    tenant_id=existing.tenant_id,
                    environment_id=existing.environment_id,
                    job_id=existing.job_id,
                    request_digest=existing.request_digest,
                    budget_digest=existing.budget_digest,
                    reserved=existing.reserved,
                    status="FINALIZED",
                    actual=actual,
                    reserved_at=existing.reserved_at,
                )
                connection.execute(
                    "UPDATE repair_budget_reservations SET "
                    "status=?,actual_json=?,reservation_digest=? "
                    "WHERE reservation_id=?",
                    (
                        finalized.status,
                        actual.model_dump_json(),
                        finalized.reservation_digest,
                        finalized.reservation_id,
                    ),
                )
                connection.commit()
                return finalized
            except RepairBudgetError:
                _rollback(connection)
                raise
            except sqlite3.Error as exc:
                _rollback(connection)
                raise RepairBudgetError(
                    "budget_store_unavailable", "Budget ledger is unavailable"
                ) from exc

    def get(
        self,
        reservation_id: str,
        *,
        tenant_id: str,
        environment_id: str,
        job_id: str,
    ) -> BudgetReservation | None:
        self._ensure_open()
        with self._lock:
            try:
                row = self._connection.execute(
                    "SELECT * FROM repair_budget_reservations "
                    "WHERE reservation_id=? AND tenant_id=? AND environment_id=? AND job_id=?",
                    (reservation_id, tenant_id, environment_id, job_id),
                ).fetchone()
                return None if row is None else _decode_reservation(row)
            except sqlite3.Error as exc:
                raise RepairBudgetError(
                    "budget_store_unavailable", "Budget ledger is unavailable"
                ) from exc

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._connection.close()
                self._closed = True

    def __enter__(self) -> SQLiteRepairBudgetLedger:
        self._ensure_open()
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _scope_usage(self, connection: sqlite3.Connection, request: RepairRequest) -> RepairUsage:
        rows = connection.execute(
            "SELECT * FROM repair_budget_reservations "
            "WHERE tenant_id=? AND environment_id=? AND job_id=?",
            (request.tenant_id, request.environment_id, request.job_id),
        ).fetchall()
        totals = {field: 0 for field in RepairUsage.model_fields}
        try:
            for row in rows:
                reservation = _decode_reservation(row)
                value = (
                    reservation.actual
                    if reservation.status == "FINALIZED"
                    else reservation.reserved
                )
                assert value is not None
                for field in totals:
                    totals[field] += getattr(value, field)
        except Exception as exc:
            raise RepairBudgetError(
                "budget_record_invalid", "Budget ledger record is invalid"
            ) from exc
        return RepairUsage.model_construct(_fields_set=set(totals), **totals)

    def _initialize_schema(self) -> None:
        self._connection.execute(
            "CREATE TABLE IF NOT EXISTS repair_budget_reservations ("
            "reservation_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, "
            "environment_id TEXT NOT NULL,"
            "job_id TEXT NOT NULL, request_digest TEXT NOT NULL, budget_digest TEXT NOT NULL,"
            "budget_json TEXT NOT NULL, reserved_json TEXT NOT NULL, status TEXT NOT NULL,"
            "actual_json TEXT, reserved_at TEXT NOT NULL, reservation_digest TEXT NOT NULL)"
        )

    def _ensure_open(self) -> None:
        if self._closed:
            raise RepairBudgetError("budget_store_closed", "Budget ledger is unavailable")


RepairBudgetLedger = SQLiteRepairBudgetLedger


def _within_budget(usage: RepairUsage, budget: RepairBudget) -> None:
    if not _usage_leq(usage, budget):
        raise BudgetExceeded()


def _usage_leq(left: RepairUsage, right: RepairUsage | RepairBudget) -> bool:
    fields = (
        ("model_calls", "max_model_calls"),
        ("input_tokens", "max_input_tokens"),
        ("output_tokens", "max_output_tokens"),
        ("cost_units", "max_cost_units"),
        ("files", "max_files"),
        ("candidate_bytes", "max_candidate_bytes"),
        ("validation_seconds", "max_validation_seconds"),
    )
    if isinstance(right, RepairUsage):
        return all(
            getattr(left, usage_name) <= getattr(right, usage_name) for usage_name, _ in fields
        )
    return all(
        getattr(left, usage_name) <= getattr(right, limit_name) for usage_name, limit_name in fields
    )


def _usage_fits_sum(current: RepairUsage, requested: RepairUsage, budget: RepairBudget) -> bool:
    limits = {
        "model_calls": "max_model_calls",
        "input_tokens": "max_input_tokens",
        "output_tokens": "max_output_tokens",
        "cost_units": "max_cost_units",
        "files": "max_files",
        "candidate_bytes": "max_candidate_bytes",
        "validation_seconds": "max_validation_seconds",
    }
    return all(
        getattr(current, field) + getattr(requested, field) <= getattr(budget, limit)
        for field, limit in limits.items()
    )


def _decode_reservation(row: sqlite3.Row) -> BudgetReservation:
    try:
        return BudgetReservation.model_validate(
            {
                "reservation_id": row["reservation_id"],
                "tenant_id": row["tenant_id"],
                "environment_id": row["environment_id"],
                "job_id": row["job_id"],
                "request_digest": row["request_digest"],
                "budget_digest": row["budget_digest"],
                "reserved": RepairUsage.model_validate(json.loads(row["reserved_json"])),
                "status": row["status"],
                "actual": None
                if row["actual_json"] is None
                else RepairUsage.model_validate(json.loads(row["actual_json"])),
                "reserved_at": datetime.fromisoformat(row["reserved_at"]),
                "reservation_digest": row["reservation_digest"],
            }
        )
    except Exception as exc:
        raise RepairBudgetError("budget_record_invalid", "Budget ledger record is invalid") from exc


def _rollback(connection: sqlite3.Connection) -> None:
    with suppress(sqlite3.Error):
        connection.rollback()


__all__ = [
    "BudgetConflict",
    "BudgetExceeded",
    "BudgetNotFound",
    "BudgetReservation",
    "RepairBudgetError",
    "RepairBudgetLedger",
    "SQLiteRepairBudgetLedger",
]
