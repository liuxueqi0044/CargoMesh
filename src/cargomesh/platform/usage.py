"""Tenant-scoped, verification-gated usage metering."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from collections.abc import Mapping, Sequence
from contextlib import suppress
from pathlib import Path
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from cargomesh.verification.models import VerificationReport, VerificationVerdict

Sha256Digest = Annotated[str, StringConstraints(pattern=r"^sha256:[0-9a-f]{64}$")]
Identifier = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=1, max_length=256),
]


class UsageModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class UsageError(RuntimeError):
    def __init__(self, code: str, message: str = "Usage operation failed") -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class UsageConflict(UsageError):
    def __init__(self) -> None:
        super().__init__("usage_conflict", "Usage meter conflicts with existing metadata")


class MeterRecord(UsageModel):
    tenant_id: Identifier
    environment_id: Identifier
    transaction_id: Identifier
    capability_digest: Sha256Digest
    verification_report_digest: Sha256Digest
    units: int = Field(ge=1, le=2**63 - 1, strict=True)
    meter_digest: Sha256Digest

    @model_validator(mode="after")
    def validate_digest(self) -> MeterRecord:
        if self.meter_digest != _digest(self.model_dump(exclude={"meter_digest"})):
            raise ValueError("usage meter digest does not match")
        return self

    @classmethod
    def issue(cls, **values: object) -> MeterRecord:
        payload = dict(values)
        unsigned = cls.model_construct(_fields_set=set(payload), **payload)
        payload["meter_digest"] = _digest(unsigned.model_dump())
        return cls.model_validate(payload)


class SQLiteUsageMeter:
    """A metadata-only meter with one immutable row per transaction scope."""

    def __init__(self, database: str | Path = ":memory:") -> None:
        self._database = str(database)
        self._lock = threading.RLock()
        self._closed = False
        try:
            self._connection = sqlite3.connect(
                self._database, isolation_level=None, check_same_thread=False, timeout=10
            )
            self._connection.row_factory = sqlite3.Row
            self._connection.execute("PRAGMA busy_timeout=10000")
            self._connection.execute("PRAGMA foreign_keys=ON")
            if self._database != ":memory:":
                self._connection.execute("PRAGMA journal_mode=WAL")
            self._connection.execute(
                "CREATE TABLE IF NOT EXISTS usage_meters ("
                "tenant_id TEXT NOT NULL, environment_id TEXT NOT NULL, "
                "transaction_id TEXT NOT NULL, capability_digest TEXT NOT NULL, "
                "verification_report_digest TEXT NOT NULL, units INTEGER NOT NULL, "
                "meter_digest TEXT NOT NULL, "
                "PRIMARY KEY (tenant_id, environment_id, transaction_id), "
                "UNIQUE (verification_report_digest))"
            )
        except sqlite3.Error as exc:
            raise UsageError("usage_store_unavailable") from exc

    def record(
        self,
        report: VerificationReport,
        *,
        tenant_id: str,
        environment_id: str,
        transaction_id: str,
        capability_digest: str,
        units: int,
    ) -> MeterRecord:
        self._ensure_open()
        if not isinstance(report, VerificationReport):
            raise UsageError("verification_report_invalid")
        try:
            verified_report = VerificationReport.model_validate(report.model_dump(mode="python"))
        except Exception as exc:
            raise UsageError("verification_report_invalid") from exc
        if verified_report.verdict is not VerificationVerdict.VERIFIED:
            raise UsageError("usage_not_verified")
        if verified_report.synthetic or any(item.synthetic for item in verified_report.evidence):
            raise UsageError("usage_synthetic_not_billable")
        if verified_report.transaction_id != transaction_id:
            raise UsageError("usage_scope_mismatch")
        try:
            record = MeterRecord.issue(
                tenant_id=tenant_id,
                environment_id=environment_id,
                transaction_id=transaction_id,
                capability_digest=capability_digest,
                verification_report_digest=verified_report.report_digest,
                units=units,
            )
        except Exception as exc:
            raise UsageError("usage_meter_invalid") from exc
        with self._lock:
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                report_row = self._connection.execute(
                    "SELECT * FROM usage_meters WHERE verification_report_digest=?",
                    (record.verification_report_digest,),
                ).fetchone()
                if report_row is not None:
                    existing_report = _decode(report_row)
                    if existing_report != record:
                        raise UsageConflict()
                    self._connection.commit()
                    return existing_report
                row = self._connection.execute(
                    "SELECT * FROM usage_meters WHERE tenant_id=? AND environment_id=? "
                    "AND transaction_id=?",
                    (tenant_id, environment_id, transaction_id),
                ).fetchone()
                if row is not None:
                    existing = _decode(row)
                    if existing != record:
                        raise UsageConflict()
                    self._connection.commit()
                    return existing
                self._connection.execute(
                    "INSERT INTO usage_meters VALUES (?,?,?,?,?,?,?)",
                    (
                        record.tenant_id,
                        record.environment_id,
                        record.transaction_id,
                        record.capability_digest,
                        record.verification_report_digest,
                        record.units,
                        record.meter_digest,
                    ),
                )
                self._connection.commit()
                return record
            except UsageError:
                _rollback(self._connection)
                raise
            except sqlite3.Error as exc:
                _rollback(self._connection)
                raise UsageError("usage_store_unavailable") from exc

    meter = record

    def get(
        self, *, tenant_id: str, environment_id: str, transaction_id: str
    ) -> MeterRecord | None:
        self._ensure_open()
        with self._lock:
            try:
                row = self._connection.execute(
                    "SELECT * FROM usage_meters WHERE tenant_id=? AND environment_id=? "
                    "AND transaction_id=?",
                    (tenant_id, environment_id, transaction_id),
                ).fetchone()
                return None if row is None else _decode(row)
            except sqlite3.Error as exc:
                raise UsageError("usage_store_unavailable") from exc

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._connection.close()
                self._closed = True

    def __enter__(self) -> SQLiteUsageMeter:
        self._ensure_open()
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _ensure_open(self) -> None:
        if self._closed:
            raise UsageError("usage_store_closed")


UsageMeter = SQLiteUsageMeter
UsageRecord = MeterRecord


def _decode(row: sqlite3.Row) -> MeterRecord:
    try:
        return MeterRecord.model_validate(dict(row))
    except Exception as exc:
        raise UsageError("usage_record_invalid") from exc


def _rollback(connection: sqlite3.Connection) -> None:
    with suppress(sqlite3.Error):
        connection.rollback()


def _canonical(value: object) -> object:
    if isinstance(value, BaseModel):
        return _canonical(value.model_dump(mode="python"))
    if isinstance(value, Mapping):
        return {str(key): _canonical(item) for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        return [_canonical(item) for item in value]
    return value


def _digest(value: object) -> str:
    encoded = json.dumps(
        _canonical(value), ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


__all__ = [
    "Identifier",
    "MeterRecord",
    "SQLiteUsageMeter",
    "Sha256Digest",
    "UsageConflict",
    "UsageError",
    "UsageMeter",
    "UsageModel",
    "UsageRecord",
]
