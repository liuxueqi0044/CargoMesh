"""Offline synthetic DCSA Booking carrier and independent read-only ledger."""

from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
import threading
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Annotated, Any, Literal

import uvicorn
from fastapi import FastAPI, Header, Request, Response
from pydantic import BaseModel, ConfigDict, StringConstraints, model_validator
from starlette.responses import JSONResponse

from .contracts import (
    BookingCancellationRequest,
    BookingCreateRequest,
    BookingCreateResponse,
)

SYNTHETIC_FAULT_HEADER = "X-CargoMesh-Synthetic-Fault"
SYNTHETIC_CARRIER_SCHEMA_VERSION: Literal["cargomesh.synthetic-booking/v1"] = (
    "cargomesh.synthetic-booking/v1"
)
_MAX_IDEMPOTENCY_KEY = 256
_FAULTS = frozenset(
    {
        "normal",
        "reject-before-effect",
        "effect-then-lose-response",
        "ledger-missing",
        "ledger-conflict",
        "cancellation-failure",
    }
)

BookingReference = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=128,
        pattern=r"^CBRR-[A-Za-z0-9_-]{16,96}$",
    ),
]
ExternalReference = Annotated[
    str, StringConstraints(strip_whitespace=True, min_length=1, max_length=_MAX_IDEMPOTENCY_KEY)
]
Sha256Digest = Annotated[str, StringConstraints(pattern=r"^sha256:[0-9a-f]{64}$")]


class SyntheticBookingModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class SyntheticBookingRecord(SyntheticBookingModel):
    """Digest-bound synthetic business record shared only by the local services."""

    schema_version: Literal["cargomesh.synthetic-booking/v1"] = SYNTHETIC_CARRIER_SCHEMA_VERSION
    carrier_booking_request_reference: BookingReference
    external_reference: ExternalReference
    request_digest: Sha256Digest
    request_payload: dict[str, Any]
    booking_status: Literal["RECEIVED", "CANCELLED"] = "RECEIVED"
    synthetic: Literal[True] = True
    created_at: datetime
    updated_at: datetime
    record_digest: Sha256Digest

    @model_validator(mode="after")
    def validate_record(self) -> SyntheticBookingRecord:
        if self.updated_at < self.created_at:
            raise ValueError("booking update cannot precede creation")
        if self.request_digest != value_digest(self.request_payload):
            raise ValueError("booking request digest does not match payload")
        if self.record_digest != model_digest(self, exclude={"record_digest"}):
            raise ValueError("booking record digest does not match")
        return self

    @classmethod
    def issue(cls, **values: object) -> SyntheticBookingRecord:
        payload = dict(values)
        payload.setdefault("schema_version", SYNTHETIC_CARRIER_SCHEMA_VERSION)
        payload.setdefault("synthetic", True)
        request_payload = payload.get("request_payload")
        if not isinstance(request_payload, dict):
            raise ValueError("synthetic booking request is invalid")
        payload["request_digest"] = value_digest(request_payload)
        unsigned = cls.model_construct(_fields_set=set(payload), **payload)
        payload["record_digest"] = model_digest(unsigned, exclude={"record_digest"})
        return cls.model_validate(payload)


class SyntheticCarrierError(RuntimeError):
    """Bounded carrier-store failure with text safe for the synthetic HTTP surface."""

    def __init__(self, code: str, message: str, *, status_code: int) -> None:
        self.code = code
        self.message = message
        self.status_code = status_code
        super().__init__(message)


class SyntheticBookingConflict(SyntheticCarrierError):
    def __init__(self) -> None:
        super().__init__(
            "booking_idempotency_conflict", "Booking request conflicts", status_code=409
        )


class SQLiteSyntheticCarrierStore:
    """Atomic SQLite reference store for a synthetic carrier and separate ledger."""

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
            self._connection.execute("PRAGMA busy_timeout=10000")
            self._initialize()
        except sqlite3.Error as exc:
            raise SyntheticCarrierError(
                "synthetic_carrier_unavailable", "Synthetic carrier is unavailable", status_code=503
            ) from exc

    def create(
        self,
        request: BookingCreateRequest,
        external_reference: str,
        *,
        now: datetime | None = None,
    ) -> tuple[SyntheticBookingRecord, bool]:
        self._ensure_open()
        reference = _external_reference(external_reference)
        request_payload = request.to_dcsa()
        request_digest = value_digest(request_payload)
        occurred_at = _now(now)
        with self._lock:
            c = self._connection
            try:
                c.execute("BEGIN IMMEDIATE")
                row = c.execute(
                    "SELECT * FROM synthetic_bookings WHERE external_reference=?", (reference,)
                ).fetchone()
                if row is not None:
                    current = self._decode(row)
                    if current.request_digest != request_digest:
                        raise SyntheticBookingConflict()
                    c.commit()
                    return current, False
                record = SyntheticBookingRecord.issue(
                    carrier_booking_request_reference=_new_booking_reference(),
                    external_reference=reference,
                    request_payload=request_payload,
                    booking_status="RECEIVED",
                    created_at=occurred_at,
                    updated_at=occurred_at,
                )
                c.execute(
                    "INSERT INTO synthetic_bookings VALUES (?,?,?,?,?,?,?,?)",
                    _row_values(record),
                )
                c.commit()
                return record, True
            except SyntheticCarrierError:
                _rollback(c)
                raise
            except sqlite3.Error as exc:
                _rollback(c)
                raise SyntheticCarrierError(
                    "synthetic_carrier_unavailable",
                    "Synthetic carrier is unavailable",
                    status_code=503,
                ) from exc

    def get(self, carrier_booking_request_reference: str) -> SyntheticBookingRecord | None:
        self._ensure_open()
        with self._lock:
            try:
                row = self._connection.execute(
                    "SELECT * FROM synthetic_bookings WHERE carrier_booking_request_reference=?",
                    (carrier_booking_request_reference,),
                ).fetchone()
            except sqlite3.Error as exc:
                raise SyntheticCarrierError(
                    "synthetic_carrier_unavailable",
                    "Synthetic carrier is unavailable",
                    status_code=503,
                ) from exc
        return None if row is None else self._decode(row)

    def ledger_by_external_reference(
        self, external_reference: str
    ) -> SyntheticBookingRecord | None:
        self._ensure_open()
        reference = _external_reference(external_reference)
        with self._lock:
            try:
                row = self._connection.execute(
                    "SELECT * FROM synthetic_bookings WHERE external_reference=?", (reference,)
                ).fetchone()
            except sqlite3.Error as exc:
                raise SyntheticCarrierError(
                    "synthetic_ledger_unavailable",
                    "Synthetic ledger is unavailable",
                    status_code=503,
                ) from exc
        return None if row is None else self._decode(row)

    def cancel(
        self,
        carrier_booking_request_reference: str,
        *,
        now: datetime | None = None,
    ) -> SyntheticBookingRecord | None:
        self._ensure_open()
        occurred_at = _now(now)
        with self._lock:
            c = self._connection
            try:
                c.execute("BEGIN IMMEDIATE")
                row = c.execute(
                    "SELECT * FROM synthetic_bookings WHERE carrier_booking_request_reference=?",
                    (carrier_booking_request_reference,),
                ).fetchone()
                if row is None:
                    c.commit()
                    return None
                current = self._decode(row)
                if current.booking_status == "CANCELLED":
                    c.commit()
                    return current
                record = SyntheticBookingRecord.issue(
                    carrier_booking_request_reference=current.carrier_booking_request_reference,
                    external_reference=current.external_reference,
                    request_payload=current.request_payload,
                    booking_status="CANCELLED",
                    created_at=current.created_at,
                    updated_at=occurred_at,
                )
                c.execute(
                    "UPDATE synthetic_bookings SET booking_status=?,updated_at=?,record_digest=?,"
                    "record_json=? WHERE carrier_booking_request_reference=?",
                    (
                        record.booking_status,
                        _store_time(record.updated_at),
                        record.record_digest,
                        record.model_dump_json(),
                        carrier_booking_request_reference,
                    ),
                )
                c.commit()
                return record
            except SyntheticCarrierError:
                _rollback(c)
                raise
            except sqlite3.Error as exc:
                _rollback(c)
                raise SyntheticCarrierError(
                    "synthetic_carrier_unavailable",
                    "Synthetic carrier is unavailable",
                    status_code=503,
                ) from exc

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._connection.close()
                self._closed = True

    def _initialize(self) -> None:
        self._connection.execute(
            "CREATE TABLE IF NOT EXISTS synthetic_booking_schema "
            "(component TEXT PRIMARY KEY, version INTEGER NOT NULL)"
        )
        self._connection.execute(
            "INSERT OR IGNORE INTO synthetic_booking_schema(component,version) VALUES (?,1)",
            (SYNTHETIC_CARRIER_SCHEMA_VERSION,),
        )
        self._connection.execute(
            """CREATE TABLE IF NOT EXISTS synthetic_bookings (
                carrier_booking_request_reference TEXT PRIMARY KEY,
                external_reference TEXT NOT NULL UNIQUE,
                request_digest TEXT NOT NULL,
                booking_status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                record_digest TEXT NOT NULL,
                record_json TEXT NOT NULL
            )"""
        )

    @staticmethod
    def _decode(row: sqlite3.Row) -> SyntheticBookingRecord:
        try:
            record = SyntheticBookingRecord.model_validate_json(row["record_json"])
            if (
                record.carrier_booking_request_reference != row["carrier_booking_request_reference"]
                or record.external_reference != row["external_reference"]
                or record.request_digest != row["request_digest"]
                or record.booking_status != row["booking_status"]
                or record.record_digest != row["record_digest"]
            ):
                raise ValueError("stored synthetic booking does not match indexes")
            return record
        except Exception as exc:
            raise SyntheticCarrierError(
                "synthetic_carrier_integrity_error",
                "Stored synthetic booking is invalid",
                status_code=503,
            ) from exc

    def _ensure_open(self) -> None:
        if self._closed:
            raise SyntheticCarrierError(
                "synthetic_carrier_closed", "Synthetic carrier is unavailable", status_code=503
            )


def create_synthetic_carrier(
    store: SQLiteSyntheticCarrierStore | None = None,
    *,
    clock: Callable[[], datetime] | None = None,
) -> FastAPI:
    """Create the write-capable synthetic carrier API; it never reaches a carrier."""

    database = store or SQLiteSyntheticCarrierStore()
    application = FastAPI(title="CargoMesh Synthetic Booking Carrier")

    @application.post("/v2/bookings", status_code=202, response_model=BookingCreateResponse)
    async def create_booking(
        booking: BookingCreateRequest,
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
        fault: str | None = Header(default=None, alias=SYNTHETIC_FAULT_HEADER),
    ) -> BookingCreateResponse:
        mode = _fault_mode(fault)
        if idempotency_key is None:
            raise _http_error(
                "synthetic_idempotency_key_required", "Idempotency-Key is required", 400
            )
        if mode == "reject-before-effect":
            raise _http_error("synthetic_rejected", "Synthetic carrier rejected booking", 422)
        record, _ = database.create(booking, idempotency_key, now=_clock_now(clock))
        if mode == "effect-then-lose-response":
            raise _http_error("synthetic_response_lost", "Synthetic carrier response was lost", 503)
        return BookingCreateResponse.model_validate(
            {"carrierBookingRequestReference": record.carrier_booking_request_reference}
        )

    @application.get("/v2/bookings/{carrier_booking_request_reference}")
    async def get_booking(
        carrier_booking_request_reference: str,
        fault: str | None = Header(default=None, alias=SYNTHETIC_FAULT_HEADER),
    ) -> dict[str, object]:
        _fault_mode(fault)
        record = database.get(carrier_booking_request_reference)
        if record is None:
            raise _http_error("synthetic_booking_not_found", "Synthetic booking was not found", 404)
        return _carrier_view(record)

    @application.patch(
        "/v2/bookings/{carrier_booking_request_reference}",
        status_code=202,
        response_class=Response,
    )
    async def cancel_booking(
        carrier_booking_request_reference: str,
        cancellation: BookingCancellationRequest,
        fault: str | None = Header(default=None, alias=SYNTHETIC_FAULT_HEADER),
    ) -> Response:
        del cancellation
        mode = _fault_mode(fault)
        if mode == "cancellation-failure":
            raise _http_error("synthetic_cancellation_failed", "Synthetic cancellation failed", 503)
        record = database.cancel(carrier_booking_request_reference, now=_clock_now(clock))
        if record is None:
            raise _http_error("synthetic_booking_not_found", "Synthetic booking was not found", 404)
        return Response(status_code=202)

    @application.exception_handler(SyntheticCarrierError)
    async def synthetic_error(_: Request, exc: SyntheticCarrierError) -> JSONResponse:
        return _error_response(exc.code, exc.message, exc.status_code)

    return application


def create_synthetic_ledger(
    store: SQLiteSyntheticCarrierStore,
) -> FastAPI:
    """Create a distinct read-only synthetic system-of-record app over the same DB."""

    application = FastAPI(title="CargoMesh Synthetic Booking Ledger")

    @application.get("/synthetic-ledger/bookings/by-external-reference/{external_reference}")
    async def booking_by_external_reference(
        external_reference: str,
        fault: str | None = Header(default=None, alias=SYNTHETIC_FAULT_HEADER),
    ) -> dict[str, object]:
        mode = _fault_mode(fault)
        if mode == "ledger-missing":
            raise _http_error(
                "synthetic_ledger_not_found", "Synthetic ledger record was not found", 404
            )
        record = store.ledger_by_external_reference(external_reference)
        if record is None:
            raise _http_error(
                "synthetic_ledger_not_found", "Synthetic ledger record was not found", 404
            )
        result = _ledger_view(record)
        if mode == "ledger-conflict":
            result["bookingStatus"] = "CONFLICT"
        return result

    @application.exception_handler(SyntheticCarrierError)
    async def synthetic_error(_: Request, exc: SyntheticCarrierError) -> JSONResponse:
        return _error_response(exc.code, exc.message, exc.status_code)

    return application


create_synthetic_booking_carrier = create_synthetic_carrier
create_synthetic_booking_ledger = create_synthetic_ledger


def run_synthetic_carrier() -> None:
    """Run an explicitly synthetic local carrier for manual development only."""

    store = SQLiteSyntheticCarrierStore("synthetic-booking.sqlite3")
    uvicorn.run(create_synthetic_carrier(store), host="127.0.0.1", port=8091)


def run_synthetic_ledger() -> None:
    """Run an explicitly synthetic local ledger for manual development only."""

    store = SQLiteSyntheticCarrierStore("synthetic-booking.sqlite3")
    uvicorn.run(create_synthetic_ledger(store), host="127.0.0.1", port=8092)


def _carrier_view(record: SyntheticBookingRecord) -> dict[str, object]:
    return {
        "carrierBookingRequestReference": record.carrier_booking_request_reference,
        "bookingStatus": record.booking_status,
    }


def _ledger_view(record: SyntheticBookingRecord) -> dict[str, object]:
    return {
        "carrierBookingRequestReference": record.carrier_booking_request_reference,
        "bookingStatus": record.booking_status,
        "externalReference": record.external_reference,
        "recordDigest": record.record_digest,
        "synthetic": True,
    }


def _fault_mode(value: str | None) -> str:
    mode = "normal" if value is None else value.strip().lower()
    if mode not in _FAULTS:
        raise _http_error("synthetic_fault_invalid", "Synthetic fault mode is invalid", 400)
    return mode


def _http_error(code: str, message: str, status_code: int) -> SyntheticCarrierError:
    return SyntheticCarrierError(code, message, status_code=status_code)


def _external_reference(value: str) -> str:
    if not isinstance(value, str) or not value or len(value) > _MAX_IDEMPOTENCY_KEY:
        raise SyntheticCarrierError(
            "synthetic_idempotency_key_invalid", "Idempotency-Key is invalid", status_code=400
        )
    if value != value.strip() or any(character.isspace() for character in value):
        raise SyntheticCarrierError(
            "synthetic_idempotency_key_invalid", "Idempotency-Key is invalid", status_code=400
        )
    return value


def _new_booking_reference() -> str:
    return "CBRR-" + secrets.token_urlsafe(24)


def _clock_now(clock: Callable[[], datetime] | None) -> datetime | None:
    return None if clock is None else clock()


def _now(value: datetime | None) -> datetime:
    result = datetime.now(UTC) if value is None else value
    if result.tzinfo is None or result.utcoffset() is None:
        raise ValueError("synthetic carrier timestamp must include a timezone")
    return result.astimezone(UTC)


def _store_time(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="microseconds")


def _row_values(record: SyntheticBookingRecord) -> tuple[object, ...]:
    return (
        record.carrier_booking_request_reference,
        record.external_reference,
        record.request_digest,
        record.booking_status,
        _store_time(record.created_at),
        _store_time(record.updated_at),
        record.record_digest,
        record.model_dump_json(),
    )


def model_digest(model: BaseModel, *, exclude: set[str]) -> str:
    return value_digest(model.model_dump(mode="python", exclude=exclude, warnings=False))


def value_digest(value: object) -> str:
    canonical = json.dumps(
        canonical_value(value),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def canonical_value(value: object) -> object:
    if isinstance(value, BaseModel):
        return canonical_value(value.model_dump(mode="python"))
    if isinstance(value, datetime):
        return _now(value).isoformat(timespec="microseconds")
    if isinstance(value, Enum):
        return canonical_value(value.value)
    if isinstance(value, Mapping):
        return {str(key): canonical_value(item) for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        return [canonical_value(item) for item in value]
    return value


def _error_response(code: str, message: str, status_code: int) -> JSONResponse:
    return JSONResponse(
        status_code=status_code, content={"error": {"code": code, "message": message}}
    )


def _rollback(connection: sqlite3.Connection) -> None:
    with suppress(sqlite3.Error):
        connection.rollback()


__all__ = [
    "SYNTHETIC_CARRIER_SCHEMA_VERSION",
    "SYNTHETIC_FAULT_HEADER",
    "SQLiteSyntheticCarrierStore",
    "SyntheticBookingConflict",
    "SyntheticBookingRecord",
    "SyntheticCarrierError",
    "create_synthetic_booking_carrier",
    "create_synthetic_booking_ledger",
    "create_synthetic_carrier",
    "create_synthetic_ledger",
    "run_synthetic_carrier",
    "run_synthetic_ledger",
]
