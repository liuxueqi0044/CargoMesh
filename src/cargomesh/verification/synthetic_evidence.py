"""A separate, deterministic synthetic system-of-record evidence service."""

from __future__ import annotations

import argparse
import asyncio
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Final, Literal

from fastapi import FastAPI, HTTPException

EvidenceVariant = Literal["healthy", "conflict", "missing", "stale", "server_error"]
_VARIANTS: Final[frozenset[str]] = frozenset(
    {"healthy", "conflict", "missing", "stale", "server_error"}
)
_SCHEMA_VERSION: Final[str] = "cargomesh.synthetic-evidence/v1"
_RECORDS: Final[dict[str, str]] = {
    "CBR-001": "IN_TRANSIT",
    "CBR-002": "DELIVERED",
}
_STALE_AGE: Final[timedelta] = timedelta(days=365)


def create_synthetic_evidence_service(
    variant: EvidenceVariant = "healthy",
    delay_ms: int = 0,
    clock: Callable[[], datetime] | None = None,
) -> FastAPI:
    """Create a local synthetic ledger service with deterministic fault injection.

    The injected clock is evaluated exactly once while constructing the app.
    Therefore every successful response from one service instance has the same
    timestamp, which makes collector retries and test replays stable.
    """

    if not isinstance(variant, str) or variant not in _VARIANTS:
        raise ValueError(f"unknown synthetic evidence variant: {variant}")
    if not isinstance(delay_ms, int) or isinstance(delay_ms, bool) or not 0 <= delay_ms <= 5000:
        raise ValueError("delay_ms must be an integer between 0 and 5000")
    observed_at = _require_aware_utc((clock or _utc_now)())
    if variant == "stale":
        observed_at -= _STALE_AGE
    observed_at_text = _format_timestamp(observed_at)

    application = FastAPI(title="CargoMesh Synthetic Evidence Ledger", version="1.0.0")

    @application.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok", "service": "synthetic-evidence"}

    @application.get("/v1/evidence/shipments/{reference}")
    async def shipment_evidence(reference: str) -> dict[str, object]:
        if delay_ms:
            await asyncio.sleep(delay_ms / 1000)
        if variant == "server_error":
            raise HTTPException(status_code=503, detail="synthetic evidence service unavailable")
        if variant == "missing" or reference not in _RECORDS:
            raise HTTPException(status_code=404, detail="synthetic evidence record not found")
        status = _RECORDS[reference]
        if variant == "conflict" and reference == "CBR-001":
            status = "DELAYED"
        return {
            "schema_version": _SCHEMA_VERSION,
            "source_record_id": f"synthetic-ledger:{reference}",
            "source_system": "synthetic.ledger",
            "channel": "SYSTEM_RECORD",
            "subject_reference": reference,
            "observed_at": observed_at_text,
            "claims": {
                "shipment.reference": reference,
                "shipment.status": status,
            },
            "synthetic": True,
        }

    return application


def run_synthetic_evidence_service() -> None:
    """Run the separate local synthetic evidence service through Uvicorn."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8766)
    parser.add_argument("--variant", choices=sorted(_VARIANTS), default="healthy")
    parser.add_argument("--delay-ms", type=int, default=0)
    arguments = parser.parse_args()

    import uvicorn

    uvicorn.run(
        create_synthetic_evidence_service(arguments.variant, arguments.delay_ms),
        host=arguments.host,
        port=arguments.port,
    )


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _require_aware_utc(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("clock must return a timezone-aware datetime")
    return value.astimezone(UTC)


def _format_timestamp(value: datetime) -> str:
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")
