"""Local deterministic tracking API used for adapter integration tests.

This service is deliberately synthetic: it neither represents nor contacts a
carrier system. Its fault variants make HTTP adapter failure paths testable
without an external dependency.
"""

from __future__ import annotations

import argparse
import asyncio
from typing import Final, Literal

from fastapi import FastAPI
from fastapi.responses import JSONResponse, Response

SyntheticApiVariant = Literal["healthy", "server_error", "malformed", "not_found"]
_VARIANTS: Final[frozenset[str]] = frozenset(
    {"healthy", "server_error", "malformed", "not_found"}
)
_RECORDS: Final[dict[str, str]] = {
    "CBR-001": "IN_TRANSIT",
    "CBR-002": "DELIVERED",
}
_SCHEMA_VERSION: Final = "cargomesh.synthetic-api/v1"


def create_synthetic_tracking_api(
    variant: SyntheticApiVariant = "healthy", delay_ms: int = 0
) -> FastAPI:
    """Create a synthetic tracking API with deterministic fault injection."""

    if not isinstance(variant, str) or variant not in _VARIANTS:
        raise ValueError(f"unknown synthetic API variant: {variant}")
    if not isinstance(delay_ms, int) or isinstance(delay_ms, bool) or not 0 <= delay_ms <= 5000:
        raise ValueError("delay_ms must be an integer between 0 and 5000")

    application = FastAPI(title="CargoMesh Synthetic Tracking API", version="1.0.0")

    @application.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok", "service": "synthetic-api"}

    @application.get("/v1/shipments/{reference}")
    async def get_shipment(reference: str) -> Response:
        if delay_ms:
            await asyncio.sleep(delay_ms / 1000)
        if variant == "server_error":
            return JSONResponse({"detail": "Synthetic API unavailable."}, status_code=503)
        if variant == "not_found" or reference not in _RECORDS:
            return Response(status_code=404)

        status = _RECORDS[reference]
        if variant == "malformed":
            return JSONResponse(
                {
                    "schema_version": "cargomesh.synthetic-api/v0",
                    "source_system": "synthetic.api",
                    "subject_reference": reference,
                    "data": {"shipment.reference": reference},
                    "synthetic": True,
                }
            )
        return JSONResponse(
            {
                "schema_version": _SCHEMA_VERSION,
                "source_record_id": f"synthetic-api:{reference}",
                "source_system": "synthetic.api",
                "subject_reference": reference,
                "data": {
                    "shipment.reference": reference,
                    "shipment.status": status,
                },
                "synthetic": True,
            }
        )

    return application


def run_synthetic_tracking_api() -> None:
    """Run the synthetic tracking API with Uvicorn."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8767)
    parser.add_argument("--variant", choices=sorted(_VARIANTS), default="healthy")
    parser.add_argument("--delay-ms", type=int, default=0)
    arguments = parser.parse_args()

    import uvicorn

    uvicorn.run(
        create_synthetic_tracking_api(arguments.variant, arguments.delay_ms),
        host=arguments.host,
        port=arguments.port,
    )
