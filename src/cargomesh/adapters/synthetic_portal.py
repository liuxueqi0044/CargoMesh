"""Deterministic local logistics portal used by adapter integration tests.

The portal is intentionally small and self-contained.  It represents no carrier
system and makes that boundary visible in every tracking response.
"""

from __future__ import annotations

import argparse
import asyncio
import html
from typing import Final, Literal

from fastapi import FastAPI, Query
from fastapi.responses import HTMLResponse

PortalVariant = Literal["healthy", "label_drift", "silent_drop", "server_error"]
_VARIANTS: Final[frozenset[str]] = frozenset(
    {"healthy", "label_drift", "silent_drop", "server_error"}
)
_RECORDS: Final[dict[str, str]] = {
    "CBR-001": "IN_TRANSIT",
    "CBR-002": "DELIVERED",
}


def create_synthetic_portal(
    variant: PortalVariant = "healthy", delay_ms: int = 0
) -> FastAPI:
    """Create a local synthetic portal with deterministic fault injection."""

    if not isinstance(variant, str) or variant not in _VARIANTS:
        raise ValueError(f"unknown synthetic portal variant: {variant}")
    if not isinstance(delay_ms, int) or isinstance(delay_ms, bool) or not 0 <= delay_ms <= 5000:
        raise ValueError("delay_ms must be an integer between 0 and 5000")

    application = FastAPI(title="CargoMesh Synthetic Logistics Portal", version="1.0.0")

    @application.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok", "service": "synthetic-portal"}

    @application.get("/track", response_class=HTMLResponse)
    async def track(
        booking_reference: str | None = Query(default=None, alias="bookingReference"),
    ) -> HTMLResponse:
        if delay_ms:
            await asyncio.sleep(delay_ms / 1000)
        if variant == "server_error":
            return HTMLResponse(
                content=(
                    "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
                    "<title>Track shipment</title></head><body><main>"
                    "<h1>Track shipment</h1>"
                    '<p data-testid="synthetic-notice">Synthetic demo only: '
                    "No carrier transaction was executed.</p>"
                    "<p role=\"alert\">Synthetic portal unavailable.</p>"
                    "</main></body></html>"
                ),
                status_code=503,
            )

        reference = booking_reference or ""
        escaped_reference = html.escape(reference, quote=True)
        label = "Shipment reference" if variant == "label_drift" else "Booking reference"
        result_markup = ""
        if variant in {"healthy", "label_drift"}:
            status = _RECORDS.get(reference)
            if status is None:
                result_markup = (
                    '<p data-testid="tracking-not-found" role="status">'
                    "No tracking result found.</p>"
                )
            else:
                escaped_status = html.escape(status, quote=True)
                result_markup = (
                    '<section aria-labelledby="tracking-result-heading">'
                    '<h2 id="tracking-result-heading">Tracking result</h2>'
                    f'<p data-testid="tracking-reference">{escaped_reference}</p>'
                    f'<p data-testid="tracking-status">{escaped_status}</p>'
                    "</section>"
                )
        elif variant == "silent_drop":
            result_markup = '<p role="status">No tracking result available.</p>'

        markup = f"""<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Track shipment</title></head>
<body>
  <main>
    <h1>Track shipment</h1>
    <p data-testid="synthetic-notice">Synthetic demo only: No carrier transaction was executed.</p>
    <form method="get" action="/track">
      <label for="booking-reference">{html.escape(label, quote=True)}</label>
      <input id="booking-reference" name="bookingReference" value="{escaped_reference}">
      <button type="submit">Search</button>
    </form>
    {result_markup}
  </main>
</body>
</html>"""
        return HTMLResponse(content=markup)

    return application


def run_synthetic_portal() -> None:
    """Run the synthetic portal as a small local Uvicorn process."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--variant", choices=sorted(_VARIANTS), default="healthy")
    parser.add_argument("--delay-ms", type=int, default=0)
    arguments = parser.parse_args()

    import uvicorn

    uvicorn.run(
        create_synthetic_portal(arguments.variant, arguments.delay_ms),
        host=arguments.host,
        port=arguments.port,
    )
