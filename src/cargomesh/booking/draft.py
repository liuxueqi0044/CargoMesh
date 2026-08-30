"""Pure preflight adapter for the reviewed DCSA Booking request subset."""

from __future__ import annotations

import hashlib
import json

from cargomesh.runtime.adapters import AdapterExecutionError
from cargomesh.runtime.models import AdapterInvocation, AdapterResult

from .contracts import map_ir_to_booking


class BookingDraftAdapter:
    """Validate and fingerprint a booking without creating an external effect."""

    async def execute(self, invocation: AdapterInvocation) -> AdapterResult:
        if invocation.operation != "prepare":
            raise AdapterExecutionError(
                "booking_operation_unsupported",
                "Booking draft operation is unsupported",
                retryable=False,
            )
        try:
            request = map_ir_to_booking(invocation.input)
        except Exception as exc:
            raise AdapterExecutionError(
                "booking_schema_rejected",
                "Booking request failed schema validation during preflight",
                retryable=False,
            ) from exc
        canonical = json.dumps(
            request.to_dcsa(),
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        return AdapterResult(
            output={
                "synthetic": True,
                "draft_digest": f"sha256:{hashlib.sha256(canonical).hexdigest()}",
            }
        )


__all__ = ["BookingDraftAdapter"]
