"""Independent, read-only evidence boundary for synthetic bookings."""

from __future__ import annotations

import json
import math
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote, urlsplit

import httpx2

from cargomesh.verification.collectors import EvidenceCollectionError
from cargomesh.verification.models import (
    EvidenceChannel,
    EvidenceCollectionInvocation,
    EvidenceObservation,
)

LEDGER_PATH = "/synthetic-ledger/bookings/by-external-reference/"
# Keep the ledger identity consistent with the existing verification source;
# it remains distinct from the booking execution source (synthetic.carrier).
LEDGER_SOURCE = "synthetic.ledger"


class BookingEvidenceCollectorConfig:
    def __init__(
        self,
        origin: str,
        *,
        timeout: float = 10.0,
        max_response_bytes: int = 65_536,
        transport: Any = None,
    ) -> None:
        parsed = urlsplit(origin)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("booking ledger origin must be an http(s) origin")
        try:
            port = parsed.port
        except ValueError as exc:
            raise ValueError("booking ledger origin must contain a valid port") from exc
        if parsed.username or parsed.password or parsed.path not in {"", "/"}:
            raise ValueError("booking ledger origin must not include credentials or a path")
        if parsed.query or parsed.fragment:
            raise ValueError("booking ledger origin must not include a query or fragment")
        if (
            not isinstance(timeout, int | float)
            or isinstance(timeout, bool)
            or not math.isfinite(timeout)
            or not 0.1 <= timeout <= 30
        ):
            raise ValueError("booking ledger timeout is out of bounds")
        if not isinstance(max_response_bytes, int) or isinstance(max_response_bytes, bool):
            raise ValueError("booking ledger response limit is invalid")
        if not 1 <= max_response_bytes <= 65_536:
            raise ValueError("booking ledger response limit is out of bounds")
        host = parsed.hostname.lower()
        if host not in {"localhost", "127.0.0.1", "::1"} and transport is None:
            raise ValueError("booking ledger collector requires a loopback origin")
        host_part = f"[{host}]" if ":" in host else host
        default_port = 443 if parsed.scheme.lower() == "https" else 80
        port_part = "" if port is None or port == default_port else f":{port}"
        self.origin = f"{parsed.scheme.lower()}://{host_part}{port_part}"
        self.timeout = timeout
        self.max_response_bytes = max_response_bytes
        self.transport = transport


class BookingEvidenceCollector:
    """Collect exactly two non-secret claims from the separate ledger."""

    def __init__(self, config: BookingEvidenceCollectorConfig) -> None:
        self.config = config

    async def collect(self, invocation: EvidenceCollectionInvocation) -> EvidenceObservation:
        if invocation.operation not in {"fetch", "booking.fetch"}:
            raise EvidenceCollectionError(
                "operation_not_supported",
                "Booking ledger operation is unsupported",
                retryable=False,
            )
        reference = _external_reference(invocation.input)
        url = f"{self.config.origin}{LEDGER_PATH}{quote(reference, safe='')}"
        try:
            async with (
                httpx2.AsyncClient(
                    timeout=self.config.timeout,
                    trust_env=False,
                    follow_redirects=False,
                    transport=self.config.transport,
                ) as client,
                client.stream("GET", url) as response,
            ):
                if 300 <= response.status_code < 400:
                    raise EvidenceCollectionError(
                        "redirect_rejected", "Booking ledger redirect was rejected", retryable=False
                    )
                if response.status_code < 200 or response.status_code >= 300:
                    raise EvidenceCollectionError(
                        "evidence_unavailable",
                        "Booking ledger returned an unsuccessful response",
                        retryable=False,
                    )
                if (
                    response.headers.get("content-type", "").split(";", 1)[0].lower()
                    != "application/json"
                ):
                    raise EvidenceCollectionError(
                        "invalid_response_schema",
                        "Booking ledger response was not JSON",
                        retryable=False,
                    )
                body_buffer = bytearray()
                async for chunk in response.aiter_bytes():
                    body_buffer.extend(chunk)
                    if len(body_buffer) > self.config.max_response_bytes:
                        raise EvidenceCollectionError(
                            "response_too_large",
                            "Booking ledger response exceeds size limit",
                            retryable=False,
                        )
                body = bytes(body_buffer)
        except EvidenceCollectionError:
            raise
        except (httpx2.TimeoutException, httpx2.HTTPError) as exc:
            raise EvidenceCollectionError(
                "evidence_unavailable", "Booking ledger request failed", retryable=True
            ) from exc
        return _observation(body, invocation, reference)


def _external_reference(input_data: dict[str, Any]) -> str:
    for key in ("external_reference", "carrier_booking_request_reference"):
        value = input_data.get(key)
        if isinstance(value, str) and value.strip():
            return value
    raise EvidenceCollectionError(
        "invalid_invocation", "Booking evidence reference is unavailable", retryable=False
    )


def _observation(
    body: bytes, invocation: EvidenceCollectionInvocation, reference: str
) -> EvidenceObservation:
    try:
        decoded = json.loads(body)
        if not isinstance(decoded, dict):
            raise ValueError("response is not an object")
        allowed = {
            "externalReference",
            "external_reference",
            "carrierBookingRequestReference",
            "bookingStatus",
            "booking_status",
            "sourceRecordId",
            "source_record_id",
            "observedAt",
            "observed_at",
            "recordDigest",
            "synthetic",
        }
        if set(decoded) - allowed:
            raise ValueError("response contains unsupported fields")
        record_digest = decoded.get("recordDigest")
        if (
            decoded.get("synthetic") is not True
            or not isinstance(record_digest, str)
            or not record_digest.startswith("sha256:")
            or len(record_digest) != len("sha256:") + 64
            or any(character not in "0123456789abcdef" for character in record_digest[7:])
        ):
            raise ValueError("response provenance is invalid")
        response_reference = decoded.get("externalReference", decoded.get("external_reference"))
        if response_reference is None:
            response_reference = decoded.get("carrierBookingRequestReference")
        status = decoded.get("bookingStatus", decoded.get("booking_status"))
        if response_reference != reference or not isinstance(status, str) or not status:
            raise ValueError("response subject or status is invalid")
        source_record_id = decoded.get("sourceRecordId", decoded.get("source_record_id"))
        if not isinstance(source_record_id, str) or not source_record_id:
            source_record_id = f"booking:{reference}"
        raw_time = decoded.get("observedAt", decoded.get("observed_at"))
        observed_at = (
            datetime.fromisoformat(raw_time.replace("Z", "+00:00"))
            if isinstance(raw_time, str)
            else datetime.now(UTC)
        )
        if observed_at.tzinfo is None or observed_at.utcoffset() is None:
            raise ValueError("observation timestamp is not timezone aware")
        return EvidenceObservation.issue(
            evidence_id=f"booking:{invocation.tenant_id}:{invocation.transaction_id}:{source_record_id}",
            tenant_id=invocation.tenant_id,
            transaction_id=invocation.transaction_id,
            source_record_id=source_record_id,
            source_system=LEDGER_SOURCE,
            channel=EvidenceChannel.SYSTEM_RECORD,
            collector_id=invocation.collector_id,
            collection_id=f"booking-ledger:{invocation.tenant_id}:{invocation.transaction_id}:{invocation.step_id}",
            observed_at=observed_at,
            claims={"booking.external_reference": reference, "booking.status": status},
            synthetic=True,
        )
    except (ValueError, TypeError, json.JSONDecodeError) as exc:
        raise EvidenceCollectionError(
            "invalid_response_schema",
            "Booking ledger response does not match the evidence schema",
            retryable=False,
        ) from exc


SyntheticBookingLedgerCollector = BookingEvidenceCollector
SyntheticBookingLedgerCollectorConfig = BookingEvidenceCollectorConfig

__all__ = [
    "BookingEvidenceCollector",
    "BookingEvidenceCollectorConfig",
    "SyntheticBookingLedgerCollector",
    "SyntheticBookingLedgerCollectorConfig",
]
