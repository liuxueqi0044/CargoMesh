"""Credential-aware HTTP execution adapter for the synthetic DCSA Booking API."""

from __future__ import annotations

import json
import math
from typing import Any
from urllib.parse import quote, urlsplit

import httpx2

from cargomesh.runtime.adapters import (
    AdapterExecutionError,
    CredentialAwareAdapterExecutor,
    CredentialLeaseSet,
)
from cargomesh.runtime.models import AdapterInvocation, AdapterResult
from cargomesh.verification.models import EvidenceChannel, ExecutionSource

from .contracts import (
    BookingCancellationRequest,
    BookingCancellationResponse,
    BookingCreateResponse,
    BookingGetResponse,
    map_ir_to_booking,
)

BOOKING_PATH = "/v2/bookings"
LEDGER_SOURCE = "synthetic.carrier"


class BookingHttpAdapterConfig:
    def __init__(
        self,
        origin: str,
        *,
        timeout: float = 10.0,
        max_response_bytes: int = 65_536,
        transport: Any = None,
        credential_name: str = "api_key",
    ) -> None:
        parsed = urlsplit(origin)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("booking origin must be an http(s) origin")
        try:
            port = parsed.port
        except ValueError as exc:
            raise ValueError("booking origin must contain a valid port") from exc
        if parsed.username or parsed.password or parsed.path not in {"", "/"}:
            raise ValueError("booking origin must not include credentials or a path")
        if parsed.query or parsed.fragment:
            raise ValueError("booking origin must not include a query or fragment")
        if (
            not isinstance(timeout, int | float)
            or isinstance(timeout, bool)
            or not math.isfinite(timeout)
            or not 0.1 <= timeout <= 30
        ):
            raise ValueError("booking timeout is out of bounds")
        if not isinstance(max_response_bytes, int) or isinstance(max_response_bytes, bool):
            raise ValueError("booking response limit is invalid")
        if not 1 <= max_response_bytes <= 65_536:
            raise ValueError("booking response limit is out of bounds")
        host = parsed.hostname.lower()
        loopback = host in {"localhost", "127.0.0.1", "::1"}
        if not loopback and transport is None:
            raise ValueError("booking adapter requires a loopback origin")
        host_part = f"[{host}]" if ":" in host else host
        default_port = 443 if parsed.scheme.lower() == "https" else 80
        port_part = "" if port is None or port == default_port else f":{port}"
        self.origin = f"{parsed.scheme.lower()}://{host_part}{port_part}"
        self.timeout = timeout
        self.max_response_bytes = max_response_bytes
        self.transport = transport
        self.credential_name = credential_name


class BookingHttpAdapter(CredentialAwareAdapterExecutor):
    def __init__(self, config: BookingHttpAdapterConfig) -> None:
        self.config = config

    async def execute_with_credentials(
        self, invocation: AdapterInvocation, credentials: CredentialLeaseSet
    ) -> AdapterResult:
        if invocation.operation not in {"submit", "booking.submit", "cancel"}:
            raise AdapterExecutionError(
                "booking_operation_unsupported",
                "Booking adapter operation is unsupported",
                retryable=False,
            )
        if invocation.operation == "cancel":
            return await self._cancel(invocation, credentials)
        try:
            request = map_ir_to_booking(invocation.input)
        except Exception as exc:
            raise AdapterExecutionError(
                "booking_schema_rejected",
                "Booking request failed schema validation before submission",
                retryable=False,
            ) from exc
        reference = _external_reference(invocation.input)
        if reference is None:
            raise AdapterExecutionError(
                "booking_schema_rejected",
                "Booking request has no external reference",
                retryable=False,
            )
        headers = self._credential_header(credentials)
        headers["Idempotency-Key"] = reference
        body = await self._request(
            "POST", BOOKING_PATH, request.to_dcsa(), headers, expected_status=202
        )
        try:
            response = BookingCreateResponse.model_validate(_strict_json(body))
        except Exception as exc:
            raise AdapterExecutionError(
                "booking_effect_unknown",
                "Booking response could not be validated after submission",
                retryable=False,
            ) from exc
        reference = response.carrier_booking_request_reference
        try:
            status_body = await self._request(
                "GET",
                f"{BOOKING_PATH}/{quote(reference, safe='')}",
                None,
                headers,
                expected_status=200,
            )
            status = BookingGetResponse.model_validate(_strict_json(status_body))
        except Exception as exc:
            raise AdapterExecutionError(
                "booking_effect_unknown",
                "Booking status could not be validated after submission",
                retryable=False,
            ) from exc
        if status.carrier_booking_request_reference != reference:
            raise AdapterExecutionError(
                "booking_effect_unknown", "Booking status reference did not match", retryable=False
            )
        return AdapterResult(
            output={
                "synthetic": True,
                "carrier_booking_request_reference": reference,
                "booking_status": status.booking_status,
            },
            effect_reference=reference,
            execution_source=ExecutionSource(
                source_system=LEDGER_SOURCE,
                channel=EvidenceChannel.API,
                adapter_id=invocation.adapter,
                collection_id=f"booking:{invocation.transaction_id}:{invocation.step_id}",
                synthetic=True,
            ),
        )

    async def _cancel(
        self, invocation: AdapterInvocation, credentials: CredentialLeaseSet
    ) -> AdapterResult:
        reference = invocation.input.get("effect_reference")
        if not isinstance(reference, str) or not reference:
            raise AdapterExecutionError(
                "booking_effect_reference_missing",
                "Booking cancellation requires an effect reference",
                retryable=False,
            )
        body = await self._request(
            "PATCH",
            f"{BOOKING_PATH}/{quote(reference, safe='')}",
            BookingCancellationRequest(bookingStatus="CANCELLED").model_dump(by_alias=True),
            self._credential_header(credentials),
            expect_json=False,
            expected_status=202,
        )
        if body:
            try:
                cancellation = BookingCancellationResponse.model_validate(_strict_json(body))
            except Exception as exc:
                raise AdapterExecutionError(
                    "booking_cancellation_failed",
                    "Booking cancellation response was invalid",
                    retryable=False,
                ) from exc
            if cancellation.carrier_booking_request_reference != reference:
                raise AdapterExecutionError(
                    "booking_cancellation_failed",
                    "Booking cancellation reference did not match",
                    retryable=False,
                )
        return AdapterResult(
            output={"synthetic": True, "booking_status": "CANCELLED"},
            effect_reference=reference,
            execution_source=ExecutionSource(
                source_system=LEDGER_SOURCE,
                channel=EvidenceChannel.API,
                adapter_id=invocation.adapter,
                collection_id=f"booking:{invocation.transaction_id}:{invocation.step_id}",
                synthetic=True,
            ),
        )

    def _credential_header(self, credentials: CredentialLeaseSet) -> dict[str, str]:
        try:
            value = credentials.read(self.config.credential_name).decode("utf-8")
        except Exception as exc:
            raise AdapterExecutionError(
                "booking_credential_unavailable",
                "Booking credential is unavailable",
                retryable=False,
            ) from exc
        if not value:
            raise AdapterExecutionError(
                "booking_credential_unavailable",
                "Booking credential is unavailable",
                retryable=False,
            )
        return {"Authorization": f"Bearer {value}"}

    async def _request(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None,
        headers: dict[str, str],
        *,
        expect_json: bool = True,
        expected_status: int,
    ) -> bytes:
        try:
            async with (
                httpx2.AsyncClient(
                    timeout=self.config.timeout,
                    trust_env=False,
                    follow_redirects=False,
                    transport=self.config.transport,
                ) as client,
                client.stream(
                    method, f"{self.config.origin}{path}", json=payload, headers=headers
                ) as response,
            ):
                if 300 <= response.status_code < 400:
                    raise AdapterExecutionError(
                        "booking_effect_unknown", "Booking redirect was rejected", retryable=False
                    )
                if method == "POST" and response.status_code == 400:
                    raise AdapterExecutionError(
                        "booking_schema_rejected",
                        "Booking request was rejected by schema",
                        retryable=False,
                    )
                if response.status_code != expected_status:
                    raise AdapterExecutionError(
                        "booking_effect_unknown",
                        "Booking endpoint returned an unsuccessful response",
                        retryable=False,
                    )
                if (
                    expect_json
                    and response.headers.get("content-type", "").split(";", 1)[0].lower()
                    != "application/json"
                ):
                    raise AdapterExecutionError(
                        "booking_effect_unknown",
                        "Booking endpoint response was not JSON",
                        retryable=False,
                    )
                chunks = bytearray()
                async for chunk in response.aiter_bytes():
                    chunks.extend(chunk)
                    if len(chunks) > self.config.max_response_bytes:
                        raise AdapterExecutionError(
                            "booking_effect_unknown",
                            "Booking response exceeded the size limit",
                            retryable=False,
                        )
                return bytes(chunks)
        except AdapterExecutionError:
            raise
        except (httpx2.TimeoutException, httpx2.HTTPError) as exc:
            raise AdapterExecutionError(
                "booking_effect_unknown", "Booking transport failed", retryable=False
            ) from exc


def _strict_json(body: bytes) -> dict[str, Any]:
    decoded = json.loads(body)
    if not isinstance(decoded, dict):
        raise ValueError("response is not an object")
    return decoded


def _external_reference(input_data: dict[str, Any]) -> str | None:
    """Find only the IR idempotency reference, without inspecting payload data."""

    direct = input_data.get("external_reference")
    if isinstance(direct, str) and direct.strip():
        return direct
    transaction = input_data.get("transaction")
    if isinstance(transaction, dict):
        nested = transaction.get("external_reference")
        if isinstance(nested, str) and nested.strip():
            return nested
    return None


__all__ = ["BookingHttpAdapter", "BookingHttpAdapterConfig"]
