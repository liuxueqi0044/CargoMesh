"""Strict, read-only HTTP adapter for the local synthetic tracking API."""

from __future__ import annotations

import hashlib
import json
import math
from typing import Final, cast
from urllib.parse import quote, urlsplit

import httpx2
from pydantic import JsonValue

from cargomesh.runtime.adapters import AdapterExecutionError
from cargomesh.runtime.models import AdapterInvocation, AdapterResult
from cargomesh.verification.models import EvidenceChannel, ExecutionSource

SYNTHETIC_TRACKING_PATH: Final = "/v1/shipments/"
MAX_RESPONSE_BYTES: Final = 65_536
_SCHEMA_VERSION: Final = "cargomesh.synthetic-api/v1"
_SOURCE_SYSTEM: Final = "synthetic.api"
_ADAPTER_VERSION: Final = "0.1.0"
_REQUIRED_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "schema_version",
        "source_record_id",
        "source_system",
        "subject_reference",
        "data",
        "synthetic",
    }
)
_DATA_FIELDS: Final[frozenset[str]] = frozenset(
    {"shipment.reference", "shipment.status", "shipment.location"}
)


class SyntheticTrackingHttpAdapterConfig:
    """Exact-origin configuration for the synthetic tracking HTTP adapter."""

    def __init__(
        self,
        origin: str,
        *,
        timeout: float = 10.0,
        max_response_bytes: int = MAX_RESPONSE_BYTES,
    ) -> None:
        parsed = urlsplit(origin)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("origin must be an http(s) origin")
        try:
            port = parsed.port
        except ValueError as exc:
            raise ValueError("origin must contain a valid port") from exc
        if parsed.username or parsed.password or parsed.path not in {"", "/"}:
            raise ValueError("origin must not include credentials or a path")
        if parsed.query or parsed.fragment:
            raise ValueError("origin must not include a query or fragment")
        if (
            not isinstance(timeout, int | float)
            or isinstance(timeout, bool)
            or not math.isfinite(timeout)
            or not 0.1 <= timeout <= 30.0
        ):
            raise ValueError("timeout must be between 0.1 and 30 seconds")
        if not isinstance(max_response_bytes, int) or isinstance(max_response_bytes, bool):
            raise ValueError("max_response_bytes must be an integer")
        if not 1 <= max_response_bytes <= MAX_RESPONSE_BYTES:
            raise ValueError("max_response_bytes must be between 1 and 65536")

        host = parsed.hostname.lower()
        host_part = f"[{host}]" if ":" in host else host
        default_port = 443 if parsed.scheme.lower() == "https" else 80
        port_part = "" if port is None or port == default_port else f":{port}"
        self.origin = f"{parsed.scheme.lower()}://{host_part}{port_part}"
        self.timeout = timeout
        self.max_response_bytes = max_response_bytes


class SyntheticTrackingHttpAdapter:
    """Fetch shipment tracking data with a bounded single GET request."""

    def __init__(self, config: SyntheticTrackingHttpAdapterConfig) -> None:
        self.config = config

    async def execute(self, invocation: AdapterInvocation) -> AdapterResult:
        if invocation.operation != "fetch":
            raise AdapterExecutionError(
                "operation_not_supported",
                "Synthetic tracking API adapter supports only fetch",
                retryable=False,
            )
        reference = _booking_reference(invocation.input)
        url = f"{self.config.origin}{SYNTHETIC_TRACKING_PATH}{quote(reference, safe='')}"
        body = await self._fetch(url)
        data = _validate_response(body, reference)
        return AdapterResult(
            output={
                "adapter": invocation.adapter,
                "adapter_version": _ADAPTER_VERSION,
                "operation": "fetch",
                "synthetic": True,
                "data": data,
            },
            execution_source=ExecutionSource(
                source_system=_SOURCE_SYSTEM,
                channel=EvidenceChannel.API,
                adapter_id=invocation.adapter,
                collection_id=_collection_id(invocation),
                synthetic=True,
            ),
        )

    async def _fetch(self, url: str) -> bytes:
        try:
            async with httpx2.AsyncClient(
                timeout=self.config.timeout,
                trust_env=False,
                follow_redirects=False,
            ) as client, client.stream("GET", url) as response:
                _check_response_headers(response, self.config.max_response_bytes)
                if response.status_code == 404:
                    raise AdapterExecutionError(
                        "api_not_found", "Tracking record was not found", retryable=False
                    )
                if response.status_code < 200 or response.status_code >= 300:
                    raise AdapterExecutionError(
                        (
                            "api_server_error"
                            if response.status_code >= 500
                            else "api_response_invalid"
                        ),
                        "Tracking API returned an unsuccessful response",
                        retryable=response.status_code >= 500,
                    )
                media_type = response.headers.get("content-type", "").split(";", 1)[0].strip()
                if media_type.lower() != "application/json":
                    raise AdapterExecutionError(
                        "api_response_invalid", "Tracking API response is not JSON", retryable=False
                    )
                buffer = bytearray()
                async for chunk in response.aiter_bytes():
                    buffer.extend(chunk)
                    if len(buffer) > self.config.max_response_bytes:
                        raise AdapterExecutionError(
                            "api_response_invalid",
                            "Tracking API response exceeds the size limit",
                            retryable=False,
                        )
                return bytes(buffer)
        except AdapterExecutionError:
            raise
        except httpx2.TimeoutException as exc:
            raise AdapterExecutionError(
                "api_timeout", "Tracking API request timed out", retryable=True
            ) from exc
        except httpx2.HTTPError as exc:
            raise AdapterExecutionError(
                "api_transport_error", "Tracking API request failed", retryable=True
            ) from exc


def _booking_reference(payload: dict[str, JsonValue]) -> str:
    try:
        transaction = payload["transaction"]
        subject = transaction["subject"] if isinstance(transaction, dict) else None
        reference = subject["carrier_booking_reference"] if isinstance(subject, dict) else None
    except KeyError:
        reference = None
    if not isinstance(reference, str) or not reference:
        raise AdapterExecutionError(
            "invalid_adapter_input",
            "Adapter input has no carrier booking reference",
            retryable=False,
        )
    return reference


def _check_response_headers(response: httpx2.Response, maximum: int) -> None:
    content_length = response.headers.get("content-length")
    if content_length is None:
        return
    try:
        declared = int(content_length)
    except ValueError as exc:
        raise AdapterExecutionError(
            "api_response_invalid", "Tracking API has an invalid content length", retryable=False
        ) from exc
    if declared < 0 or declared > maximum:
        raise AdapterExecutionError(
            "api_response_invalid", "Tracking API response exceeds the size limit", retryable=False
        )


def _validate_response(body: bytes, reference: str) -> dict[str, JsonValue]:
    try:
        decoded = json.loads(body)
        if not isinstance(decoded, dict) or set(decoded) != _REQUIRED_FIELDS:
            raise ValueError("unexpected response fields")
        if decoded["schema_version"] != _SCHEMA_VERSION:
            raise ValueError("unexpected schema")
        if decoded["source_system"] != _SOURCE_SYSTEM:
            raise ValueError("unexpected source")
        if decoded["subject_reference"] != reference or decoded["synthetic"] is not True:
            raise ValueError("unexpected subject or synthetic marker")
        if not isinstance(decoded["source_record_id"], str) or not decoded["source_record_id"]:
            raise ValueError("invalid record identifier")
        data = decoded["data"]
        if not isinstance(data, dict) or not {"shipment.reference", "shipment.status"} <= set(data):
            raise ValueError("missing tracking fields")
        if not set(data) <= _DATA_FIELDS:
            raise ValueError("unexpected tracking fields")
        if data["shipment.reference"] != reference:
            raise ValueError("mismatched tracking reference")
        if not all(isinstance(value, str) and value for value in data.values()):
            raise ValueError("invalid tracking values")
        return cast(dict[str, JsonValue], data)
    except (ValueError, TypeError, json.JSONDecodeError) as exc:
        raise AdapterExecutionError(
            "api_response_invalid",
            "Tracking API response does not match the certified schema",
            retryable=False,
        ) from exc


def _collection_id(invocation: AdapterInvocation) -> str:
    canonical = (
        f"{invocation.tenant_id}\0{invocation.transaction_id}\0"
        f"{invocation.step_id}\0{invocation.adapter}"
    ).encode()
    return "sha256:" + hashlib.sha256(canonical).hexdigest()
