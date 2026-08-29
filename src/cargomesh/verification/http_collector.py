"""Bounded, read-only HTTP evidence collection for the synthetic ledger."""

from __future__ import annotations

import hashlib
import json
import math
from datetime import datetime
from typing import Final
from urllib.parse import quote, urlsplit

import httpx2

from cargomesh.verification.collectors import EvidenceCollectionError
from cargomesh.verification.models import (
    EvidenceChannel,
    EvidenceCollectionInvocation,
    EvidenceObservation,
)

LEDGER_TRACK_PATH: Final[str] = "/v1/evidence/shipments/"
MAX_ALLOWED_RESPONSE_BYTES: Final[int] = 65_536


class SyntheticLedgerHttpCollectorConfig:
    """Configuration for one exact-origin synthetic ledger collector."""

    def __init__(
        self,
        origin: str,
        *,
        expected_source_system: str = "synthetic.ledger",
        timeout: float = 10.0,
        max_response_bytes: int = MAX_ALLOWED_RESPONSE_BYTES,
    ) -> None:
        parsed = urlsplit(origin)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("origin must be an http(s) origin")
        try:
            _ = parsed.port
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
        if not 1 <= max_response_bytes <= MAX_ALLOWED_RESPONSE_BYTES:
            raise ValueError("max_response_bytes must be between 1 and 65536")
        if expected_source_system != "synthetic.ledger":
            raise ValueError("expected_source_system must be synthetic.ledger")

        self.origin = f"{parsed.scheme}://{parsed.netloc}"
        self.expected_source_system = expected_source_system
        self.timeout = timeout
        self.max_response_bytes = max_response_bytes


class SyntheticLedgerHttpCollector:
    """Collect one observation from a fixed synthetic-ledger route."""

    def __init__(self, config: SyntheticLedgerHttpCollectorConfig) -> None:
        self.config = config

    async def collect(self, invocation: EvidenceCollectionInvocation) -> EvidenceObservation:
        if invocation.operation != "fetch":
            raise EvidenceCollectionError(
                "operation_not_supported",
                "Synthetic ledger collector supports only fetch",
                retryable=False,
            )
        reference = invocation.input.get("carrier_booking_reference")
        if not isinstance(reference, str) or not reference:
            raise EvidenceCollectionError(
                "invalid_invocation",
                "Evidence invocation has no shipment reference",
                retryable=False,
            )
        url = f"{self.config.origin}{LEDGER_TRACK_PATH}{quote(reference, safe='')}"
        try:
            async with httpx2.AsyncClient(
                timeout=self.config.timeout,
                trust_env=False,
                follow_redirects=False,
            ) as client, client.stream("GET", url) as response:
                content_length = response.headers.get("content-length")
                if content_length is not None:
                    try:
                        declared_length = int(content_length)
                    except ValueError as exc:
                        raise EvidenceCollectionError(
                            "invalid_content_length",
                            "Evidence response has invalid content length",
                            retryable=False,
                        ) from exc
                    if declared_length < 0:
                        raise EvidenceCollectionError(
                            "invalid_content_length",
                            "Evidence response has invalid content length",
                            retryable=False,
                        )
                    if declared_length > self.config.max_response_bytes:
                        raise EvidenceCollectionError(
                            "response_too_large",
                            "Evidence response exceeds size limit",
                            retryable=False,
                        )
                if 300 <= response.status_code < 400:
                    raise EvidenceCollectionError(
                        "redirect_rejected",
                        "Evidence redirect was rejected",
                        retryable=False,
                    )
                if response.status_code < 200 or response.status_code >= 300:
                    raise EvidenceCollectionError(
                        "http_error",
                        "Evidence endpoint returned an unsuccessful status",
                        retryable=response.status_code >= 500,
                    )
                media_type = (
                    response.headers.get("content-type", "")
                    .split(";", 1)[0]
                    .strip()
                    .lower()
                )
                if media_type != "application/json":
                    raise EvidenceCollectionError(
                        "invalid_content_type",
                        "Evidence response is not JSON",
                        retryable=False,
                    )
                body_buffer = bytearray()
                async for chunk in response.aiter_bytes():
                    body_buffer.extend(chunk)
                    if len(body_buffer) > self.config.max_response_bytes:
                        raise EvidenceCollectionError(
                            "response_too_large",
                            "Evidence response exceeds size limit",
                            retryable=False,
                        )
                body = bytes(body_buffer)
        except EvidenceCollectionError:
            raise
        except httpx2.TooManyRedirects as exc:
            raise EvidenceCollectionError(
                "redirect_rejected", "Evidence redirect was rejected", retryable=False
            ) from exc
        except httpx2.TimeoutException as exc:
            raise EvidenceCollectionError(
                "timeout", "Evidence request timed out", retryable=True
            ) from exc
        except httpx2.HTTPError as exc:
            raise EvidenceCollectionError(
                "transport_error", "Evidence request failed", retryable=True
            ) from exc

        observation = _validate_observation(body, invocation, reference)
        _check_observation_matches(observation, reference)
        return observation


def _validate_observation(
    body: bytes, invocation: EvidenceCollectionInvocation, reference: str
) -> EvidenceObservation:
    try:
        decoded = json.loads(body)
        expected_keys = {
            "schema_version",
            "source_record_id",
            "source_system",
            "channel",
            "subject_reference",
            "observed_at",
            "claims",
            "synthetic",
        }
        if not isinstance(decoded, dict) or set(decoded) != expected_keys:
            raise ValueError("unexpected response fields")
        if decoded["source_system"] != "synthetic.ledger":
            raise ValueError("unexpected source system")
        if decoded["schema_version"] != "cargomesh.synthetic-evidence/v1":
            raise ValueError("unexpected response schema")
        if decoded["channel"] != "SYSTEM_RECORD":
            raise ValueError("unexpected channel")
        if decoded["subject_reference"] != reference:
            raise ValueError("unexpected subject")
        if decoded["synthetic"] is not True or not isinstance(decoded["claims"], dict):
            raise ValueError("invalid evidence markers")
        observed_at = datetime.fromisoformat(
            str(decoded["observed_at"]).replace("Z", "+00:00")
        )
        values = {
            "schema_version": "cargomesh.evidence-observation/v1",
            "evidence_id": _evidence_id(invocation, str(decoded["source_record_id"])),
            "tenant_id": invocation.tenant_id,
            "transaction_id": invocation.transaction_id,
            "source_record_id": decoded["source_record_id"],
            "source_system": decoded["source_system"],
            "channel": EvidenceChannel.SYSTEM_RECORD,
            "collector_id": invocation.collector_id,
            "collection_id": _collection_id(invocation),
            "observed_at": observed_at,
            "expires_at": None,
            "claims": decoded["claims"],
            "synthetic": True,
        }
        return EvidenceObservation.issue(**values)
    except (ValueError, TypeError, json.JSONDecodeError) as exc:
        raise EvidenceCollectionError(
            "invalid_response_schema",
            "Evidence response does not match the observation schema",
            retryable=False,
        ) from exc


def _check_observation_matches(observation: EvidenceObservation, reference: str) -> None:
    if observation.source_system != "synthetic.ledger":
        raise EvidenceCollectionError(
            "source_mismatch", "Evidence source system does not match", retryable=False
        )
    if observation.channel is not EvidenceChannel.SYSTEM_RECORD:
        raise EvidenceCollectionError(
            "channel_mismatch", "Evidence channel does not match", retryable=False
        )
    claim_reference = observation.claims.get("shipment.reference")
    if claim_reference is None or str(claim_reference) != reference:
        raise EvidenceCollectionError(
            "subject_mismatch", "Evidence subject does not match", retryable=False
        )


def _collection_id(invocation: EvidenceCollectionInvocation) -> str:
    return _stable_id(
        invocation.tenant_id,
        invocation.transaction_id,
        invocation.step_id,
        invocation.collector_id,
    )


def _evidence_id(
    invocation: EvidenceCollectionInvocation, source_record_id: str
) -> str:
    return _stable_id(
        invocation.tenant_id,
        invocation.transaction_id,
        invocation.step_id,
        source_record_id,
    )


def _stable_id(*parts: str) -> str:
    canonical = "\0".join(parts).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()
