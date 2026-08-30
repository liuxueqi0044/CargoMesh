from __future__ import annotations

import asyncio

import httpx2
import pytest

from cargomesh.booking.evidence import (
    BookingEvidenceCollector,
    BookingEvidenceCollectorConfig,
)
from cargomesh.verification.collectors import EvidenceCollectionError
from cargomesh.verification.models import EvidenceChannel, EvidenceCollectionInvocation


def _invocation(reference: str = "EXT-1") -> EvidenceCollectionInvocation:
    return EvidenceCollectionInvocation(
        tenant_id="tenant-1",
        transaction_id="txn-1",
        step_id="verify-booking",
        collector_id="booking-ledger",
        operation="fetch",
        input={"external_reference": reference},
    )


def test_reads_separate_ledger_and_issues_system_record_claims() -> None:
    requests: list[httpx2.Request] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        requests.append(request)
        return httpx2.Response(
            200,
            headers={"content-type": "application/json"},
            json={
                "externalReference": "EXT-1",
                "bookingStatus": "RECEIVED",
                "sourceRecordId": "ledger-1",
                "observedAt": "2026-08-31T00:00:00Z",
                "recordDigest": "sha256:" + "a" * 64,
                "synthetic": True,
            },
        )

    collector = BookingEvidenceCollector(
        BookingEvidenceCollectorConfig(
            "http://ledger.test", transport=httpx2.MockTransport(handler)
        )
    )
    observation = asyncio.run(collector.collect(_invocation()))
    assert requests[0].url.path == "/synthetic-ledger/bookings/by-external-reference/EXT-1"
    assert observation.channel is EvidenceChannel.SYSTEM_RECORD
    assert observation.synthetic is True
    assert observation.claims == {
        "booking.external_reference": "EXT-1",
        "booking.status": "RECEIVED",
    }


def test_ledger_reference_mismatch_is_bounded() -> None:
    def handler(_: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(
            200,
            headers={"content-type": "application/json"},
            json={"externalReference": "OTHER", "bookingStatus": "RECEIVED"},
        )

    collector = BookingEvidenceCollector(
        BookingEvidenceCollectorConfig(
            "http://ledger.test", transport=httpx2.MockTransport(handler)
        )
    )
    with pytest.raises(EvidenceCollectionError) as raised:
        asyncio.run(collector.collect(_invocation()))
    assert raised.value.code == "invalid_response_schema"
    assert "OTHER" not in str(raised.value)
