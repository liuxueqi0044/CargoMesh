from __future__ import annotations

import asyncio

import httpx2
import pytest
from fastapi import FastAPI
from fastapi.responses import PlainTextResponse, RedirectResponse, Response

from cargomesh.verification.http_collector import (
    EvidenceCollectionError,
    SyntheticLedgerHttpCollector,
    SyntheticLedgerHttpCollectorConfig,
)
from cargomesh.verification.models import EvidenceCollectionInvocation
from cargomesh.verification.synthetic_evidence import create_synthetic_evidence_service


def invocation(reference: str = "CBR-001") -> EvidenceCollectionInvocation:
    return EvidenceCollectionInvocation(
        tenant_id="tenant-a",
        transaction_id="tx-a",
        step_id="evidence-step",
        collector_id="synthetic-ledger-http",
        operation="fetch",
        input={"carrier_booking_reference": reference},
    )


def patch_client(monkeypatch: pytest.MonkeyPatch, app: object) -> None:
    original = httpx2.AsyncClient

    def factory(**kwargs: object) -> httpx2.AsyncClient:
        return original(transport=httpx2.ASGITransport(app=app), **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr("cargomesh.verification.http_collector.httpx2.AsyncClient", factory)


def test_collects_strict_observation_from_synthetic_ledger(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    patch_client(monkeypatch, create_synthetic_evidence_service())
    collector = SyntheticLedgerHttpCollector(SyntheticLedgerHttpCollectorConfig("http://ledger.test"))

    observation = asyncio.run(collector.collect(invocation()))

    assert observation.tenant_id == "tenant-a"
    assert observation.transaction_id == "tx-a"
    assert observation.source_system == "synthetic.ledger"
    assert observation.claims["shipment.status"] == "IN_TRANSIT"
    assert observation.synthetic is True


def test_http_failures_are_safe_and_classified(monkeypatch: pytest.MonkeyPatch) -> None:
    patch_client(monkeypatch, create_synthetic_evidence_service(variant="server_error"))
    collector = SyntheticLedgerHttpCollector(SyntheticLedgerHttpCollectorConfig("http://ledger.test"))

    with pytest.raises(EvidenceCollectionError) as error:
        asyncio.run(collector.collect(invocation()))

    assert error.value.code == "http_error"
    assert error.value.retryable is True
    assert "http://" not in error.value.message


def test_config_is_bounded_to_exact_http_origin() -> None:
    with pytest.raises(ValueError):
        SyntheticLedgerHttpCollectorConfig("ftp://ledger.test")
    with pytest.raises(ValueError):
        SyntheticLedgerHttpCollectorConfig("http://ledger.test/private")
    with pytest.raises(ValueError):
        SyntheticLedgerHttpCollectorConfig("http://ledger.test", timeout=0.09)
    with pytest.raises(ValueError):
        SyntheticLedgerHttpCollectorConfig("http://ledger.test", timeout=30.01)
    with pytest.raises(ValueError):
        SyntheticLedgerHttpCollectorConfig("http://ledger.test", max_response_bytes=65537)
    with pytest.raises(ValueError):
        SyntheticLedgerHttpCollectorConfig("http://ledger.test", expected_source_system="carrier")
    with pytest.raises(ValueError):
        SyntheticLedgerHttpCollectorConfig("http://user:pass@ledger.test")
    with pytest.raises(ValueError):
        SyntheticLedgerHttpCollectorConfig("http://ledger.test?secret=no")
    with pytest.raises(ValueError):
        SyntheticLedgerHttpCollectorConfig("http://ledger.test", timeout=True)


def test_operation_and_subject_mismatch_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    collector = SyntheticLedgerHttpCollector(
        SyntheticLedgerHttpCollectorConfig("http://ledger.test")
    )
    unsupported = invocation().model_copy(update={"operation": "write"})
    with pytest.raises(EvidenceCollectionError) as operation_error:
        asyncio.run(collector.collect(unsupported))
    assert operation_error.value.code == "operation_not_supported"

    application = FastAPI()

    @application.get("/v1/evidence/shipments/{reference}")
    async def mismatched(reference: str) -> dict[str, object]:
        del reference
        return {
            "schema_version": "cargomesh.synthetic-evidence/v1",
            "source_record_id": "synthetic-ledger:OTHER",
            "source_system": "synthetic.ledger",
            "channel": "SYSTEM_RECORD",
            "subject_reference": "OTHER",
            "observed_at": "2026-01-01T00:00:00Z",
            "claims": {
                "shipment.reference": "OTHER",
                "shipment.status": "IN_TRANSIT",
            },
            "synthetic": True,
        }

    patch_client(monkeypatch, application)
    with pytest.raises(EvidenceCollectionError) as subject_error:
        asyncio.run(collector.collect(invocation()))
    assert subject_error.value.code == "invalid_response_schema"


@pytest.mark.parametrize(
    ("response", "expected_code"),
    [
        (RedirectResponse("/elsewhere"), "redirect_rejected"),
        (PlainTextResponse("not json"), "invalid_content_type"),
        (Response(b"x" * 128, media_type="application/json"), "response_too_large"),
    ],
)
def test_redirect_content_type_and_size_are_bounded(
    monkeypatch: pytest.MonkeyPatch,
    response: Response,
    expected_code: str,
) -> None:
    application = FastAPI()

    @application.get("/v1/evidence/shipments/{reference}")
    async def evidence(reference: str) -> Response:
        del reference
        return response

    patch_client(monkeypatch, application)
    collector = SyntheticLedgerHttpCollector(
        SyntheticLedgerHttpCollectorConfig(
            "http://ledger.test", max_response_bytes=64
        )
    )
    with pytest.raises(EvidenceCollectionError) as error:
        asyncio.run(collector.collect(invocation()))
    assert error.value.code == expected_code
