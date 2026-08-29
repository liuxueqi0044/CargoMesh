from __future__ import annotations

import asyncio

import httpx2
import pytest
from fastapi import FastAPI
from fastapi.responses import Response

from cargomesh.adapters.http_api import (
    SyntheticTrackingHttpAdapter,
    SyntheticTrackingHttpAdapterConfig,
)
from cargomesh.adapters.synthetic_api import create_synthetic_tracking_api
from cargomesh.runtime.adapters import AdapterExecutionError
from cargomesh.runtime.models import AdapterInvocation
from cargomesh.verification.models import EvidenceChannel


def invocation(reference: str = "CBR-001", operation: str = "fetch") -> AdapterInvocation:
    return AdapterInvocation(
        transaction_id="tx-a",
        tenant_id="tenant-a",
        step_id="fetch-shipment",
        adapter="synthetic.api.track",
        operation=operation,
        input={"transaction": {"subject": {"carrier_booking_reference": reference}}},
    )


def patch_client(monkeypatch: pytest.MonkeyPatch, app: FastAPI) -> None:
    original = httpx2.AsyncClient

    def factory(**kwargs: object) -> httpx2.AsyncClient:
        return original(transport=httpx2.ASGITransport(app=app), **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr("cargomesh.adapters.http_api.httpx2.AsyncClient", factory)


def adapter() -> SyntheticTrackingHttpAdapter:
    return SyntheticTrackingHttpAdapter(SyntheticTrackingHttpAdapterConfig("http://tracking.test"))


def test_fetches_normalized_data_and_api_execution_source(monkeypatch: pytest.MonkeyPatch) -> None:
    patch_client(monkeypatch, create_synthetic_tracking_api())

    result = asyncio.run(adapter().execute(invocation()))

    assert result.output == {
        "adapter": "synthetic.api.track",
        "adapter_version": "0.1.0",
        "operation": "fetch",
        "synthetic": True,
        "data": {"shipment.reference": "CBR-001", "shipment.status": "IN_TRANSIT"},
    }
    assert result.execution_source is not None
    assert result.execution_source.source_system == "synthetic.api"
    assert result.execution_source.channel is EvidenceChannel.API
    assert result.execution_source.synthetic is True


@pytest.mark.parametrize(
    ("variant", "code", "retryable"),
    [
        ("server_error", "api_server_error", True),
        ("malformed", "api_response_invalid", False),
        ("not_found", "api_not_found", False),
    ],
)
def test_synthetic_api_faults_are_classified(
    monkeypatch: pytest.MonkeyPatch, variant: str, code: str, retryable: bool
) -> None:
    patch_client(monkeypatch, create_synthetic_tracking_api(variant=variant))  # type: ignore[arg-type]

    with pytest.raises(AdapterExecutionError) as caught:
        asyncio.run(adapter().execute(invocation()))

    assert caught.value.code == code
    assert caught.value.retryable is retryable
    assert "CBR-001" not in caught.value.message


def test_large_response_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    application = FastAPI()

    @application.get("/v1/shipments/{reference}")
    async def large_response(reference: str) -> Response:
        del reference
        return Response(b"x" * 65_537, media_type="application/json")

    patch_client(monkeypatch, application)
    with pytest.raises(AdapterExecutionError) as caught:
        asyncio.run(adapter().execute(invocation()))

    assert caught.value.code == "api_response_invalid"
    assert caught.value.retryable is False


def test_invalid_operation_and_input_fail_closed() -> None:
    with pytest.raises(AdapterExecutionError) as operation:
        asyncio.run(adapter().execute(invocation(operation="submit")))
    assert operation.value.code == "operation_not_supported"

    missing_reference = invocation().model_copy(update={"input": {"transaction": {"subject": {}}}})
    with pytest.raises(AdapterExecutionError) as input_error:
        asyncio.run(adapter().execute(missing_reference))
    assert input_error.value.code == "invalid_adapter_input"


def test_timeout_and_transport_errors_are_retryable(monkeypatch: pytest.MonkeyPatch) -> None:
    class TimeoutClient:
        async def __aenter__(self) -> TimeoutClient:
            raise httpx2.ReadTimeout("timeout")

        async def __aexit__(self, *args: object) -> None:
            return None

    monkeypatch.setattr(
        "cargomesh.adapters.http_api.httpx2.AsyncClient", lambda **_: TimeoutClient()
    )
    with pytest.raises(AdapterExecutionError) as timeout:
        asyncio.run(adapter().execute(invocation()))
    assert timeout.value.code == "api_timeout"
    assert timeout.value.retryable is True

    class TransportClient:
        async def __aenter__(self) -> TransportClient:
            raise httpx2.ConnectError("failed")

        async def __aexit__(self, *args: object) -> None:
            return None

    monkeypatch.setattr(
        "cargomesh.adapters.http_api.httpx2.AsyncClient", lambda **_: TransportClient()
    )
    with pytest.raises(AdapterExecutionError) as transport:
        asyncio.run(adapter().execute(invocation()))
    assert transport.value.code == "api_transport_error"
    assert transport.value.retryable is True


def test_origin_and_size_configuration_is_bounded() -> None:
    with pytest.raises(ValueError):
        SyntheticTrackingHttpAdapterConfig("ftp://tracking.test")
    with pytest.raises(ValueError):
        SyntheticTrackingHttpAdapterConfig("http://tracking.test/private")
    with pytest.raises(ValueError):
        SyntheticTrackingHttpAdapterConfig("http://tracking.test", max_response_bytes=65_537)
    with pytest.raises(ValueError):
        SyntheticTrackingHttpAdapterConfig("http://tracking.test", timeout=True)
