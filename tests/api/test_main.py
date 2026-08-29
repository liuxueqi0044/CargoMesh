from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient

from cargomesh.api.main import create_app
from cargomesh.application.compile import CompilationError, CompilationResult


class FakeCompileService:
    def compile(self, source: str, payload: Any, *, context: Any = None) -> CompilationResult:
        del payload, context
        return CompilationResult(
            command={"schema_version": "cargomesh.transaction/v1"},
            canonical_json='{"schema_version":"cargomesh.transaction/v1"}',
            digest="sha256:" + "b" * 64,
            diagnostics=[],
            source_schema_version=source,
        )


class FakeReferenceProvider:
    def get_namespace(self, namespace: str, *, as_of: str | None = None) -> dict[str, Any]:
        return {"namespace": namespace, "as_of": as_of, "records": [{"code": "CN"}]}


class FakeTransactionService:
    def __init__(self) -> None:
        self.submit_calls: list[tuple[Any, str]] = []
        self.approval_calls: list[tuple[str, Any]] = []
        self.cancel_calls: list[str] = []

    async def submit(self, compilation: Any, idempotency_key: str) -> dict[str, Any]:
        self.submit_calls.append((compilation, idempotency_key))
        return {
            "transaction_id": "tx-1",
            "status": "ACCEPTED",
            "replayed": idempotency_key == "replay-key",
        }

    async def get(self, transaction_id: str) -> dict[str, Any]:
        return {"transaction_id": transaction_id, "status": "RUNNING"}

    async def approve(self, transaction_id: str, decision: Any) -> dict[str, Any]:
        self.approval_calls.append((transaction_id, decision))
        return {"transaction_id": transaction_id, "status": "RUNNING"}

    async def cancel(self, transaction_id: str) -> dict[str, Any]:
        self.cancel_calls.append(transaction_id)
        return {"transaction_id": transaction_id, "status": "CANCELLED"}


def test_healthz_has_request_id() -> None:
    client = TestClient(create_app(compile_service=FakeCompileService()))
    response = client.get("/healthz", headers={"X-Request-ID": "test-request"})

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    assert response.headers["X-Request-ID"] == "test-request"


def test_compile_and_reference_data_are_offline() -> None:
    client = TestClient(
        create_app(
            compile_service=FakeCompileService(),
            reference_data_provider=FakeReferenceProvider(),
        )
    )
    compile_response = client.post(
        "/v1/ir/compile",
        json={
            "source_schema_version": "cargomesh.transaction/v1",
            "payload": {"schema_version": "cargomesh.transaction/v1"},
        },
    )
    reference_response = client.get(
        "/v1/reference-data/un-location", params={"as_of": "2026-01-01"}
    )

    assert compile_response.status_code == 200
    assert compile_response.json()["business_digest"].startswith("sha256:")
    assert reference_response.json()["records"] == [{"code": "CN"}]


def test_dcsa_query_compiles_with_tenant_context() -> None:
    client = TestClient(create_app())
    response = client.post(
        "/v1/ir/compile",
        json={
            "source_schema_version": "dcsa.tnt.query/v2.3",
            "payload": {"carrierBookingReference": "ABC-123"},
            "context": {"tenant_id": "tenant-a"},
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["source_schema_version"] == "dcsa.tnt.query/v2.3"
    assert body["target_schema_version"] == "cargomesh.transaction/v1"
    assert body["transaction_ir"]["external_reference"] == "ABC-123"


def test_default_reference_catalog_and_contract_schemas_are_available() -> None:
    client = TestClient(create_app())

    reference_response = client.get("/v1/reference-data/dcsa.tnt.event_type")
    dcsa_schema_response = client.get("/v1/contracts/dcsa-tnt-query-v2.3/schema")
    capabilities_response = client.get("/v1/capabilities")

    assert reference_response.status_code == 200
    assert {record["code"] for record in reference_response.json()["records"]} == {
        "EQUIPMENT",
        "SHIPMENT",
        "TRANSPORT",
    }
    dcsa_properties = dcsa_schema_response.json()["properties"]
    assert "carrierBookingReference" in dcsa_properties
    assert "ISSU" in dcsa_properties["shipmentEventTypeCode"]["items"]["enum"]
    assert capabilities_response.json()["capabilities"] == [
        {
            "name": "shipment.track.read",
            "source_schema_version": "dcsa.tnt.query/v2.3",
            "target_schema_version": "cargomesh.transaction/v1",
        }
    ]


def test_compile_request_rejects_implicit_or_unknown_fields() -> None:
    client = TestClient(create_app())
    response = client.post(
        "/v1/ir/compile",
        json={"carrierBookingReference": "ABC-123", "tenant_id": "tenant-a"},
    )

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "invalid_request"


def test_errors_are_stable_and_do_not_expose_tracebacks() -> None:
    class BrokenCompileService(FakeCompileService):
        def compile(self, source: str, payload: Any, *, context: Any = None) -> CompilationResult:
            del source, payload, context
            raise CompilationError("invalid_ir", "Payload is not valid CargoMesh Transaction IR")

    client = TestClient(create_app(compile_service=BrokenCompileService()))
    response = client.post(
        "/v1/ir/compile",
        json={"source_schema_version": "cargomesh.transaction/v1", "payload": {}},
    )

    assert response.status_code == 422
    assert set(response.json()["error"]) == {"code", "message", "request_id"}
    assert "Traceback" not in response.text


def test_transaction_transport_submit_replay_lookup_approval_and_cancel() -> None:
    runtime = FakeTransactionService()
    client = TestClient(
        create_app(compile_service=FakeCompileService(), transaction_service=runtime)
    )
    body = {
        "sourceSchemaVersion": "cargomesh.transaction/v1",
        "payload": {"schema_version": "cargomesh.transaction/v1"},
        "context": {"tenant_id": "tenant-a"},
    }

    created = client.post("/v1/transactions", json=body, headers={"Idempotency-Key": "new-key"})
    replayed = client.post(
        "/v1/transactions", json=body, headers={"Idempotency-Key": "replay-key"}
    )
    looked_up = client.get("/v1/transactions/tx-1")
    approved = client.post(
        "/v1/transactions/tx-1/approval",
        json={"step_id": "step-1", "approved": True, "decided_by": "operator"},
    )
    cancelled = client.post("/v1/transactions/tx-1/cancel")

    assert created.status_code == 202
    assert replayed.status_code == 200
    assert looked_up.status_code == approved.status_code == cancelled.status_code == 200
    assert runtime.submit_calls[0][1] == "new-key"
    assert runtime.approval_calls[0][1].step_id == "step-1"
    assert runtime.cancel_calls == ["tx-1"]


def test_transaction_transport_requires_valid_key_and_runtime() -> None:
    body = {
        "source_schema_version": "cargomesh.transaction/v1",
        "payload": {"schema_version": "cargomesh.transaction/v1"},
    }
    client = TestClient(create_app(compile_service=FakeCompileService()))

    missing = client.post("/v1/transactions", json=body)
    invalid = client.post(
        "/v1/transactions", json=body, headers={"Idempotency-Key": "bad key"}
    )
    unavailable = client.post(
        "/v1/transactions", json=body, headers={"Idempotency-Key": "valid-key"}
    )

    assert missing.status_code == invalid.status_code == 400
    assert missing.json()["error"]["code"] == "missing_idempotency_key"
    assert invalid.json()["error"]["code"] == "invalid_idempotency_key"
    assert unavailable.status_code == 503
    assert unavailable.json()["error"]["code"] == "runtime_unavailable"


def test_approval_request_rejects_unknown_fields_without_traceback() -> None:
    runtime = FakeTransactionService()
    client = TestClient(create_app(transaction_service=runtime))
    response = client.post(
        "/v1/transactions/tx-1/approval",
        json={
            "step_id": "step-1",
            "approved": False,
            "decided_by": "operator",
            "unexpected": "field",
        },
    )

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "invalid_request"
    assert "Traceback" not in response.text


def test_rejected_approval_requires_audit_reason() -> None:
    runtime = FakeTransactionService()
    client = TestClient(create_app(transaction_service=runtime))

    response = client.post(
        "/v1/transactions/tx-1/approval",
        json={"step_id": "step-1", "approved": False, "decided_by": "operator"},
    )

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "invalid_request"
    assert runtime.approval_calls == []


def test_unhandled_errors_are_redacted() -> None:
    class ExplodingCompileService(FakeCompileService):
        def compile(self, source: str, payload: Any, *, context: Any = None) -> CompilationResult:
            del source, payload, context
            raise RuntimeError("secret implementation detail")

    client = TestClient(
        create_app(compile_service=ExplodingCompileService()),
        raise_server_exceptions=False,
    )
    response = client.post(
        "/v1/ir/compile",
        json={"source_schema_version": "cargomesh.transaction/v1", "payload": {}},
    )

    assert response.status_code == 500
    assert response.json()["error"]["code"] == "internal_error"
    assert "secret implementation detail" not in response.text
