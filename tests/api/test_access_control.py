from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient

from cargomesh.api.main import create_app
from cargomesh.application.compile import CompilationResult
from cargomesh.controlplane.access import AccessController
from cargomesh.controlplane.models import (
    AccessAction,
    AuditRecord,
    AuthorizationDecision,
    MembershipRole,
    Principal,
    PrincipalType,
)

NOW = datetime(2026, 8, 31, 1, 0, tzinfo=UTC)


class CompileService:
    def compile(self, source: str, payload: Any, *, context: Any = None) -> CompilationResult:
        del payload
        tenant_id = (
            context.get("tenant_id", "tenant-a")
            if isinstance(context, dict)
            else "tenant-a"
        )
        return CompilationResult(
            command={"schema_version": "cargomesh.transaction/v1", "tenant_id": tenant_id},
            canonical_json='{"schema_version":"cargomesh.transaction/v1"}',
            digest="sha256:" + "b" * 64,
            diagnostics=[],
            source_schema_version=source,
        )


class Authenticator:
    async def authenticate(self, token: str, *, now: datetime) -> Principal:
        del now
        if token != "valid-token":
            raise ValueError("bad bearer")
        return Principal(
            issuer="https://identity.example",
            subject="verified-user",
            principal_type=PrincipalType.HUMAN,
            audiences=("cargomesh",),
            token_id_digest="sha256:" + "1" * 64,
            issued_at=NOW - timedelta(minutes=5),
            expires_at=NOW + timedelta(minutes=5),
            authenticated_at=NOW,
        )


class Authorizer:
    def __init__(self, denied_actions: frozenset[AccessAction] = frozenset()) -> None:
        self.denied_actions = denied_actions

    def authorize(self, request: Any) -> AuthorizationDecision:
        in_tenant = request.tenant_id == "tenant-a"
        allowed = in_tenant and request.action not in self.denied_actions
        return AuthorizationDecision.issue(
            request=request,
            allowed=allowed,
            reason_code=(
                "role_allowed"
                if allowed
                else "action_not_permitted"
                if in_tenant
                else "tenant_membership_missing"
            ),
            matched_roles=(MembershipRole.TENANT_ADMIN,) if in_tenant else (),
            membership_revision=7 if in_tenant else None,
        )


class Audit:
    def __init__(self) -> None:
        self.records: list[AuditRecord] = []

    def append(self, event: Any) -> AuditRecord:
        previous = self.records[-1].record_digest if self.records else None
        record = AuditRecord.issue(
            sequence=len(self.records) + 1,
            event=event,
            previous_record_digest=previous,
        )
        self.records.append(record)
        return record


class Runtime:
    def __init__(self) -> None:
        self.approvals: list[Any] = []
        self.cancellations: list[str] = []

    async def submit(self, compilation: Any, idempotency_key: str) -> dict[str, Any]:
        del compilation, idempotency_key
        return {"tenant_id": "tenant-a", "transaction_id": "tx-1", "created": True}

    async def get(self, transaction_id: str) -> dict[str, Any]:
        tenant_id = "tenant-b" if transaction_id == "tx-other" else "tenant-a"
        return {"tenant_id": tenant_id, "transaction_id": transaction_id, "status": "RUNNING"}

    async def approve(self, transaction_id: str, decision: Any) -> dict[str, Any]:
        self.approvals.append(decision)
        return {"tenant_id": "tenant-a", "transaction_id": transaction_id, "status": "RUNNING"}

    async def cancel(self, transaction_id: str) -> dict[str, Any]:
        self.cancellations.append(transaction_id)
        return {"tenant_id": "tenant-a", "transaction_id": transaction_id, "status": "CANCELLED"}


def _client(authorizer: Authorizer | None = None) -> tuple[TestClient, Runtime, Audit]:
    runtime = Runtime()
    audit = Audit()
    controller = AccessController(
        authenticator=Authenticator(),
        authorizer=authorizer or Authorizer(),
        audit=audit,
        environment_id="production",
    )
    client = TestClient(
        create_app(
            compile_service=CompileService(),
            transaction_service=runtime,
            access_controller=controller,
        )
    )
    return client, runtime, audit


def test_protected_api_requires_bearer_and_audits_success() -> None:
    client, _, audit = _client()

    missing = client.get("/v1/transactions/tx-1")
    allowed = client.get(
        "/v1/transactions/tx-1",
        headers={"Authorization": "Bearer valid-token", "X-Request-ID": "request-1"},
    )

    assert missing.status_code == 401
    assert missing.headers["WWW-Authenticate"] == "Bearer"
    assert allowed.status_code == 200
    assert [record.event.details["phase"] for record in audit.records] == [
        "authorization",
        "outcome",
    ]
    assert "valid-token" not in "".join(record.model_dump_json() for record in audit.records)


@pytest.mark.parametrize("operation", ["read", "approve", "cancel"])
def test_cross_tenant_resources_are_hidden_and_mutations_are_never_called(
    operation: str,
) -> None:
    client, runtime, audit = _client()

    if operation == "read":
        denied = client.get(
            "/v1/transactions/tx-other",
            headers={"Authorization": "Bearer valid-token"},
        )
    elif operation == "approve":
        denied = client.post(
            "/v1/transactions/tx-other/approval",
            headers={"Authorization": "Bearer valid-token"},
            json={"step_id": "step-1", "approved": True, "decided_by": "spoofed"},
        )
    else:
        denied = client.post(
            "/v1/transactions/tx-other/cancel",
            headers={"Authorization": "Bearer valid-token"},
        )

    assert denied.status_code == 404
    assert denied.json()["error"]["code"] == "transaction_not_found"
    assert runtime.approvals == []
    assert runtime.cancellations == []
    assert audit.records[-1].event.result == "DENIED"


def test_approval_actor_is_derived_from_authenticated_principal() -> None:
    client, runtime, _ = _client()

    response = client.post(
        "/v1/transactions/tx-1/approval",
        headers={"Authorization": "Bearer valid-token"},
        json={
            "step_id": "step-1",
            "approved": True,
            "decided_by": "spoofed-user",
        },
    )

    assert response.status_code == 200
    assert runtime.approvals[0].decided_by == "verified-user"


def test_transaction_create_is_authorized_against_compiled_tenant() -> None:
    client, _, _ = _client()
    body = {
        "sourceSchemaVersion": "cargomesh.transaction/v1",
        "payload": {"schema_version": "cargomesh.transaction/v1"},
        "context": {"tenant_id": "tenant-b"},
    }

    response = client.post(
        "/v1/transactions",
        headers={"Authorization": "Bearer valid-token", "Idempotency-Key": "request-1"},
        json=body,
    )

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "transaction_not_found"


def test_same_tenant_action_denial_is_forbidden() -> None:
    client, runtime, audit = _client(
        Authorizer(frozenset({AccessAction.TRANSACTION_CANCEL}))
    )

    response = client.post(
        "/v1/transactions/tx-1/cancel",
        headers={"Authorization": "Bearer valid-token"},
    )

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "authorization_denied"
    assert runtime.cancellations == []
    assert audit.records[-1].event.result == "DENIED"
