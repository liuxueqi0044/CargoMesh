from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import pytest

from cargomesh.controlplane.access import AccessControlError, AccessController
from cargomesh.controlplane.models import (
    AccessAction,
    AuditRecord,
    AuthorizationDecision,
    MembershipRole,
    Principal,
    PrincipalType,
)

NOW = datetime(2026, 8, 31, 1, 0, tzinfo=UTC)


def _principal() -> Principal:
    return Principal(
        issuer="https://identity.example",
        subject="user-1",
        principal_type=PrincipalType.HUMAN,
        audiences=("cargomesh",),
        token_id_digest="sha256:" + "1" * 64,
        issued_at=NOW - timedelta(minutes=5),
        expires_at=NOW + timedelta(minutes=5),
        authenticated_at=NOW,
    )


class Authenticator:
    async def authenticate(self, token: str, *, now: datetime) -> Principal:
        del now
        if token != "valid-token":
            raise ValueError("invalid token")
        return _principal()


class Authorizer:
    def __init__(self, *, allowed: bool = True, reason: str = "role_allowed") -> None:
        self.allowed = allowed
        self.reason = reason

    def authorize(self, request: object) -> AuthorizationDecision:
        return AuthorizationDecision.issue(
            request=request,
            allowed=self.allowed,
            reason_code=self.reason,
            matched_roles=(MembershipRole.OPERATOR,) if self.allowed else (),
            membership_revision=1 if self.allowed else None,
        )


class Audit:
    def __init__(self, *, fail: bool = False) -> None:
        self.events: list[object] = []
        self.fail = fail

    def append(self, event: object) -> AuditRecord:
        if self.fail:
            raise RuntimeError("audit failed")
        self.events.append(event)
        return AuditRecord.issue(sequence=1, event=event, previous_record_digest=None)


def test_authenticate_require_and_record_outcome() -> None:
    audit = Audit()
    controller = AccessController(
        authenticator=Authenticator(),
        authorizer=Authorizer(),
        audit=audit,
        environment_id="production",
    )

    principal = asyncio.run(controller.authenticate("Bearer valid-token", now=NOW))
    grant = controller.require(
        principal,
        action=AccessAction.TRANSACTION_CREATE,
        tenant_id="tenant-a",
        resource_type="transaction",
        resource_id=None,
        request_id="request-1",
        now=NOW,
    )
    controller.record_outcome(
        grant,
        succeeded=True,
        reason_code="transaction_created",
        details={"replayed": False},
        now=NOW,
    )

    assert len(audit.events) == 2
    assert audit.events[0].details == {"phase": "authorization"}
    assert audit.events[1].details == {"phase": "outcome", "replayed": False}


def test_authentication_and_scope_denials_are_bounded() -> None:
    controller = AccessController(
        authenticator=Authenticator(),
        authorizer=Authorizer(allowed=False, reason="tenant_membership_missing"),
        audit=Audit(),
        environment_id="production",
    )

    with pytest.raises(AccessControlError) as missing:
        asyncio.run(controller.authenticate(None, now=NOW))
    assert missing.value.status_code == 401

    with pytest.raises(AccessControlError) as invalid:
        asyncio.run(controller.authenticate("Bearer invalid-token", now=NOW))
    assert invalid.value.code == "invalid_credentials"
    assert "invalid-token" not in invalid.value.message

    principal = asyncio.run(controller.authenticate("Bearer valid-token", now=NOW))
    with pytest.raises(AccessControlError) as denied:
        controller.require(
            principal,
            action=AccessAction.TRANSACTION_READ,
            tenant_id="tenant-b",
            resource_type="transaction",
            resource_id="tx-1",
            request_id="request-2",
            now=NOW,
        )
    assert denied.value.status_code == 404
    assert denied.value.code == "transaction_not_found"


def test_audit_failure_prevents_authorized_operation() -> None:
    controller = AccessController(
        authenticator=Authenticator(),
        authorizer=Authorizer(),
        audit=Audit(fail=True),
        environment_id="production",
    )
    principal = asyncio.run(controller.authenticate("Bearer valid-token", now=NOW))

    with pytest.raises(AccessControlError) as failed:
        controller.require(
            principal,
            action=AccessAction.TRANSACTION_CANCEL,
            tenant_id="tenant-a",
            resource_type="transaction",
            resource_id="tx-1",
            request_id="request-3",
            now=NOW,
        )

    assert failed.value.code == "audit_unavailable"
    assert failed.value.status_code == 503


def test_membership_provider_failure_is_audited_and_returns_unavailable() -> None:
    audit = Audit()
    controller = AccessController(
        authenticator=Authenticator(),
        authorizer=Authorizer(allowed=False, reason="membership_provider_error"),
        audit=audit,
        environment_id="production",
    )
    principal = asyncio.run(controller.authenticate("Bearer valid-token", now=NOW))

    with pytest.raises(AccessControlError) as failed:
        controller.require(
            principal,
            action=AccessAction.TRANSACTION_READ,
            tenant_id="tenant-a",
            resource_type="transaction",
            resource_id="tx-1",
            request_id="request-4",
            now=NOW,
        )

    assert failed.value.code == "access_control_unavailable"
    assert failed.value.status_code == 503
    assert audit.events[0].result == "DENIED"
