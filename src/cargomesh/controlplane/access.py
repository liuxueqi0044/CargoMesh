"""Fail-closed orchestration for authentication, authorization, and audit."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

from .models import (
    AccessAction,
    AuditEvent,
    AuditRecord,
    AuditResult,
    AuditScalar,
    AuthorizationDecision,
    AuthorizationRequest,
    Principal,
)


class Authenticator(Protocol):
    async def authenticate(self, token: str, *, now: datetime) -> Principal: ...


class Authorizer(Protocol):
    def authorize(self, request: AuthorizationRequest) -> AuthorizationDecision: ...


class AuditWriter(Protocol):
    def append(self, event: AuditEvent) -> AuditRecord: ...


class AccessControlError(RuntimeError):
    """Bounded access failure safe for the existing HTTP error normalizer."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        status_code: int,
        authenticate_header: bool = False,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code
        self.authenticate_header = authenticate_header


@dataclass(frozen=True, slots=True)
class AccessGrant:
    principal: Principal
    decision: AuthorizationDecision
    request_id: str


class AccessController:
    """Coordinates the three independent security providers.

    An allow/deny audit record is persisted before a mutating endpoint can run.
    A second outcome record is written before its HTTP response is returned.
    """

    def __init__(
        self,
        *,
        authenticator: Authenticator,
        authorizer: Authorizer,
        audit: AuditWriter,
        environment_id: str,
    ) -> None:
        if not environment_id or environment_id != environment_id.strip():
            raise ValueError("environment_id must be a non-empty trimmed string")
        self.authenticator = authenticator
        self.authorizer = authorizer
        self.audit = audit
        self.environment_id = environment_id

    async def authenticate(
        self,
        authorization: str | None,
        *,
        now: datetime | None = None,
    ) -> Principal:
        if authorization is None:
            raise AccessControlError(
                "authentication_required",
                "Bearer authentication is required",
                status_code=401,
                authenticate_header=True,
            )
        scheme, separator, token = authorization.partition(" ")
        if (
            separator != " "
            or scheme.casefold() != "bearer"
            or not token
            or token != token.strip()
            or " " in token
        ):
            raise AccessControlError(
                "invalid_credentials",
                "Bearer credentials are invalid",
                status_code=401,
                authenticate_header=True,
            )
        try:
            return await self.authenticator.authenticate(token, now=_utc_now(now))
        except AccessControlError:
            raise
        except Exception as exc:
            raise AccessControlError(
                "invalid_credentials",
                "Bearer credentials are invalid",
                status_code=401,
                authenticate_header=True,
            ) from exc

    def require(
        self,
        principal: Principal,
        *,
        action: AccessAction,
        tenant_id: str,
        resource_type: str,
        resource_id: str | None,
        request_id: str,
        now: datetime | None = None,
    ) -> AccessGrant:
        evaluated_at = _utc_now(now)
        request = AuthorizationRequest(
            principal=principal,
            tenant_id=tenant_id,
            environment_id=self.environment_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            evaluated_at=evaluated_at,
        )
        try:
            decision = self.authorizer.authorize(request)
        except Exception as exc:
            raise AccessControlError(
                "access_control_unavailable",
                "Access control is unavailable",
                status_code=503,
            ) from exc
        if decision.request != request:
            raise AccessControlError(
                "access_control_unavailable",
                "Access control is unavailable",
                status_code=503,
            )

        grant = AccessGrant(principal=principal, decision=decision, request_id=request_id)
        self._write_audit(
            grant,
            result=AuditResult.ALLOWED if decision.allowed else AuditResult.DENIED,
            reason_code=decision.reason_code,
            phase="authorization",
            occurred_at=evaluated_at,
        )
        if decision.allowed:
            return grant
        if decision.reason_code == "membership_provider_error":
            raise AccessControlError(
                "access_control_unavailable",
                "Access control is unavailable",
                status_code=503,
            )
        if decision.reason_code in {"tenant_membership_missing", "environment_scope_mismatch"}:
            raise AccessControlError(
                "transaction_not_found",
                "Transaction was not found",
                status_code=404,
            )
        raise AccessControlError(
            "authorization_denied",
            "The authenticated principal is not authorized for this action",
            status_code=403,
        )

    def record_outcome(
        self,
        grant: AccessGrant,
        *,
        succeeded: bool,
        reason_code: str,
        details: dict[str, AuditScalar] | None = None,
        now: datetime | None = None,
    ) -> AuditRecord:
        return self._write_audit(
            grant,
            result=AuditResult.ALLOWED if succeeded else AuditResult.ERROR,
            reason_code=reason_code,
            phase="outcome",
            details=details,
            occurred_at=_utc_now(now),
        )

    def _write_audit(
        self,
        grant: AccessGrant,
        *,
        result: AuditResult,
        reason_code: str,
        phase: str,
        occurred_at: datetime,
        details: dict[str, AuditScalar] | None = None,
    ) -> AuditRecord:
        request = grant.decision.request
        bounded_details: dict[str, AuditScalar] = {"phase": phase}
        if details:
            bounded_details.update(details)
        event = AuditEvent.issue(
            event_id=str(uuid.uuid4()),
            tenant_id=request.tenant_id,
            environment_id=request.environment_id,
            actor_issuer=grant.principal.issuer,
            actor_subject=grant.principal.subject,
            actor_type=grant.principal.principal_type,
            action=request.action,
            resource_type=request.resource_type,
            resource_id=request.resource_id,
            result=result,
            reason_code=reason_code,
            request_id=grant.request_id,
            authorization_decision_digest=grant.decision.decision_digest,
            details=bounded_details,
            occurred_at=occurred_at,
        )
        try:
            return self.audit.append(event)
        except Exception as exc:
            raise AccessControlError(
                "audit_unavailable",
                "Security audit is unavailable",
                status_code=503,
            ) from exc


def _utc_now(value: datetime | None) -> datetime:
    now = value or datetime.now(UTC)
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("access-control time must include a timezone")
    return now.astimezone(UTC)
