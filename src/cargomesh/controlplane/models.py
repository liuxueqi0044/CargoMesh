"""Pure contracts for authenticated tenant access and bounded audit records."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from enum import Enum, StrEnum
from typing import Annotated, Literal, cast

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

PRINCIPAL_SCHEMA_VERSION: Literal["cargomesh.principal/v1"] = "cargomesh.principal/v1"
MEMBERSHIP_SCHEMA_VERSION: Literal["cargomesh.membership/v1"] = "cargomesh.membership/v1"
AUTHORIZATION_DECISION_SCHEMA_VERSION: Literal[
    "cargomesh.authorization-decision/v1"
] = "cargomesh.authorization-decision/v1"
AUDIT_EVENT_SCHEMA_VERSION: Literal["cargomesh.audit-event/v1"] = (
    "cargomesh.audit-event/v1"
)
AUDIT_RECORD_SCHEMA_VERSION: Literal["cargomesh.audit-record/v1"] = (
    "cargomesh.audit-record/v1"
)

ControlIdentifier = Annotated[
    str, StringConstraints(strip_whitespace=True, min_length=1, max_length=256)
]
ControlIssuer = Annotated[
    str, StringConstraints(strip_whitespace=True, min_length=1, max_length=2048)
]
ControlName = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=128,
        pattern=r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$",
    ),
]
Sha256Digest = Annotated[str, StringConstraints(pattern=r"^sha256:[0-9a-f]{64}$")]
AuditScalar = str | int | bool | None

_SECRET_KEY_RE = re.compile(
    r"(?:^|[._-])(?:authorization|cookie|credential|password|secret|token|api[_-]?key)"
    r"(?:$|[._-])",
    re.IGNORECASE,
)
_SECRET_VALUE_RE = re.compile(
    r"(?:\bbearer\s+|\b(?:password|secret|token|cookie|api[_-]?key)\s*[=:]|"
    r"^eyJ[A-Za-z0-9_-]{12,}\.|^[A-Za-z]:[\\/]|^/)",
    re.IGNORECASE,
)


class ControlModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class PrincipalType(StrEnum):
    HUMAN = "HUMAN"
    SERVICE_ACCOUNT = "SERVICE_ACCOUNT"


class MembershipRole(StrEnum):
    TENANT_ADMIN = "tenant_admin"
    OPERATOR = "operator"
    APPROVER = "approver"
    ADAPTER_DEVELOPER = "adapter_developer"
    AUDITOR = "auditor"
    VIEWER = "viewer"
    SERVICE_ACCOUNT = "service_account"


class MembershipStatus(StrEnum):
    ACTIVE = "ACTIVE"
    DISABLED = "DISABLED"


class AccessAction(StrEnum):
    TRANSACTION_CREATE = "transaction.create"
    TRANSACTION_READ = "transaction.read"
    TRANSACTION_APPROVE = "transaction.approve"
    TRANSACTION_CANCEL = "transaction.cancel"
    AUDIT_READ = "audit.read"
    MEMBERSHIP_MANAGE = "membership.manage"


class AuditResult(StrEnum):
    ALLOWED = "ALLOWED"
    DENIED = "DENIED"
    ERROR = "ERROR"


class Principal(ControlModel):
    schema_version: Literal["cargomesh.principal/v1"] = PRINCIPAL_SCHEMA_VERSION
    issuer: ControlIssuer
    subject: ControlIdentifier
    principal_type: PrincipalType
    audiences: tuple[ControlIdentifier, ...] = Field(min_length=1, max_length=8)
    client_id: ControlIdentifier | None = None
    token_id_digest: Sha256Digest
    issued_at: datetime
    expires_at: datetime
    authenticated_at: datetime

    @field_validator("issued_at", "expires_at", "authenticated_at")
    @classmethod
    def require_utc(cls, value: datetime) -> datetime:
        return _aware_utc(value, "principal timestamps")

    @model_validator(mode="after")
    def validate_principal(self) -> Principal:
        if len(self.audiences) != len(set(self.audiences)):
            raise ValueError("principal audiences must be unique")
        if self.expires_at <= self.issued_at:
            raise ValueError("principal expiry must be after issue time")
        if not self.issued_at <= self.authenticated_at < self.expires_at:
            raise ValueError("authentication time must be inside token lifetime")
        return self


class TenantMembership(ControlModel):
    schema_version: Literal["cargomesh.membership/v1"] = MEMBERSHIP_SCHEMA_VERSION
    membership_id: ControlIdentifier
    issuer: ControlIssuer
    subject: ControlIdentifier
    principal_type: PrincipalType
    tenant_id: ControlIdentifier
    environment_id: ControlIdentifier
    role: MembershipRole
    status: MembershipStatus = MembershipStatus.ACTIVE
    revision: int = Field(ge=1, le=2**63 - 1)
    created_at: datetime
    updated_at: datetime
    membership_digest: Sha256Digest

    @field_validator("created_at", "updated_at")
    @classmethod
    def require_utc(cls, value: datetime) -> datetime:
        return _aware_utc(value, "membership timestamps")

    @model_validator(mode="after")
    def validate_membership(self) -> TenantMembership:
        if self.updated_at < self.created_at:
            raise ValueError("membership update time cannot precede creation")
        if self.membership_digest != model_digest(self, exclude={"membership_digest"}):
            raise ValueError("membership digest does not match")
        return self

    @classmethod
    def issue(cls, **values: object) -> TenantMembership:
        return cast(
            TenantMembership,
            issue_model(
                cls,
                values,
                digest_field="membership_digest",
                schema_version=MEMBERSHIP_SCHEMA_VERSION,
            ),
        )


class AuthorizationRequest(ControlModel):
    principal: Principal
    tenant_id: ControlIdentifier
    environment_id: ControlIdentifier
    action: AccessAction
    resource_type: ControlName
    resource_id: ControlIdentifier | None = None
    evaluated_at: datetime

    @field_validator("evaluated_at")
    @classmethod
    def require_utc(cls, value: datetime) -> datetime:
        return _aware_utc(value, "authorization evaluation time")


class AuthorizationDecision(ControlModel):
    schema_version: Literal["cargomesh.authorization-decision/v1"] = (
        AUTHORIZATION_DECISION_SCHEMA_VERSION
    )
    request: AuthorizationRequest
    allowed: bool
    reason_code: ControlName
    matched_roles: tuple[MembershipRole, ...] = Field(default=(), max_length=7)
    membership_revision: int | None = Field(default=None, ge=1, le=2**63 - 1)
    decision_digest: Sha256Digest

    @model_validator(mode="after")
    def validate_decision(self) -> AuthorizationDecision:
        if len(self.matched_roles) != len(set(self.matched_roles)):
            raise ValueError("authorization roles must be unique")
        if tuple(sorted(self.matched_roles, key=str)) != self.matched_roles:
            raise ValueError("authorization roles must be sorted")
        if self.allowed and (not self.matched_roles or self.membership_revision is None):
            raise ValueError("allowed authorization requires matching membership")
        if self.decision_digest != model_digest(self, exclude={"decision_digest"}):
            raise ValueError("authorization decision digest does not match")
        return self

    @classmethod
    def issue(cls, **values: object) -> AuthorizationDecision:
        return cast(
            AuthorizationDecision,
            issue_model(
                cls,
                values,
                digest_field="decision_digest",
                schema_version=AUTHORIZATION_DECISION_SCHEMA_VERSION,
            ),
        )


class AuditEvent(ControlModel):
    schema_version: Literal["cargomesh.audit-event/v1"] = AUDIT_EVENT_SCHEMA_VERSION
    event_id: ControlIdentifier
    tenant_id: ControlIdentifier
    environment_id: ControlIdentifier
    actor_issuer: ControlIssuer
    actor_subject: ControlIdentifier
    actor_type: PrincipalType
    action: AccessAction
    resource_type: ControlName
    resource_id: ControlIdentifier | None = None
    result: AuditResult
    reason_code: ControlName
    request_id: ControlIdentifier
    authorization_decision_digest: Sha256Digest | None = None
    before_digest: Sha256Digest | None = None
    after_digest: Sha256Digest | None = None
    details: dict[ControlName, AuditScalar] = Field(default_factory=dict, max_length=16)
    occurred_at: datetime
    event_digest: Sha256Digest

    @field_validator("occurred_at")
    @classmethod
    def require_utc(cls, value: datetime) -> datetime:
        return _aware_utc(value, "audit event time")

    @field_validator("details")
    @classmethod
    def reject_sensitive_details(
        cls, value: dict[str, AuditScalar]
    ) -> dict[str, AuditScalar]:
        for key, item in value.items():
            if _SECRET_KEY_RE.search(key):
                raise ValueError("audit details contain a secret-like key")
            if isinstance(item, str):
                if len(item) > 512:
                    raise ValueError("audit detail strings must not exceed 512 characters")
                if _SECRET_VALUE_RE.search(item):
                    raise ValueError("audit details contain secret-like material")
        return value

    @model_validator(mode="after")
    def validate_event(self) -> AuditEvent:
        if self.event_digest != model_digest(self, exclude={"event_digest"}):
            raise ValueError("audit event digest does not match")
        return self

    @classmethod
    def issue(cls, **values: object) -> AuditEvent:
        return cast(
            AuditEvent,
            issue_model(
                cls,
                values,
                digest_field="event_digest",
                schema_version=AUDIT_EVENT_SCHEMA_VERSION,
            ),
        )


class AuditRecord(ControlModel):
    schema_version: Literal["cargomesh.audit-record/v1"] = AUDIT_RECORD_SCHEMA_VERSION
    sequence: int = Field(ge=1, le=2**63 - 1)
    event: AuditEvent
    previous_record_digest: Sha256Digest | None = None
    record_digest: Sha256Digest

    @model_validator(mode="after")
    def validate_record(self) -> AuditRecord:
        if self.sequence == 1 and self.previous_record_digest is not None:
            raise ValueError("first audit record cannot have a previous digest")
        if self.sequence > 1 and self.previous_record_digest is None:
            raise ValueError("later audit records require a previous digest")
        if self.record_digest != model_digest(self, exclude={"record_digest"}):
            raise ValueError("audit record digest does not match")
        return self

    @classmethod
    def issue(cls, **values: object) -> AuditRecord:
        return cast(
            AuditRecord,
            issue_model(
                cls,
                values,
                digest_field="record_digest",
                schema_version=AUDIT_RECORD_SCHEMA_VERSION,
            ),
        )


def issue_model(
    model_type: type[TenantMembership]
    | type[AuthorizationDecision]
    | type[AuditEvent]
    | type[AuditRecord],
    values: Mapping[str, object],
    *,
    digest_field: str,
    schema_version: str,
) -> TenantMembership | AuthorizationDecision | AuditEvent | AuditRecord:
    payload = dict(values)
    payload.setdefault("schema_version", schema_version)
    unsigned = model_type.model_construct(_fields_set=set(payload), **payload)
    payload[digest_field] = model_digest(unsigned, exclude={digest_field})
    return model_type.model_validate(payload)


def model_digest(model: BaseModel, *, exclude: set[str]) -> str:
    return value_digest(model.model_dump(mode="python", exclude=exclude, warnings=False))


def value_digest(value: object) -> str:
    canonical = json.dumps(
        canonical_value(value),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def canonical_value(value: object) -> object:
    if isinstance(value, BaseModel):
        return canonical_value(value.model_dump(mode="python"))
    if isinstance(value, datetime):
        return _aware_utc(value, "canonical timestamps").isoformat(timespec="microseconds")
    if isinstance(value, Enum):
        return canonical_value(value.value)
    if isinstance(value, Mapping):
        return {str(key): canonical_value(item) for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        return [canonical_value(item) for item in value]
    return value


def _aware_utc(value: datetime, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must include a timezone")
    return value.astimezone(UTC)
