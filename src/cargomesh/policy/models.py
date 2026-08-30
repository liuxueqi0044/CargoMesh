"""Immutable, payload-free business policy contracts."""

from __future__ import annotations

import hashlib
import json
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

from cargomesh.ir.enums import RiskClass, VerificationLevel
from cargomesh.routing.models import DataClassification, ExecutionChannel

POLICY_INPUT_SCHEMA_VERSION: Literal["cargomesh.policy-input/v1"] = "cargomesh.policy-input/v1"
POLICY_RULE_SCHEMA_VERSION: Literal["cargomesh.policy-rule/v1"] = "cargomesh.policy-rule/v1"
POLICY_SET_SCHEMA_VERSION: Literal["cargomesh.policy-set/v1"] = "cargomesh.policy-set/v1"
POLICY_DECISION_SCHEMA_VERSION: Literal["cargomesh.policy-decision/v1"] = (
    "cargomesh.policy-decision/v1"
)

PolicyIdentifier = Annotated[
    str, StringConstraints(strip_whitespace=True, min_length=1, max_length=256)
]
PolicyName = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=128,
        pattern=r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$",
    ),
]
SemVer = Annotated[
    str,
    StringConstraints(
        pattern=r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$"
    ),
]
Sha256Digest = Annotated[str, StringConstraints(pattern=r"^sha256:[0-9a-f]{64}$")]


class PolicyModel(BaseModel):
    """Strict immutable base for values that may be frozen into a plan."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class PolicyEffect(StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


class PolicyInput(PolicyModel):
    """The bounded policy view of a request, deliberately excluding its body."""

    schema_version: Literal["cargomesh.policy-input/v1"] = POLICY_INPUT_SCHEMA_VERSION
    tenant_id: PolicyIdentifier
    environment_id: PolicyIdentifier
    principal_ref: PolicyIdentifier
    capability: PolicyName
    risk_class: RiskClass
    data_classification: DataClassification
    requested_verification_level: VerificationLevel
    route: PolicyName
    channel: ExecutionChannel
    adapter: PolicyName
    evaluated_at: datetime
    input_digest: Sha256Digest

    @field_validator("evaluated_at")
    @classmethod
    def require_utc(cls, value: datetime) -> datetime:
        return _aware_utc(value, "policy evaluation time")

    @model_validator(mode="after")
    def validate_digest(self) -> PolicyInput:
        if self.input_digest != model_digest(self, exclude={"input_digest"}):
            raise ValueError("policy input digest does not match")
        return self

    @classmethod
    def issue(cls, **values: object) -> PolicyInput:
        return cast(
            PolicyInput,
            issue_model(
                cls,
                values,
                digest_field="input_digest",
                schema_version=POLICY_INPUT_SCHEMA_VERSION,
            ),
        )


class PolicyRule(PolicyModel):
    """A small reviewed predicate.  Empty selector tuples are wildcards."""

    schema_version: Literal["cargomesh.policy-rule/v1"] = POLICY_RULE_SCHEMA_VERSION
    rule_id: PolicyName
    priority: int = Field(ge=-1_000_000, le=1_000_000)
    tenant_ids: tuple[PolicyIdentifier, ...] = Field(default=(), max_length=64)
    environment_ids: tuple[PolicyIdentifier, ...] = Field(default=(), max_length=64)
    principal_refs: tuple[PolicyIdentifier, ...] = Field(default=(), max_length=64)
    capabilities: tuple[PolicyName, ...] = Field(default=(), max_length=64)
    risk_classes: tuple[RiskClass, ...] = Field(default=(), max_length=3)
    data_classifications: tuple[DataClassification, ...] = Field(default=(), max_length=4)
    requested_verification_levels: tuple[VerificationLevel, ...] = Field(
        default=(), max_length=4
    )
    routes: tuple[PolicyName, ...] = Field(default=(), max_length=64)
    channels: tuple[ExecutionChannel, ...] = Field(default=(), max_length=4)
    adapters: tuple[PolicyName, ...] = Field(default=(), max_length=64)
    effect: PolicyEffect
    approval_requirement: PolicyName | None = None
    reason_code: PolicyName
    rule_digest: Sha256Digest

    @model_validator(mode="after")
    def validate_rule(self) -> PolicyRule:
        for field_name in (
            "tenant_ids",
            "environment_ids",
            "principal_refs",
            "capabilities",
            "risk_classes",
            "data_classifications",
            "requested_verification_levels",
            "routes",
            "channels",
            "adapters",
        ):
            value = getattr(self, field_name)
            if len(value) != len(set(value)):
                raise ValueError(f"{field_name} must be unique")
        if self.effect is PolicyEffect.REQUIRE_APPROVAL:
            if self.approval_requirement is None:
                raise ValueError("approval effect requires an approval requirement")
        elif self.approval_requirement is not None:
            raise ValueError("approval requirement requires approval effect")
        if self.rule_digest != model_digest(self, exclude={"rule_digest"}):
            raise ValueError("policy rule digest does not match")
        return self

    @classmethod
    def issue(cls, **values: object) -> PolicyRule:
        return cast(
            PolicyRule,
            issue_model(
                cls,
                values,
                digest_field="rule_digest",
                schema_version=POLICY_RULE_SCHEMA_VERSION,
            ),
        )


class PolicySet(PolicyModel):
    """An immutable reviewed policy set and its ordered-independent identity."""

    schema_version: Literal["cargomesh.policy-set/v1"] = POLICY_SET_SCHEMA_VERSION
    policy_id: PolicyName
    version: SemVer
    rules: tuple[PolicyRule, ...] = Field(default=(), max_length=256)
    policy_digest: Sha256Digest

    @model_validator(mode="after")
    def validate_set(self) -> PolicySet:
        rule_ids = tuple(rule.rule_id for rule in self.rules)
        if len(rule_ids) != len(set(rule_ids)):
            raise ValueError("policy rule ids must be unique")
        if self.policy_digest != model_digest(self, exclude={"policy_digest"}):
            raise ValueError("policy set digest does not match")
        return self

    @classmethod
    def issue(cls, **values: object) -> PolicySet:
        return cast(
            PolicySet,
            issue_model(
                cls,
                values,
                digest_field="policy_digest",
                schema_version=POLICY_SET_SCHEMA_VERSION,
            ),
        )


class PolicyDecision(PolicyModel):
    """A complete, digest-bound decision suitable for workflow plan freezing."""

    schema_version: Literal["cargomesh.policy-decision/v1"] = POLICY_DECISION_SCHEMA_VERSION
    input: PolicyInput
    policy_id: PolicyName
    policy_version: SemVer
    policy_digest: Sha256Digest
    effect: PolicyEffect
    matched_rule_id: PolicyName | None = None
    matched_rule_digest: Sha256Digest | None = None
    approval_requirement: PolicyName | None = None
    reason_code: PolicyName
    evaluated_at: datetime
    decision_digest: Sha256Digest

    @field_validator("evaluated_at")
    @classmethod
    def require_utc(cls, value: datetime) -> datetime:
        return _aware_utc(value, "policy decision time")

    @model_validator(mode="after")
    def validate_decision(self) -> PolicyDecision:
        if self.evaluated_at != self.input.evaluated_at:
            raise ValueError("policy decision time must equal input evaluation time")
        if (self.matched_rule_id is None) != (self.matched_rule_digest is None):
            raise ValueError("matched policy rule identity must be complete")
        if self.effect is PolicyEffect.REQUIRE_APPROVAL:
            if self.approval_requirement is None:
                raise ValueError("approval decision requires an approval requirement")
        elif self.approval_requirement is not None:
            raise ValueError("approval requirement requires approval decision")
        if self.effect is not PolicyEffect.DENY and self.matched_rule_id is None:
            raise ValueError("allow and approval decisions require a matched rule")
        if self.decision_digest != model_digest(self, exclude={"decision_digest"}):
            raise ValueError("policy decision digest does not match")
        return self

    @property
    def result(self) -> PolicyEffect:
        """Compatibility-friendly name for the policy outcome."""

        return self.effect

    @classmethod
    def issue(cls, **values: object) -> PolicyDecision:
        return cast(
            PolicyDecision,
            issue_model(
                cls,
                values,
                digest_field="decision_digest",
                schema_version=POLICY_DECISION_SCHEMA_VERSION,
            ),
        )


def issue_model(
    model_type: type[PolicyInput] | type[PolicyRule] | type[PolicySet] | type[PolicyDecision],
    values: Mapping[str, object],
    *,
    digest_field: str,
    schema_version: str,
) -> PolicyInput | PolicyRule | PolicySet | PolicyDecision:
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
