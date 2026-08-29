"""Immutable contracts shared by the CargoMesh durable execution runtime."""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Annotated, Final, Literal

from pydantic import BaseModel, ConfigDict, Field, JsonValue, StringConstraints, model_validator

from cargomesh.ir.enums import RiskClass, VerificationLevel
from cargomesh.verification.models import (
    ExecutionSource,
    VerificationPlan,
    VerificationReport,
)

EXECUTION_PLAN_SCHEMA_VERSION: Final[Literal["cargomesh.execution-plan/v1"]] = (
    "cargomesh.execution-plan/v1"
)

RuntimeIdentifier = Annotated[
    str, StringConstraints(strip_whitespace=True, min_length=1, max_length=256)
]
RuntimeName = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=128,
        pattern=r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$",
    ),
]

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_SECRET_KEY_RE = re.compile(
    r"(?:^|[._-])(?:authorization|cookie|credential|password|secret|token)(?:$|[._-])",
    re.IGNORECASE,
)


class RuntimeModel(BaseModel):
    """Strict, immutable base for data persisted in workflow history."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class ExecutionStatus(StrEnum):
    ACCEPTED = "ACCEPTED"
    RUNNING = "RUNNING"
    WAITING_APPROVAL = "WAITING_APPROVAL"
    COMPENSATING = "COMPENSATING"
    VERIFYING = "VERIFYING"
    VERIFIED = "VERIFIED"
    NEEDS_REVIEW = "NEEDS_REVIEW"
    EXECUTED_UNVERIFIED = "EXECUTED_UNVERIFIED"
    COMPENSATED = "COMPENSATED"
    REJECTED = "REJECTED"
    HALTED = "HALTED"
    CANCELLED = "CANCELLED"


TERMINAL_EXECUTION_STATUSES = frozenset(
    {
        ExecutionStatus.EXECUTED_UNVERIFIED,
        ExecutionStatus.VERIFIED,
        ExecutionStatus.NEEDS_REVIEW,
        ExecutionStatus.COMPENSATED,
        ExecutionStatus.REJECTED,
        ExecutionStatus.HALTED,
        ExecutionStatus.CANCELLED,
    }
)


class RetryPolicySpec(RuntimeModel):
    """Portable subset of Temporal activity retry policy."""

    initial_interval_seconds: float = Field(default=1.0, gt=0, le=3600)
    backoff_coefficient: float = Field(default=2.0, ge=1.0, le=100.0)
    maximum_interval_seconds: float = Field(default=60.0, gt=0, le=86400)
    maximum_attempts: int = Field(default=3, ge=1, le=100)
    non_retryable_error_types: tuple[RuntimeName, ...] = ()

    @model_validator(mode="after")
    def validate_intervals(self) -> RetryPolicySpec:
        if self.maximum_interval_seconds < self.initial_interval_seconds:
            raise ValueError("maximum retry interval must not be below the initial interval")
        if len(self.non_retryable_error_types) != len(set(self.non_retryable_error_types)):
            raise ValueError("non-retryable error types must not contain duplicates")
        return self


class CompensationSpec(RuntimeModel):
    adapter: RuntimeName
    operation: RuntimeName
    input: dict[str, JsonValue] = Field(default_factory=dict)
    timeout_seconds: int = Field(default=60, ge=1, le=86400)
    retry: RetryPolicySpec = Field(default_factory=RetryPolicySpec)


class ExecutionStep(RuntimeModel):
    step_id: RuntimeName
    capability: RuntimeName
    adapter: RuntimeName
    operation: RuntimeName
    risk_class: RiskClass = RiskClass.READ_ONLY
    input: dict[str, JsonValue] = Field(default_factory=dict)
    depends_on: tuple[RuntimeName, ...] = ()
    timeout_seconds: int = Field(default=60, ge=1, le=86400)
    retry: RetryPolicySpec = Field(default_factory=RetryPolicySpec)
    requires_approval: bool = False
    approval_timeout_seconds: int | None = Field(default=None, ge=1, le=604800)
    compensation: CompensationSpec | None = None

    @model_validator(mode="after")
    def validate_step(self) -> ExecutionStep:
        if self.step_id in self.depends_on:
            raise ValueError("a step cannot depend on itself")
        if len(self.depends_on) != len(set(self.depends_on)):
            raise ValueError("step dependencies must not contain duplicates")
        if not self.requires_approval and self.approval_timeout_seconds is not None:
            raise ValueError("approval timeout requires an approval boundary")
        if self.risk_class is RiskClass.READ_ONLY and self.compensation is not None:
            raise ValueError("read-only execution steps must not declare compensation")
        _reject_secret_values(self.input)
        if self.compensation is not None:
            _reject_secret_values(self.compensation.input)
        return self


class ExecutionPlan(RuntimeModel):
    schema_version: Literal["cargomesh.execution-plan/v1"] = EXECUTION_PLAN_SCHEMA_VERSION
    transaction_id: RuntimeIdentifier
    tenant_id: RuntimeIdentifier
    business_digest: str
    risk_class: RiskClass
    verification_level: VerificationLevel
    steps: tuple[ExecutionStep, ...]
    verification: VerificationPlan | None = None

    @model_validator(mode="after")
    def validate_plan(self) -> ExecutionPlan:
        if _DIGEST_RE.fullmatch(self.business_digest) is None:
            raise ValueError("business_digest must be a lowercase sha256 digest")
        if not self.steps:
            raise ValueError("execution plan must contain at least one step")
        step_ids = [step.step_id for step in self.steps]
        if len(step_ids) != len(set(step_ids)):
            raise ValueError("execution plan step ids must be unique")
        available: set[str] = set()
        for step in self.steps:
            missing = set(step.depends_on) - available
            if missing:
                raise ValueError(
                    f"step {step.step_id} has unknown or forward dependencies: "
                    + ", ".join(sorted(missing))
                )
            available.add(step.step_id)
        risk_rank = {
            RiskClass.READ_ONLY: 0,
            RiskClass.REVERSIBLE_WRITE: 1,
            RiskClass.CONSEQUENTIAL_WRITE: 2,
        }
        maximum_step_risk = max(self.steps, key=lambda step: risk_rank[step.risk_class]).risk_class
        if maximum_step_risk is not self.risk_class:
            raise ValueError("plan risk_class must equal the highest step risk class")
        if (
            self.verification is not None
            and self.verification.required_level is not self.verification_level
        ):
            raise ValueError("verification plan level must equal execution plan level")
        return self


class AdapterInvocation(RuntimeModel):
    transaction_id: RuntimeIdentifier
    tenant_id: RuntimeIdentifier
    step_id: RuntimeName
    adapter: RuntimeName
    operation: RuntimeName
    input: dict[str, JsonValue]


class AdapterResult(RuntimeModel):
    output: dict[str, JsonValue] = Field(default_factory=dict)
    effect_reference: RuntimeIdentifier | None = None
    execution_source: ExecutionSource | None = None


class ApprovalDecision(RuntimeModel):
    step_id: RuntimeName
    approved: bool
    decided_by: RuntimeIdentifier
    reason: Annotated[str, StringConstraints(strip_whitespace=True, max_length=1000)] | None = None

    @model_validator(mode="after")
    def require_rejection_reason(self) -> ApprovalDecision:
        if not self.approved and not self.reason:
            raise ValueError("a rejected approval requires a reason")
        return self


class StepOutput(RuntimeModel):
    step_id: RuntimeName
    output: dict[str, JsonValue] = Field(default_factory=dict)
    effect_reference: RuntimeIdentifier | None = None
    execution_source: ExecutionSource | None = None


class ExecutionSnapshot(RuntimeModel):
    transaction_id: RuntimeIdentifier
    workflow_id: RuntimeIdentifier
    status: ExecutionStatus = ExecutionStatus.ACCEPTED
    current_step_id: RuntimeName | None = None
    awaiting_approval_step_id: RuntimeName | None = None
    completed_step_ids: tuple[RuntimeName, ...] = ()
    compensated_step_ids: tuple[RuntimeName, ...] = ()
    outputs: tuple[StepOutput, ...] = ()
    failure_code: RuntimeName | None = None
    verification: VerificationReport | None = None

    @property
    def terminal(self) -> bool:
        return self.status in TERMINAL_EXECUTION_STATUSES


def _reject_secret_values(value: JsonValue, *, path: str = "input") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            next_path = f"{path}.{key}"
            if _SECRET_KEY_RE.search(key):
                raise ValueError(
                    f"{next_path} looks like secret material; pass a credential reference instead"
                )
            _reject_secret_values(item, path=next_path)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _reject_secret_values(item, path=f"{path}[{index}]")
