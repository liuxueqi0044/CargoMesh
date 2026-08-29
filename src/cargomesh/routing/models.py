"""Immutable contracts for deterministic execution-path routing."""

from __future__ import annotations

import hashlib
import json
import math
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

from cargomesh.ir.enums import RiskClass, VerificationLevel

ROUTE_CANDIDATE_SCHEMA_VERSION: Literal["cargomesh.route-candidate/v1"] = (
    "cargomesh.route-candidate/v1"
)
ROUTING_POLICY_SCHEMA_VERSION: Literal["cargomesh.routing-policy/v1"] = (
    "cargomesh.routing-policy/v1"
)
ROUTE_DECISION_SCHEMA_VERSION: Literal["cargomesh.route-decision/v1"] = (
    "cargomesh.route-decision/v1"
)
ROUTE_OUTCOME_SCHEMA_VERSION: Literal["cargomesh.route-outcome/v1"] = (
    "cargomesh.route-outcome/v1"
)

RouteIdentifier = Annotated[
    str, StringConstraints(strip_whitespace=True, min_length=1, max_length=256)
]
RouteName = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=128,
        pattern=r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$",
    ),
]
Sha256Digest = Annotated[str, StringConstraints(pattern=r"^sha256:[0-9a-f]{64}$")]
SemVer = Annotated[
    str,
    StringConstraints(
        pattern=r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$"
    ),
]

_SECRET_KEY_RE = re.compile(
    r"(?:^|[._-])(?:authorization|cookie|credential|password|secret|token)(?:$|[._-])",
    re.IGNORECASE,
)


class RoutingModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class ExecutionChannel(StrEnum):
    API = "API"
    EDI = "EDI"
    BROWSER = "BROWSER"
    HUMAN = "HUMAN"


class DataClassification(StrEnum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    RESTRICTED = "RESTRICTED"


class RouteHealthStatus(StrEnum):
    UNKNOWN = "UNKNOWN"
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    UNAVAILABLE = "UNAVAILABLE"


class RouteOutcomeKind(StrEnum):
    SUCCESS = "SUCCESS"
    RETRYABLE_FAILURE = "RETRYABLE_FAILURE"
    TERMINAL_FAILURE = "TERMINAL_FAILURE"


class RouteAttemptStatus(StrEnum):
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"


class RouteRetryPolicy(RoutingModel):
    initial_interval_seconds: float = Field(default=1.0, gt=0, le=3600)
    backoff_coefficient: float = Field(default=2.0, ge=1.0, le=100.0)
    maximum_interval_seconds: float = Field(default=30.0, gt=0, le=86400)
    maximum_attempts: int = Field(default=3, ge=1, le=20)
    non_retryable_error_types: tuple[RouteName, ...] = Field(default=(), max_length=32)

    @model_validator(mode="after")
    def validate_retry(self) -> RouteRetryPolicy:
        if self.maximum_interval_seconds < self.initial_interval_seconds:
            raise ValueError("maximum retry interval must not be below initial interval")
        if len(self.non_retryable_error_types) != len(
            set(self.non_retryable_error_types)
        ):
            raise ValueError("non-retryable error types must be unique")
        return self


class RouteCandidate(RoutingModel):
    schema_version: Literal["cargomesh.route-candidate/v1"] = (
        ROUTE_CANDIDATE_SCHEMA_VERSION
    )
    candidate_id: RouteName
    capability: RouteName
    adapter: RouteName
    operation: RouteName
    channel: ExecutionChannel
    baseline_success_bps: int = Field(ge=0, le=10_000)
    baseline_sample_weight: int = Field(default=10, ge=1, le=10_000)
    expected_latency_ms: int = Field(ge=1, le=86_400_000)
    cost_micros: int = Field(ge=0, le=10**15)
    static_priority: int = Field(default=100, ge=0, le=1_000_000)
    maximum_risk_class: RiskClass
    maximum_data_classification: DataClassification
    maximum_verification_level: VerificationLevel
    requires_approval: bool = False
    approval_timeout_seconds: int | None = Field(default=None, ge=1, le=604_800)
    timeout_seconds: int = Field(default=60, ge=1, le=86_400)
    retry: RouteRetryPolicy = Field(default_factory=RouteRetryPolicy)
    fallback_on_error_codes: tuple[RouteName, ...] = Field(default=(), max_length=32)
    enabled: bool = True
    profile_digest: Sha256Digest

    @model_validator(mode="after")
    def validate_candidate(self) -> RouteCandidate:
        if not self.requires_approval and self.approval_timeout_seconds is not None:
            raise ValueError("approval timeout requires approval")
        if len(self.fallback_on_error_codes) != len(
            set(self.fallback_on_error_codes)
        ):
            raise ValueError("fallback error codes must be unique")
        for code in self.fallback_on_error_codes:
            if _SECRET_KEY_RE.search(code):
                raise ValueError("fallback error codes must not look like secrets")
        if self.profile_digest != _model_digest(self, exclude={"profile_digest"}):
            raise ValueError("route candidate digest does not match")
        return self

    @classmethod
    def issue(cls, **values: object) -> RouteCandidate:
        return cast(
            RouteCandidate,
            _issue_model(
                cls,
                values,
                digest_field="profile_digest",
                schema_field=ROUTE_CANDIDATE_SCHEMA_VERSION,
            ),
        )


class RoutingWeights(RoutingModel):
    reliability: int = Field(default=60, ge=0, le=1000)
    latency: int = Field(default=25, ge=0, le=1000)
    cost: int = Field(default=15, ge=0, le=1000)

    @model_validator(mode="after")
    def require_weight(self) -> RoutingWeights:
        if self.reliability + self.latency + self.cost <= 0:
            raise ValueError("at least one routing weight must be positive")
        return self


class RoutingPolicy(RoutingModel):
    schema_version: Literal["cargomesh.routing-policy/v1"] = (
        ROUTING_POLICY_SCHEMA_VERSION
    )
    policy_id: RouteName
    version: SemVer
    allowed_channels: tuple[ExecutionChannel, ...] = (
        ExecutionChannel.API,
        ExecutionChannel.EDI,
        ExecutionChannel.BROWSER,
        ExecutionChannel.HUMAN,
    )
    allowed_candidate_ids: tuple[RouteName, ...] = ()
    denied_candidate_ids: tuple[RouteName, ...] = ()
    minimum_success_bps: int = Field(default=0, ge=0, le=10_000)
    maximum_latency_ms: int = Field(default=86_400_000, ge=1, le=86_400_000)
    maximum_cost_micros: int = Field(default=10**15, ge=0, le=10**15)
    maximum_risk_class: RiskClass = RiskClass.CONSEQUENTIAL_WRITE
    maximum_data_classification: DataClassification = DataClassification.RESTRICTED
    minimum_verification_level: VerificationLevel = VerificationLevel.L0
    approval_required_at_or_above: RiskClass | None = None
    minimum_history_samples: int = Field(default=3, ge=0, le=10_000)
    history_window_size: int = Field(default=100, ge=1, le=10_000)
    circuit_failure_threshold: int = Field(default=3, ge=1, le=100)
    circuit_cooldown_seconds: int = Field(default=300, ge=1, le=86_400)
    maximum_fallbacks: int = Field(default=2, ge=0, le=15)
    weights: RoutingWeights = Field(default_factory=RoutingWeights)
    policy_digest: Sha256Digest

    @model_validator(mode="after")
    def validate_policy(self) -> RoutingPolicy:
        for values, message in (
            (self.allowed_channels, "allowed channels"),
            (self.allowed_candidate_ids, "allowed candidates"),
            (self.denied_candidate_ids, "denied candidates"),
        ):
            if len(values) != len(set(values)):
                raise ValueError(f"{message} must be unique")
        if not self.allowed_channels:
            raise ValueError("routing policy must allow at least one channel")
        overlap = set(self.allowed_candidate_ids).intersection(self.denied_candidate_ids)
        if overlap:
            raise ValueError("candidate allow and deny lists must not overlap")
        if self.policy_digest != _model_digest(self, exclude={"policy_digest"}):
            raise ValueError("routing policy digest does not match")
        return self

    @classmethod
    def issue(cls, **values: object) -> RoutingPolicy:
        return cast(
            RoutingPolicy,
            _issue_model(
                cls,
                values,
                digest_field="policy_digest",
                schema_field=ROUTING_POLICY_SCHEMA_VERSION,
            ),
        )


class RoutingRequest(RoutingModel):
    tenant_id: RouteIdentifier
    capability: RouteName
    risk_class: RiskClass
    data_classification: DataClassification = DataClassification.INTERNAL
    required_verification_level: VerificationLevel
    evaluated_at: datetime

    @field_validator("evaluated_at")
    @classmethod
    def require_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("routing evaluation time must include a timezone")
        return value.astimezone(UTC)


class RouteHealthSnapshot(RoutingModel):
    tenant_id: RouteIdentifier
    candidate_id: RouteName
    evaluated_at: datetime
    status: RouteHealthStatus
    sample_count: int = Field(ge=0, le=10_000)
    success_count: int = Field(ge=0, le=10_000)
    retryable_failure_count: int = Field(ge=0, le=10_000)
    terminal_failure_count: int = Field(ge=0, le=10_000)
    consecutive_failures: int = Field(ge=0, le=10_000)
    observed_success_bps: int | None = Field(default=None, ge=0, le=10_000)
    p95_latency_ms: int | None = Field(default=None, ge=0, le=86_400_000)
    last_outcome_at: datetime | None = None
    circuit_open_until: datetime | None = None

    @field_validator("evaluated_at", "last_outcome_at", "circuit_open_until")
    @classmethod
    def require_utc_dates(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("route health timestamps must include a timezone")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def validate_counts(self) -> RouteHealthSnapshot:
        total = (
            self.success_count
            + self.retryable_failure_count
            + self.terminal_failure_count
        )
        if total != self.sample_count:
            raise ValueError("route health counts must equal sample count")
        if self.consecutive_failures > self.sample_count:
            raise ValueError("consecutive failures exceed sample count")
        if self.sample_count == 0:
            if any(
                value is not None
                for value in (
                    self.observed_success_bps,
                    self.p95_latency_ms,
                    self.last_outcome_at,
                    self.circuit_open_until,
                )
            ):
                raise ValueError("empty route health must not fabricate observations")
            if self.status is not RouteHealthStatus.UNKNOWN:
                raise ValueError("empty route health must be UNKNOWN")
        if self.sample_count > 0 and (
            self.observed_success_bps is None
            or self.p95_latency_ms is None
            or self.last_outcome_at is None
        ):
            raise ValueError("non-empty route health requires derived metrics")
        if self.status is RouteHealthStatus.UNAVAILABLE and self.circuit_open_until is None:
            raise ValueError("unavailable route health requires circuit expiry")
        if (
            self.status is RouteHealthStatus.UNAVAILABLE
            and self.circuit_open_until is not None
            and self.circuit_open_until <= self.evaluated_at
        ):
            raise ValueError("unavailable route health requires a future circuit expiry")
        if (
            self.status is not RouteHealthStatus.UNAVAILABLE
            and self.circuit_open_until is not None
        ):
            raise ValueError("only unavailable route health may carry circuit expiry")
        return self


class RouteEvaluation(RoutingModel):
    candidate_id: RouteName
    candidate_digest: Sha256Digest
    health_status: RouteHealthStatus
    eligible: bool
    rejection_reasons: tuple[RouteName, ...] = Field(default=(), max_length=32)
    effective_success_bps: int = Field(ge=0, le=10_000)
    effective_latency_ms: int = Field(ge=0, le=86_400_000)
    cost_micros: int = Field(ge=0, le=10**15)
    reliability_score_bps: int | None = Field(default=None, ge=0, le=10_000)
    latency_score_bps: int | None = Field(default=None, ge=0, le=10_000)
    cost_score_bps: int | None = Field(default=None, ge=0, le=10_000)
    weighted_score_bps: int | None = Field(default=None, ge=0, le=10_000)
    static_priority: int = Field(ge=0, le=1_000_000)

    @model_validator(mode="after")
    def validate_evaluation(self) -> RouteEvaluation:
        scores = (
            self.reliability_score_bps,
            self.latency_score_bps,
            self.cost_score_bps,
            self.weighted_score_bps,
        )
        if self.eligible and (self.rejection_reasons or any(score is None for score in scores)):
            raise ValueError("eligible route evaluation requires scores and no rejections")
        if not self.eligible and (
            not self.rejection_reasons or any(score is not None for score in scores)
        ):
            raise ValueError("ineligible route evaluation requires rejections and no scores")
        if len(self.rejection_reasons) != len(set(self.rejection_reasons)):
            raise ValueError("route rejection reasons must be unique")
        return self


class RouteDecision(RoutingModel):
    schema_version: Literal["cargomesh.route-decision/v1"] = ROUTE_DECISION_SCHEMA_VERSION
    request: RoutingRequest
    policy_id: RouteName
    policy_version: SemVer
    policy_digest: Sha256Digest
    health_snapshots: tuple[RouteHealthSnapshot, ...] = Field(max_length=16)
    evaluations: tuple[RouteEvaluation, ...] = Field(min_length=1, max_length=16)
    ranked_candidate_ids: tuple[RouteName, ...] = Field(min_length=1, max_length=16)
    selected_candidate_id: RouteName
    fallback_candidate_ids: tuple[RouteName, ...] = Field(default=(), max_length=15)
    decision_digest: Sha256Digest

    @model_validator(mode="after")
    def validate_decision(self) -> RouteDecision:
        evaluation_ids = [item.candidate_id for item in self.evaluations]
        if len(evaluation_ids) != len(set(evaluation_ids)):
            raise ValueError("route decision evaluations must be unique")
        health_ids = [item.candidate_id for item in self.health_snapshots]
        if len(health_ids) != len(set(health_ids)):
            raise ValueError("route decision health snapshots must be unique")
        if not set(health_ids).issubset(evaluation_ids):
            raise ValueError("route decision health must belong to evaluated candidates")
        if any(
            item.tenant_id != self.request.tenant_id
            or item.evaluated_at != self.request.evaluated_at
            for item in self.health_snapshots
        ):
            raise ValueError("route decision health identity does not match request")
        if len(self.ranked_candidate_ids) != len(set(self.ranked_candidate_ids)):
            raise ValueError("ranked candidate ids must be unique")
        eligible_ids = {
            item.candidate_id for item in self.evaluations if item.eligible
        }
        if set(self.ranked_candidate_ids) != eligible_ids:
            raise ValueError("ranked candidates must equal eligible evaluations")
        if self.selected_candidate_id != self.ranked_candidate_ids[0]:
            raise ValueError("selected candidate must be first ranked")
        ranked_fallbacks = [
            candidate_id
            for candidate_id in self.ranked_candidate_ids[1:]
            if candidate_id in self.fallback_candidate_ids
        ]
        if tuple(ranked_fallbacks) != self.fallback_candidate_ids:
            raise ValueError("fallback candidates must preserve ranking order")
        if self.decision_digest != _model_digest(self, exclude={"decision_digest"}):
            raise ValueError("route decision digest does not match")
        return self

    @classmethod
    def issue(cls, **values: object) -> RouteDecision:
        return cast(
            RouteDecision,
            _issue_model(
                cls,
                values,
                digest_field="decision_digest",
                schema_field=ROUTE_DECISION_SCHEMA_VERSION,
            ),
        )


class RouteOutcome(RoutingModel):
    schema_version: Literal["cargomesh.route-outcome/v1"] = ROUTE_OUTCOME_SCHEMA_VERSION
    event_id: RouteIdentifier
    tenant_id: RouteIdentifier
    transaction_id: RouteIdentifier
    step_id: RouteName
    candidate_id: RouteName
    temporal_attempt: int = Field(ge=1, le=100)
    kind: RouteOutcomeKind
    latency_ms: int = Field(ge=0, le=86_400_000)
    failure_code: RouteName | None = None
    occurred_at: datetime
    outcome_digest: Sha256Digest

    @field_validator("occurred_at")
    @classmethod
    def require_outcome_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("route outcome time must include a timezone")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def validate_outcome(self) -> RouteOutcome:
        if self.kind is RouteOutcomeKind.SUCCESS and self.failure_code is not None:
            raise ValueError("successful route outcome must not have a failure code")
        if self.kind is not RouteOutcomeKind.SUCCESS and self.failure_code is None:
            raise ValueError("failed route outcome requires a failure code")
        if self.outcome_digest != _model_digest(self, exclude={"outcome_digest"}):
            raise ValueError("route outcome digest does not match")
        return self

    @classmethod
    def issue(cls, **values: object) -> RouteOutcome:
        return cast(
            RouteOutcome,
            _issue_model(
                cls,
                values,
                digest_field="outcome_digest",
                schema_field=ROUTE_OUTCOME_SCHEMA_VERSION,
            ),
        )


def _issue_model(
    model_type: type[RouteCandidate]
    | type[RoutingPolicy]
    | type[RouteDecision]
    | type[RouteOutcome],
    values: Mapping[str, object],
    *,
    digest_field: str,
    schema_field: str,
) -> RouteCandidate | RoutingPolicy | RouteDecision | RouteOutcome:
    payload = dict(values)
    payload.setdefault("schema_version", schema_field)
    unsigned = model_type.model_construct(_fields_set=set(payload), **payload)
    payload[digest_field] = _model_digest(unsigned, exclude={digest_field})
    return model_type.model_validate(payload)


def _model_digest(model: BaseModel, *, exclude: set[str]) -> str:
    return _value_digest(
        model.model_dump(mode="python", exclude=exclude, warnings=False)
    )


def _value_digest(value: object) -> str:
    canonical = json.dumps(
        _canonical_value(value),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def _canonical_value(value: object) -> object:
    if isinstance(value, BaseModel):
        return _canonical_value(value.model_dump(mode="python"))
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("canonical timestamps must include a timezone")
        return value.astimezone(UTC).isoformat(timespec="microseconds")
    if isinstance(value, Enum):
        return _canonical_value(value.value)
    if isinstance(value, Mapping):
        return {str(key): _canonical_value(item) for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        return [_canonical_value(item) for item in value]
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("canonical numbers must be finite")
    return value
