"""Strict contracts for independent evidence and deterministic verification."""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from enum import Enum, StrEnum
from typing import Annotated, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    StringConstraints,
    field_validator,
    model_validator,
)

from cargomesh.ir.enums import VerificationLevel

VERIFICATION_REPORT_SCHEMA_VERSION: Literal["cargomesh.verification-report/v1"] = (
    "cargomesh.verification-report/v1"
)
EVIDENCE_OBSERVATION_SCHEMA_VERSION: Literal["cargomesh.evidence-observation/v1"] = (
    "cargomesh.evidence-observation/v1"
)

VerificationIdentifier = Annotated[
    str, StringConstraints(strip_whitespace=True, min_length=1, max_length=256)
]
VerificationName = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=128,
        pattern=r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$",
    ),
]
JsonPointer = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=512,
        pattern=r"^(?:/(?:[^~/]|~[01])*)+$",
    ),
]
Sha256Digest = Annotated[str, StringConstraints(pattern=r"^sha256:[0-9a-f]{64}$")]
ClaimScalar = str | int | float | bool | None

_SECRET_KEY_RE = re.compile(
    r"(?:^|[._-])(?:authorization|cookie|credential|password|secret|token)(?:$|[._-])",
    re.IGNORECASE,
)
_VERIFICATION_LEVEL_RANK = {
    VerificationLevel.L0: 0,
    VerificationLevel.L1: 1,
    VerificationLevel.L2: 2,
    VerificationLevel.L3: 3,
}


class VerificationModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class EvidenceChannel(StrEnum):
    API = "API"
    BROWSER = "BROWSER"
    DOCUMENT = "DOCUMENT"
    EMAIL = "EMAIL"
    SYSTEM_RECORD = "SYSTEM_RECORD"
    HUMAN_ATTESTATION = "HUMAN_ATTESTATION"


class VerificationVerdict(StrEnum):
    VERIFIED = "VERIFIED"
    NEEDS_REVIEW = "NEEDS_REVIEW"
    HALTED = "HALTED"


class ClaimOutcome(StrEnum):
    MATCH = "MATCH"
    MISMATCH = "MISMATCH"
    MISSING = "MISSING"
    CONFLICT = "CONFLICT"


class ClaimNormalization(StrEnum):
    EXACT = "EXACT"
    CASEFOLD = "CASEFOLD"


class ExecutionSource(VerificationModel):
    source_system: VerificationName
    channel: EvidenceChannel
    adapter_id: VerificationName
    collection_id: VerificationIdentifier
    synthetic: bool = False


class EvidenceObservation(VerificationModel):
    schema_version: Literal["cargomesh.evidence-observation/v1"] = (
        EVIDENCE_OBSERVATION_SCHEMA_VERSION
    )
    evidence_id: VerificationIdentifier
    tenant_id: VerificationIdentifier
    transaction_id: VerificationIdentifier
    source_record_id: VerificationIdentifier
    source_system: VerificationName
    channel: EvidenceChannel
    collector_id: VerificationName
    collection_id: VerificationIdentifier
    observed_at: datetime
    expires_at: datetime | None = None
    claims: dict[VerificationName, ClaimScalar] = Field(min_length=1, max_length=64)
    synthetic: bool = False
    content_digest: Sha256Digest

    @field_validator("observed_at", "expires_at")
    @classmethod
    def require_aware_utc(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("evidence timestamps must include a timezone")
        return value.astimezone(UTC)

    @field_validator("claims")
    @classmethod
    def validate_claims(
        cls, value: dict[str, ClaimScalar]
    ) -> dict[str, ClaimScalar]:
        for key, item in value.items():
            if _SECRET_KEY_RE.search(key):
                raise ValueError("evidence claims must not contain secret-like names")
            if isinstance(item, float) and not math.isfinite(item):
                raise ValueError("evidence claims must contain finite numbers")
            if isinstance(item, str) and len(item) > 4096:
                raise ValueError("evidence claim strings must not exceed 4096 characters")
        return value

    @model_validator(mode="after")
    def validate_lifetime_and_digest(self) -> EvidenceObservation:
        if self.expires_at is not None and self.expires_at <= self.observed_at:
            raise ValueError("evidence expiry must be after its observation time")
        if self.content_digest != _model_digest(self, exclude={"content_digest"}):
            raise ValueError("evidence content digest does not match its canonical content")
        return self

    @classmethod
    def issue(cls, **values: object) -> EvidenceObservation:
        payload = dict(values)
        payload.setdefault("schema_version", EVIDENCE_OBSERVATION_SCHEMA_VERSION)
        unsigned = cls.model_construct(_fields_set=set(payload), **payload)
        payload["content_digest"] = _model_digest(unsigned, exclude={"content_digest"})
        return cls.model_validate(payload)


class EvidenceCollectionSpec(VerificationModel):
    step_id: VerificationName
    collector_id: VerificationName
    operation: VerificationName
    input: dict[str, JsonValue] = Field(default_factory=dict, max_length=32)

    @field_validator("input")
    @classmethod
    def reject_secret_input(cls, value: dict[str, JsonValue]) -> dict[str, JsonValue]:
        _reject_secret_values(value)
        _require_bounded_json(value, maximum_bytes=65_536)
        return value


class VerificationClaimRule(VerificationModel):
    claim: VerificationName
    expected_pointer: JsonPointer
    normalization: ClaimNormalization = ClaimNormalization.EXACT


class VerificationRetryPolicy(VerificationModel):
    initial_interval_seconds: float = Field(default=1.0, gt=0, le=3600)
    backoff_coefficient: float = Field(default=2.0, ge=1.0, le=100.0)
    maximum_interval_seconds: float = Field(default=30.0, gt=0, le=86400)
    maximum_attempts: int = Field(default=3, ge=1, le=20)

    @model_validator(mode="after")
    def validate_intervals(self) -> VerificationRetryPolicy:
        if self.maximum_interval_seconds < self.initial_interval_seconds:
            raise ValueError("maximum interval must not be below the initial interval")
        return self


class VerificationPlan(VerificationModel):
    required_level: VerificationLevel
    collectors: tuple[EvidenceCollectionSpec, ...] = Field(min_length=1, max_length=8)
    claim_rules: tuple[VerificationClaimRule, ...] = Field(min_length=1, max_length=32)
    max_evidence_age_seconds: int = Field(default=3600, ge=1, le=2_592_000)
    future_clock_skew_seconds: int = Field(default=300, ge=0, le=3600)
    timeout_seconds: int = Field(default=30, ge=1, le=86400)
    retry: VerificationRetryPolicy = Field(default_factory=VerificationRetryPolicy)

    @model_validator(mode="after")
    def validate_plan(self) -> VerificationPlan:
        if self.required_level is VerificationLevel.L0:
            raise ValueError("a verification plan cannot request L0")
        step_ids = [step.step_id for step in self.collectors]
        if len(step_ids) != len(set(step_ids)):
            raise ValueError("evidence collection step ids must be unique")
        claim_names = [rule.claim for rule in self.claim_rules]
        if len(claim_names) != len(set(claim_names)):
            raise ValueError("verification claim rules must be unique")
        return self


class EvidenceCollectionInvocation(VerificationModel):
    tenant_id: VerificationIdentifier
    transaction_id: VerificationIdentifier
    step_id: VerificationName
    collector_id: VerificationName
    operation: VerificationName
    input: dict[str, JsonValue] = Field(default_factory=dict, max_length=32)

    @field_validator("input")
    @classmethod
    def validate_input(cls, value: dict[str, JsonValue]) -> dict[str, JsonValue]:
        _reject_secret_values(value)
        _require_bounded_json(value, maximum_bytes=65_536)
        return value


class VerificationInvocation(VerificationModel):
    tenant_id: VerificationIdentifier
    transaction_id: VerificationIdentifier
    business_digest: Sha256Digest
    plan: VerificationPlan
    execution_document: dict[str, JsonValue]
    execution_sources: tuple[ExecutionSource, ...] = Field(default=(), max_length=32)

    @field_validator("execution_document")
    @classmethod
    def validate_execution_document(
        cls, value: dict[str, JsonValue]
    ) -> dict[str, JsonValue]:
        _require_bounded_json(value, maximum_bytes=262_144)
        return value


class EvidenceReceiptSummary(VerificationModel):
    evidence_id: VerificationIdentifier
    source_record_id: VerificationIdentifier
    source_system: VerificationName
    channel: EvidenceChannel
    collector_id: VerificationName
    collection_id: VerificationIdentifier
    observed_at: datetime
    content_digest: Sha256Digest
    synthetic: bool = False

    @field_validator("observed_at")
    @classmethod
    def require_aware_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("receipt timestamps must include a timezone")
        return value.astimezone(UTC)


class ClaimResult(VerificationModel):
    claim: VerificationName
    outcome: ClaimOutcome
    expected: ClaimScalar = None
    observed: tuple[ClaimScalar, ...] = ()


class VerificationReport(VerificationModel):
    schema_version: Literal["cargomesh.verification-report/v1"] = (
        VERIFICATION_REPORT_SCHEMA_VERSION
    )
    transaction_id: VerificationIdentifier
    business_digest: Sha256Digest
    verdict: VerificationVerdict
    required_level: VerificationLevel
    achieved_level: VerificationLevel
    evaluated_at: datetime
    reasons: tuple[VerificationName, ...] = Field(min_length=1, max_length=64)
    claims: tuple[ClaimResult, ...] = Field(max_length=32)
    evidence: tuple[EvidenceReceiptSummary, ...] = Field(max_length=64)
    synthetic: bool = False
    report_digest: Sha256Digest

    @field_validator("evaluated_at")
    @classmethod
    def require_aware_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("report time must include a timezone")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def validate_report(self) -> VerificationReport:
        if not self.reasons:
            raise ValueError("verification report requires at least one reason code")
        if len(self.reasons) != len(set(self.reasons)):
            raise ValueError("verification reason codes must be unique")
        outcomes = {claim.outcome for claim in self.claims}
        if self.verdict is VerificationVerdict.VERIFIED:
            if (
                _VERIFICATION_LEVEL_RANK[self.achieved_level]
                < _VERIFICATION_LEVEL_RANK[self.required_level]
            ):
                raise ValueError("verified report did not achieve its required level")
            if not self.claims or outcomes != {ClaimOutcome.MATCH}:
                raise ValueError("verified report requires only matching claims")
            if not self.evidence:
                raise ValueError("verified report requires evidence receipts")
        if self.verdict is VerificationVerdict.NEEDS_REVIEW and not outcomes.intersection(
            {ClaimOutcome.CONFLICT, ClaimOutcome.MISMATCH}
        ):
            raise ValueError("review report requires a conflicting or mismatched claim")
        if self.report_digest != _model_digest(self, exclude={"report_digest"}):
            raise ValueError("verification report digest does not match")
        return self

    @classmethod
    def issue(cls, **values: object) -> VerificationReport:
        payload = dict(values)
        payload.setdefault("schema_version", VERIFICATION_REPORT_SCHEMA_VERSION)
        unsigned = cls.model_construct(_fields_set=set(payload), **payload)
        payload["report_digest"] = _model_digest(unsigned, exclude={"report_digest"})
        return cls.model_validate(payload)


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
    return value


def _reject_secret_values(value: JsonValue, *, path: str = "input") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if _SECRET_KEY_RE.search(key):
                raise ValueError(f"{path}.{key} looks like secret material")
            _reject_secret_values(item, path=f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _reject_secret_values(item, path=f"{path}[{index}]")


def _require_bounded_json(value: JsonValue, *, maximum_bytes: int) -> None:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    ).encode("utf-8")
    if len(encoded) > maximum_bytes:
        raise ValueError(f"JSON value exceeds {maximum_bytes} bytes")
