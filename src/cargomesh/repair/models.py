"""Digest-bound metadata contracts for the isolated repair lifecycle."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

RepairIdentifier = Annotated[
    str, StringConstraints(strip_whitespace=True, min_length=1, max_length=256)
]
RepairName = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=128,
        pattern=r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$",
    ),
]
Sha256Digest = Annotated[str, StringConstraints(pattern=r"^sha256:[0-9a-f]{64}$")]
SafeCode = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=128,
        pattern=r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$",
    ),
]
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_PATH_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]*\.json$")
MAX_REPAIR_PATHS = 128
MAX_REPAIR_METADATA_BYTES = 65_536


class RepairModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        str_strip_whitespace=True,
    )


class RepairRequest(RepairModel):
    tenant_id: RepairIdentifier
    environment_id: RepairIdentifier
    job_id: RepairIdentifier
    drift_report_digest: Sha256Digest
    base_package_digest: Sha256Digest
    sanitized_fixture_digest: Sha256Digest
    allowed_paths: tuple[str, ...] = Field(min_length=1, max_length=MAX_REPAIR_PATHS)
    request_digest: Sha256Digest

    @model_validator(mode="after")
    def validate_request(self) -> RepairRequest:
        if len(self.allowed_paths) != len(set(self.allowed_paths)):
            raise ValueError("repair paths must be unique")
        for path in self.allowed_paths:
            _validate_json_path(path)
        if (
            len(
                json.dumps(
                    _canonical(self.model_dump(exclude={"request_digest"})), separators=(",", ":")
                ).encode("utf-8")
            )
            > MAX_REPAIR_METADATA_BYTES
        ):
            raise ValueError("repair request metadata exceeds size limit")
        if self.request_digest != _digest(self.model_dump(exclude={"request_digest"})):
            raise ValueError("repair request digest does not match metadata")
        return self

    @classmethod
    def issue(cls, **values: object) -> RepairRequest:
        payload = dict(values)
        unsigned = cls.model_construct(_fields_set=set(payload), **payload)
        payload["request_digest"] = _digest(unsigned.model_dump())
        return cls.model_validate(payload)

    @property
    def digest(self) -> str:
        return self.request_digest


class RepairBudget(RepairModel):
    max_model_calls: int = Field(ge=1, le=10_000, strict=True)
    max_input_tokens: int = Field(ge=1, le=100_000_000, strict=True)
    max_output_tokens: int = Field(ge=1, le=100_000_000, strict=True)
    max_cost_units: int = Field(ge=1, le=2**63 - 1, strict=True)
    max_files: int = Field(ge=1, le=10_000, strict=True)
    max_candidate_bytes: int = Field(ge=1, le=2**31 - 1, strict=True)
    max_validation_seconds: int = Field(ge=1, le=86_400, strict=True)
    budget_digest: Sha256Digest

    @model_validator(mode="after")
    def validate_budget_digest(self) -> RepairBudget:
        if self.budget_digest != _digest(self.model_dump(exclude={"budget_digest"})):
            raise ValueError("repair budget digest does not match metadata")
        return self

    @classmethod
    def issue(cls, **values: object) -> RepairBudget:
        payload = dict(values)
        unsigned = cls.model_construct(_fields_set=set(payload), **payload)
        payload["budget_digest"] = _digest(unsigned.model_dump())
        return cls.model_validate(payload)

    @property
    def digest(self) -> str:
        return self.budget_digest


class RepairUsage(RepairModel):
    model_calls: int = Field(ge=0, le=10_000, strict=True)
    input_tokens: int = Field(ge=0, le=100_000_000, strict=True)
    output_tokens: int = Field(ge=0, le=100_000_000, strict=True)
    cost_units: int = Field(ge=0, le=2**63 - 1, strict=True)
    files: int = Field(ge=0, le=10_000, strict=True)
    candidate_bytes: int = Field(ge=0, le=2**31 - 1, strict=True)
    validation_seconds: int = Field(ge=0, le=86_400, strict=True)


class RepairCandidate(RepairModel):
    job_id: RepairIdentifier
    request_digest: Sha256Digest
    base_package_digest: Sha256Digest
    candidate_package_digest: Sha256Digest
    changed_paths: tuple[str, ...] = Field(min_length=1, max_length=MAX_REPAIR_PATHS)
    usage: RepairUsage
    result_code: SafeCode
    candidate_digest: Sha256Digest

    @model_validator(mode="after")
    def validate_candidate(self) -> RepairCandidate:
        for path in self.changed_paths:
            _validate_json_path(path)
        if len(self.changed_paths) != len(set(self.changed_paths)):
            raise ValueError("candidate paths must be unique")
        if self.candidate_digest != _digest(self.model_dump(exclude={"candidate_digest"})):
            raise ValueError("candidate digest does not match metadata")
        return self

    @classmethod
    def issue(cls, **values: object) -> RepairCandidate:
        payload = dict(values)
        unsigned = cls.model_construct(_fields_set=set(payload), **payload)
        payload["candidate_digest"] = _digest(unsigned.model_dump())
        return cls.model_validate(payload)


class ValidationReport(RepairModel):
    candidate_digest: Sha256Digest
    tck_report_digest: Sha256Digest
    security_report_digest: Sha256Digest
    passed: bool
    check_codes: tuple[SafeCode, ...] = Field(min_length=1, max_length=128)
    violation_codes: tuple[SafeCode, ...] = Field(default=(), max_length=64)
    duration_seconds: int = Field(ge=0, le=86_400, strict=True)
    report_digest: Sha256Digest

    @model_validator(mode="after")
    def validate_report(self) -> ValidationReport:
        if self.passed and self.violation_codes:
            raise ValueError("passing validation cannot contain violations")
        if self.report_digest != _digest(self.model_dump(exclude={"report_digest"})):
            raise ValueError("validation report digest does not match metadata")
        return self

    @classmethod
    def issue(cls, **values: object) -> ValidationReport:
        payload = dict(values)
        unsigned = cls.model_construct(_fields_set=set(payload), **payload)
        payload["report_digest"] = _digest(unsigned.model_dump())
        return cls.model_validate(payload)


class RepairProposal(RepairModel):
    request_digest: Sha256Digest
    candidate_digest: Sha256Digest
    validation_report_digest: Sha256Digest
    result_code: SafeCode
    created_at: datetime
    expires_at: datetime
    proposal_digest: Sha256Digest

    @model_validator(mode="after")
    def validate_proposal(self) -> RepairProposal:
        if (
            self.created_at.tzinfo is None
            or self.created_at.utcoffset() is None
            or self.expires_at.tzinfo is None
            or self.expires_at.utcoffset() is None
        ):
            raise ValueError("repair proposal times must include a timezone")
        if self.expires_at <= self.created_at:
            raise ValueError("repair proposal must expire after creation")
        if self.proposal_digest != _digest(self.model_dump(exclude={"proposal_digest"})):
            raise ValueError("repair proposal digest does not match metadata")
        return self

    @classmethod
    def issue(cls, **values: object) -> RepairProposal:
        payload = dict(values)
        payload.setdefault("created_at", datetime.now(UTC))
        created_at = payload["created_at"]
        if isinstance(created_at, datetime):
            payload.setdefault("expires_at", created_at + timedelta(hours=1))
        else:
            payload.setdefault("expires_at", datetime.now(UTC) + timedelta(hours=1))
        unsigned = cls.model_construct(_fields_set=set(payload), **payload)
        payload["proposal_digest"] = _digest(unsigned.model_dump())
        return cls.model_validate(payload)


class RepairApproval(RepairModel):
    proposal_digest: Sha256Digest
    principal_digest: Sha256Digest
    approval_attestation_digest: Sha256Digest
    approved: bool
    decision_code: SafeCode
    approval_digest: Sha256Digest

    @model_validator(mode="after")
    def validate_approval(self) -> RepairApproval:
        if self.approval_digest != _digest(self.model_dump(exclude={"approval_digest"})):
            raise ValueError("repair approval digest does not match metadata")
        return self

    @classmethod
    def issue(cls, **values: object) -> RepairApproval:
        payload = dict(values)
        unsigned = cls.model_construct(_fields_set=set(payload), **payload)
        payload["approval_digest"] = _digest(unsigned.model_dump())
        return cls.model_validate(payload)


class CanaryResult(RepairModel):
    proposal_digest: Sha256Digest
    passed: bool
    observation_codes: tuple[SafeCode, ...] = Field(min_length=1, max_length=64)
    safety_violation_codes: tuple[SafeCode, ...] = Field(default=(), max_length=64)
    canary_digest: Sha256Digest

    @model_validator(mode="after")
    def validate_canary(self) -> CanaryResult:
        if self.passed and self.safety_violation_codes:
            raise ValueError("passing canary cannot contain safety violations")
        if self.canary_digest != _digest(self.model_dump(exclude={"canary_digest"})):
            raise ValueError("canary digest does not match metadata")
        return self

    @classmethod
    def issue(cls, **values: object) -> CanaryResult:
        payload = dict(values)
        unsigned = cls.model_construct(_fields_set=set(payload), **payload)
        payload["canary_digest"] = _digest(unsigned.model_dump())
        return cls.model_validate(payload)


class ReleaseResult(RepairModel):
    previous_package_digest: Sha256Digest
    candidate_package_digest: Sha256Digest
    released: bool
    result_code: SafeCode
    release_digest: Sha256Digest

    @model_validator(mode="after")
    def validate_release(self) -> ReleaseResult:
        if self.release_digest != _digest(self.model_dump(exclude={"release_digest"})):
            raise ValueError("release digest does not match metadata")
        return self

    @classmethod
    def issue(cls, **values: object) -> ReleaseResult:
        payload = dict(values)
        unsigned = cls.model_construct(_fields_set=set(payload), **payload)
        payload["release_digest"] = _digest(unsigned.model_dump())
        return cls.model_validate(payload)


class RepairTransition(RepairModel):
    tenant_id: RepairIdentifier
    environment_id: RepairIdentifier
    job_id: RepairIdentifier
    request_digest: Sha256Digest
    subject_digest: Sha256Digest
    from_state: RepairName
    to_state: RepairName
    event_code: SafeCode
    previous_transition_digest: Sha256Digest | None = None
    occurred_at: datetime
    transition_digest: Sha256Digest

    @model_validator(mode="after")
    def validate_transition(self) -> RepairTransition:
        if self.occurred_at.tzinfo is None or self.occurred_at.utcoffset() is None:
            raise ValueError("repair transition time must include a timezone")
        if self.transition_digest != _digest(self.model_dump(exclude={"transition_digest"})):
            raise ValueError("transition digest does not match metadata")
        return self

    @classmethod
    def issue(cls, **values: object) -> RepairTransition:
        payload = dict(values)
        payload.setdefault("occurred_at", datetime.now(UTC))
        unsigned = cls.model_construct(_fields_set=set(payload), **payload)
        payload["transition_digest"] = _digest(unsigned.model_dump())
        return cls.model_validate(payload)


def _validate_json_path(path: str) -> None:
    if (
        _PATH_RE.fullmatch(path) is None
        or path.startswith("/")
        or path.startswith(".")
        or "\\" in path
        or "//" in path
        or any(part in {"", ".", ".."} for part in path.split("/"))
        or any(part.startswith(".") for part in path.split("/"))
        or any(part.endswith(".json") for part in path.split("/")[:-1])
        or path.endswith((".py", ".js", ".ts"))
    ):
        raise ValueError("repair path must be an allowlisted relative JSON file")


def _canonical(value: object) -> object:
    if isinstance(value, BaseModel):
        return _canonical(value.model_dump(mode="python"))
    if isinstance(value, Mapping):
        return {str(key): _canonical(item) for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        return [_canonical(item) for item in value]
    if isinstance(value, datetime):
        return value.astimezone(UTC).isoformat(timespec="microseconds")
    return value


def _digest(value: object) -> str:
    encoded = json.dumps(
        _canonical(value), ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


__all__ = [
    "MAX_REPAIR_METADATA_BYTES",
    "MAX_REPAIR_PATHS",
    "CanaryResult",
    "ReleaseResult",
    "RepairApproval",
    "RepairBudget",
    "RepairCandidate",
    "RepairIdentifier",
    "RepairModel",
    "RepairName",
    "RepairProposal",
    "RepairRequest",
    "RepairTransition",
    "RepairUsage",
    "SafeCode",
    "Sha256Digest",
    "ValidationReport",
]
