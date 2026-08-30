"""Private Runner task, lease, heartbeat, recovery, and receipt contracts."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Literal, Protocol

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    StringConstraints,
    field_validator,
    model_validator,
)

TASK_SCHEMA_VERSION: Literal["cargomesh.runner-task/v1"] = "cargomesh.runner-task/v1"
LEASE_SCHEMA_VERSION: Literal["cargomesh.runner-lease/v1"] = "cargomesh.runner-lease/v1"
HEARTBEAT_SCHEMA_VERSION: Literal["cargomesh.runner-heartbeat/v1"] = "cargomesh.runner-heartbeat/v1"
RECOVERY_SCHEMA_VERSION: Literal["cargomesh.runner-recovery/v1"] = "cargomesh.runner-recovery/v1"
RECEIPT_SCHEMA_VERSION: Literal["cargomesh.runner-result-receipt/v1"] = (
    "cargomesh.runner-result-receipt/v1"
)

RunnerIdentifier = Annotated[
    str, StringConstraints(strip_whitespace=True, min_length=1, max_length=256)
]
RunnerName = Annotated[
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
    r"(?:^|[._-])(?:authorization|cookie|credential|password|secret|token|api[_-]?key)"
    r"(?:$|[._-])",
    re.IGNORECASE,
)


class RunnerModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


def _canonical(value: object) -> object:
    if isinstance(value, BaseModel):
        return _canonical(value.model_dump(mode="python"))
    if isinstance(value, datetime):
        return value.astimezone(UTC).isoformat(timespec="microseconds")
    if isinstance(value, Mapping):
        return {str(key): _canonical(item) for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        return [_canonical(item) for item in value]
    return value


def model_digest(value: object, *, exclude: set[str]) -> str:
    payload: object
    if isinstance(value, BaseModel):
        payload = value.model_dump(mode="python", exclude=exclude)
    else:
        payload = value
    encoded = json.dumps(
        _canonical(payload), ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _utc(value: datetime, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must include a timezone")
    return value.astimezone(UTC)


def _digest(value: str, label: str) -> str:
    if _DIGEST_RE.fullmatch(value) is None:
        raise ValueError(f"{label} must be a lowercase sha256 digest")
    return value


def _reject_secret_keys(value: object, path: str = "payload") -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            key_text = str(key)
            if _SECRET_KEY_RE.search(key_text):
                raise ValueError(f"{path} contains a secret-like key")
            _reject_secret_keys(item, f"{path}.{key_text}")
    elif isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        for index, item in enumerate(value):
            _reject_secret_keys(item, f"{path}[{index}]")


class RunnerAuthorizer(Protocol):
    """Minimal registry boundary used when acquiring a task."""

    def authorize(
        self,
        runner_id: str,
        tenant_id: str,
        environment_id: str,
        runner_pool: str,
        capability: str,
    ) -> bool:
        """Return true only for an active runner with the exact scope/capability."""


class RecoveryAction(StrEnum):
    RETRY_FROM_CHECKPOINT = "RETRY_FROM_CHECKPOINT"
    VERIFY_OR_RECONCILE = "VERIFY_OR_RECONCILE"


class RunnerTask(RunnerModel):
    schema_version: Literal["cargomesh.runner-task/v1"] = TASK_SCHEMA_VERSION
    task_id: RunnerIdentifier
    tenant_id: RunnerIdentifier
    environment_id: RunnerIdentifier
    runner_pool: RunnerName
    capability: RunnerName
    execution_id: RunnerIdentifier
    adapter_digest: str
    policy_digest: str
    input_digest: str
    created_at: datetime
    deadline: datetime
    payload: dict[str, JsonValue] = Field(default_factory=dict, max_length=64)
    task_digest: str

    @field_validator("created_at", "deadline")
    @classmethod
    def validate_time(cls, value: datetime) -> datetime:
        return _utc(value, "task timestamps")

    @field_validator("adapter_digest", "policy_digest", "input_digest")
    @classmethod
    def validate_digests(cls, value: str, info: object) -> str:
        del info
        return _digest(value, "task digest")

    @model_validator(mode="after")
    def validate_task(self) -> RunnerTask:
        if self.deadline <= self.created_at:
            raise ValueError("task deadline must be after creation")
        _reject_secret_keys(self.payload)
        if self.task_digest != _digest(self.task_digest, "task digest"):
            raise ValueError("task digest is invalid")
        if self.task_digest != model_digest(self, exclude={"task_digest"}):
            raise ValueError("task digest does not match")
        return self

    @property
    def digest(self) -> str:
        return self.task_digest

    @classmethod
    def issue(cls, **values: object) -> RunnerTask:
        payload = dict(values)
        payload.setdefault("schema_version", TASK_SCHEMA_VERSION)
        unsigned = cls.model_construct(_fields_set=set(payload), **payload)
        payload["task_digest"] = model_digest(unsigned, exclude={"task_digest"})
        return cls.model_validate(payload)


class TaskLease(RunnerModel):
    schema_version: Literal["cargomesh.runner-lease/v1"] = LEASE_SCHEMA_VERSION
    task_id: RunnerIdentifier
    runner_id: RunnerIdentifier
    fencing_token: int = Field(ge=1, le=2**63 - 1)
    acquired_at: datetime
    lease_expires_at: datetime
    lease_digest: str

    @field_validator("acquired_at", "lease_expires_at")
    @classmethod
    def validate_time(cls, value: datetime) -> datetime:
        return _utc(value, "lease timestamps")

    @model_validator(mode="after")
    def validate_lease(self) -> TaskLease:
        if self.lease_expires_at <= self.acquired_at:
            raise ValueError("lease expiry must be after acquisition")
        if self.lease_digest != model_digest(self, exclude={"lease_digest"}):
            raise ValueError("lease digest does not match")
        return self

    @property
    def digest(self) -> str:
        return self.lease_digest

    @classmethod
    def issue(cls, **values: object) -> TaskLease:
        payload = dict(values)
        payload.setdefault("schema_version", LEASE_SCHEMA_VERSION)
        unsigned = cls.model_construct(_fields_set=set(payload), **payload)
        payload["lease_digest"] = model_digest(unsigned, exclude={"lease_digest"})
        return cls.model_validate(payload)


class RunnerHeartbeat(RunnerModel):
    schema_version: Literal["cargomesh.runner-heartbeat/v1"] = HEARTBEAT_SCHEMA_VERSION
    task_id: RunnerIdentifier
    runner_id: RunnerIdentifier
    fencing_token: int = Field(ge=1, le=2**63 - 1)
    step_id: RunnerName
    effect_boundary: bool | None = None
    checkpoint_digest: str | None = None
    artifact_upload_count: int = Field(default=0, ge=0, le=1_000_000)
    session_live: bool = True
    occurred_at: datetime
    heartbeat_digest: str

    @field_validator("occurred_at")
    @classmethod
    def validate_time(cls, value: datetime) -> datetime:
        return _utc(value, "heartbeat time")

    @field_validator("checkpoint_digest")
    @classmethod
    def validate_checkpoint(cls, value: str | None) -> str | None:
        return None if value is None else _digest(value, "checkpoint digest")

    @model_validator(mode="after")
    def validate_heartbeat(self) -> RunnerHeartbeat:
        if self.heartbeat_digest != model_digest(self, exclude={"heartbeat_digest"}):
            raise ValueError("heartbeat digest does not match")
        return self

    @classmethod
    def issue(cls, **values: object) -> RunnerHeartbeat:
        payload = dict(values)
        payload.setdefault("schema_version", HEARTBEAT_SCHEMA_VERSION)
        unsigned = cls.model_construct(_fields_set=set(payload), **payload)
        payload["heartbeat_digest"] = model_digest(unsigned, exclude={"heartbeat_digest"})
        return cls.model_validate(payload)


class RecoveryDirective(RunnerModel):
    schema_version: Literal["cargomesh.runner-recovery/v1"] = RECOVERY_SCHEMA_VERSION
    task_id: RunnerIdentifier
    action: RecoveryAction
    checkpoint_digest: str | None = None
    reason_code: RunnerName
    directive_digest: str

    @field_validator("checkpoint_digest")
    @classmethod
    def validate_checkpoint(cls, value: str | None) -> str | None:
        return None if value is None else _digest(value, "checkpoint digest")

    @model_validator(mode="after")
    def validate_directive(self) -> RecoveryDirective:
        if self.directive_digest != model_digest(self, exclude={"directive_digest"}):
            raise ValueError("recovery directive digest does not match")
        if self.action is RecoveryAction.RETRY_FROM_CHECKPOINT and self.checkpoint_digest is None:
            raise ValueError("checkpoint retry requires a checkpoint digest")
        return self

    @classmethod
    def issue(cls, **values: object) -> RecoveryDirective:
        payload = dict(values)
        payload.setdefault("schema_version", RECOVERY_SCHEMA_VERSION)
        unsigned = cls.model_construct(_fields_set=set(payload), **payload)
        payload["directive_digest"] = model_digest(unsigned, exclude={"directive_digest"})
        return cls.model_validate(payload)


class RunnerResultReceipt(RunnerModel):
    schema_version: Literal["cargomesh.runner-result-receipt/v1"] = RECEIPT_SCHEMA_VERSION
    task_id: RunnerIdentifier
    runner_id: RunnerIdentifier
    fencing_token: int = Field(ge=1, le=2**63 - 1)
    result_digest: str
    completed_at: datetime
    effect_boundary: bool | None = None
    receipt_digest: str

    @field_validator("completed_at")
    @classmethod
    def validate_time(cls, value: datetime) -> datetime:
        return _utc(value, "receipt time")

    @field_validator("result_digest")
    @classmethod
    def validate_result_digest(cls, value: str) -> str:
        return _digest(value, "result digest")

    @model_validator(mode="after")
    def validate_receipt(self) -> RunnerResultReceipt:
        if self.receipt_digest != model_digest(self, exclude={"receipt_digest"}):
            raise ValueError("result receipt digest does not match")
        return self

    @classmethod
    def issue(cls, **values: object) -> RunnerResultReceipt:
        payload = dict(values)
        payload.setdefault("schema_version", RECEIPT_SCHEMA_VERSION)
        unsigned = cls.model_construct(_fields_set=set(payload), **payload)
        payload["receipt_digest"] = model_digest(unsigned, exclude={"receipt_digest"})
        return cls.model_validate(payload)


__all__ = [
    "HEARTBEAT_SCHEMA_VERSION",
    "LEASE_SCHEMA_VERSION",
    "RECEIPT_SCHEMA_VERSION",
    "RECOVERY_SCHEMA_VERSION",
    "TASK_SCHEMA_VERSION",
    "RecoveryAction",
    "RecoveryDirective",
    "RunnerAuthorizer",
    "RunnerHeartbeat",
    "RunnerIdentifier",
    "RunnerResultReceipt",
    "RunnerTask",
    "TaskLease",
    "model_digest",
]
