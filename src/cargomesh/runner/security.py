"""Immutable sandbox, egress and browser-session contracts for Private Runners."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, cast

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

Identifier = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=256)]
Name = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=128,
        pattern=r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$",
    ),
]
Digest = Annotated[str, StringConstraints(pattern=r"^sha256:[0-9a-f]{64}$")]


class SecurityModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class IsolationClass(StrEnum):
    PROCESS = "PROCESS"
    CONTAINER = "CONTAINER"
    VM = "VM"


class WorkloadClass(StrEnum):
    API_READ = "API_READ"
    BROWSER_READ = "BROWSER_READ"
    EFFECTFUL_WRITE = "EFFECTFUL_WRITE"
    AI_REPAIR = "AI_REPAIR"


class EgressRule(SecurityModel):
    host: Annotated[
        str,
        StringConstraints(
            strip_whitespace=True,
            min_length=1,
            max_length=253,
            pattern=(
                r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\."
                r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$"
            ),
        ),
    ]
    port: int = Field(ge=1, le=65535)

    @model_validator(mode="after")
    def reject_ambiguous_host(self) -> EgressRule:
        if self.host in {"localhost", "metadata", "metadata.google.internal"}:
            raise ValueError("egress host is reserved")
        return self


class ResourceLimits(SecurityModel):
    cpu_millis: int = Field(ge=100, le=128_000)
    memory_mebibytes: int = Field(ge=64, le=1_048_576)
    disk_mebibytes: int = Field(ge=64, le=10_485_760)
    process_count: int = Field(ge=1, le=4096)
    deadline_seconds: int = Field(ge=1, le=604_800)
    maximum_artifact_bytes: int = Field(ge=1, le=100 * 1024 * 1024)


class SandboxSpec(SecurityModel):
    sandbox_id: Name
    workload_class: WorkloadClass
    isolation: IsolationClass
    limits: ResourceLimits
    egress: tuple[EgressRule, ...] = Field(default=(), max_length=64)
    read_only_root: bool = True
    writable_workdir: bool = True
    docker_socket_allowed: bool = False
    host_home_mounted: bool = False
    production_pool: bool = False
    repair_zone: bool = False
    spec_digest: Digest

    @model_validator(mode="after")
    def validate_sandbox(self) -> SandboxSpec:
        if not self.read_only_root or not self.writable_workdir:
            raise ValueError("sandbox filesystem controls are mandatory")
        if self.docker_socket_allowed or self.host_home_mounted:
            raise ValueError("host-control mounts are forbidden")
        identities = tuple((rule.host, rule.port) for rule in self.egress)
        if len(identities) != len(set(identities)):
            raise ValueError("egress rules must be unique")
        if self.workload_class is WorkloadClass.EFFECTFUL_WRITE and (
            self.isolation is IsolationClass.PROCESS or not self.egress
        ):
            raise ValueError("effectful writes require isolated, restricted egress")
        if self.workload_class is WorkloadClass.AI_REPAIR and (
            self.production_pool
            or not self.repair_zone
            or self.isolation is not IsolationClass.VM
        ):
            raise ValueError("AI repair requires a separate non-production VM zone")
        if self.workload_class is not WorkloadClass.AI_REPAIR and self.repair_zone:
            raise ValueError("repair zones are reserved for AI repair")
        if self.spec_digest != _digest(self.model_dump(exclude={"spec_digest"})):
            raise ValueError("sandbox specification digest does not match")
        return self

    @classmethod
    def issue(cls, **values: object) -> SandboxSpec:
        return cast(SandboxSpec, _issue(cls, values, "spec_digest"))


class BrowserSessionKind(StrEnum):
    EPHEMERAL = "EPHEMERAL"
    SEALED_STORAGE_STATE = "SEALED_STORAGE_STATE"
    ATTENDED = "ATTENDED"


class BrowserSessionLease(SecurityModel):
    lease_id: Name
    tenant_id: Identifier
    environment_id: Identifier
    runner_id: Identifier
    task_id: Identifier
    kind: BrowserSessionKind
    profile_ref: Name | None = None
    account_identity_digest: Digest | None = None
    expires_at: datetime
    lease_digest: Digest

    @model_validator(mode="after")
    def validate_lease(self) -> BrowserSessionLease:
        if self.expires_at.tzinfo is None or self.expires_at.utcoffset() is None:
            raise ValueError("session expiry must include a timezone")
        if self.kind is BrowserSessionKind.EPHEMERAL:
            if self.profile_ref is not None:
                raise ValueError("ephemeral sessions cannot reference stored profiles")
        elif self.profile_ref is None or self.account_identity_digest is None:
            raise ValueError("persistent or attended sessions require scoped profile identity")
        if self.profile_ref is not None and re.search(
            r"(?:password|secret|token|cookie|credential)", self.profile_ref, re.IGNORECASE
        ):
            raise ValueError("session profile reference is invalid")
        if self.lease_digest != _digest(self.model_dump(exclude={"lease_digest"})):
            raise ValueError("session lease digest does not match")
        return self

    @classmethod
    def issue(cls, **values: object) -> BrowserSessionLease:
        return cast(BrowserSessionLease, _issue(cls, values, "lease_digest"))


def _issue(model_type: type[BaseModel], values: Mapping[str, object], field: str) -> BaseModel:
    payload = dict(values)
    unsigned = model_type.model_construct(_fields_set=set(payload), **payload)
    payload[field] = _digest(unsigned.model_dump(exclude={field}))
    return model_type.model_validate(payload)


def _digest(value: object) -> str:
    def canonical(item: object) -> object:
        if isinstance(item, datetime):
            return item.astimezone(UTC).isoformat(timespec="microseconds")
        if isinstance(item, StrEnum):
            return item.value
        if isinstance(item, Mapping):
            return {str(key): canonical(inner) for key, inner in item.items()}
        if isinstance(item, (tuple, list)):
            return [canonical(inner) for inner in item]
        return item

    payload = json.dumps(
        canonical(value), ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode()
    return "sha256:" + hashlib.sha256(payload).hexdigest()
