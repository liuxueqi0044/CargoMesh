"""Digest-bound, metadata-only local and private deployment profiles."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from cargomesh.credentials.models import SecretRef
from cargomesh.runner.release import (
    DeploymentProfile as RunnerDeploymentProfile,
)
from cargomesh.runner.release import (
    DeploymentProfileName,
    default_deployment_profiles,
)

Sha256Digest = Annotated[str, StringConstraints(pattern=r"^sha256:[0-9a-f]{64}$")]
Identifier = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=256,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:+/@-]{0,255}$",
    ),
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

_REFERENCE_SECRET_RE = re.compile(
    r"(?:password|secret|token|credential|authorization|api[_-]?key)", re.IGNORECASE
)


class DeploymentModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class DeploymentError(ValueError):
    """Bounded deployment-profile failure."""

    def __init__(self, code: str, message: str = "Deployment profile is invalid") -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class DeploymentKind(StrEnum):
    LOCAL = "local"
    PRIVATE = "private"


class LocalDeploymentProfile(DeploymentModel):
    kind: Literal[DeploymentKind.LOCAL] = DeploymentKind.LOCAL
    deployment_id: Identifier
    tenant_id: Identifier
    environment_id: Identifier
    artifact_digest: Sha256Digest
    database_path: str = Field(min_length=1, max_length=512)
    runner_profile: RunnerDeploymentProfile = Field(
        default_factory=lambda: default_deployment_profiles()[0]
    )
    secret_refs: tuple[SecretRef, ...] = Field(default=(), max_length=32)
    production_ready: Literal[False] = False
    resources_created: Literal[False] = False
    profile_digest: Sha256Digest

    @model_validator(mode="after")
    def validate_profile(self) -> LocalDeploymentProfile:
        _validate_local_path(self.database_path)
        if (
            self.runner_profile.name is not DeploymentProfileName.DEVELOPER
            or self.runner_profile.production_capable
        ):
            raise ValueError("local deployment requires the non-production runner profile")
        if self.profile_digest != _digest(self.model_dump(exclude={"profile_digest"})):
            raise ValueError("deployment profile digest does not match")
        return self

    @classmethod
    def issue(cls, **values: object) -> LocalDeploymentProfile:
        payload = dict(values)
        unsigned = cls.model_construct(_fields_set=set(payload), **payload)
        payload["profile_digest"] = _digest(unsigned.model_dump())
        return cls.model_validate(payload)


class PrivateDeploymentProfile(DeploymentModel):
    kind: Literal[DeploymentKind.PRIVATE] = DeploymentKind.PRIVATE
    deployment_id: Identifier
    tenant_id: Identifier
    environment_id: Identifier
    artifact_digest: Sha256Digest
    artifact_store: Identifier
    database_endpoint: Identifier
    tls_mode: Literal["mTLS"]
    ingress_policy: tuple[PolicyName, ...] = Field(min_length=1, max_length=32)
    egress_policy: tuple[PolicyName, ...] = Field(min_length=1, max_length=32)
    runner_pool: Identifier
    runner_profile: RunnerDeploymentProfile
    identity_secret_provider: Identifier
    identity_secret_ref: SecretRef
    configuration_complete: Literal[True] = True
    production_ready: Literal[False] = False
    resources_created: Literal[False] = False
    profile_digest: Sha256Digest

    @model_validator(mode="after")
    def validate_profile(self) -> PrivateDeploymentProfile:
        if self.identity_secret_ref.provider != self.identity_secret_provider:
            raise ValueError("identity secret provider does not match reference")
        if (
            self.runner_profile.name is DeploymentProfileName.DEVELOPER
            or not self.runner_profile.external_secret_provider_required
            or not self.runner_profile.mtls_required
            or not self.runner_profile.production_capable
        ):
            raise ValueError("private deployment requires a production-capable runner profile")
        if len(self.ingress_policy) != len(set(self.ingress_policy)):
            raise ValueError("ingress policy entries must be unique")
        if len(self.egress_policy) != len(set(self.egress_policy)):
            raise ValueError("egress policy entries must be unique")
        for reference in (self.artifact_store, self.database_endpoint):
            _validate_reference(reference)
        if self.profile_digest != _digest(self.model_dump(exclude={"profile_digest"})):
            raise ValueError("deployment profile digest does not match")
        return self

    @classmethod
    def issue(cls, **values: object) -> PrivateDeploymentProfile:
        payload = dict(values)
        unsigned = cls.model_construct(_fields_set=set(payload), **payload)
        payload["profile_digest"] = _digest(unsigned.model_dump())
        return cls.model_validate(payload)


DeploymentProfile = LocalDeploymentProfile | PrivateDeploymentProfile


def _validate_local_path(value: str) -> None:
    if (
        "\\" in value
        or "\x00" in value
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]*", value)
        or value.startswith("/")
        or "//" in value
        or any(part in {"", ".", ".."} for part in value.split("/"))
    ):
        raise ValueError("local database path must be an explicit local file")


def _validate_reference(value: str) -> None:
    if (
        "\x00" in value
        or any(character.isspace() for character in value)
        or "@" in value
        or _REFERENCE_SECRET_RE.search(value) is not None
    ):
        raise ValueError("deployment reference is invalid")


def _canonical(value: object) -> object:
    if isinstance(value, BaseModel):
        return _canonical(value.model_dump(mode="python"))
    if isinstance(value, Mapping):
        return {str(key): _canonical(item) for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        return [_canonical(item) for item in value]
    return value


def _digest(value: object) -> str:
    payload = json.dumps(
        _canonical(value), ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


__all__ = [
    "DeploymentError",
    "DeploymentKind",
    "DeploymentModel",
    "DeploymentProfile",
    "Identifier",
    "LocalDeploymentProfile",
    "PolicyName",
    "PrivateDeploymentProfile",
    "RunnerDeploymentProfile",
    "Sha256Digest",
]
