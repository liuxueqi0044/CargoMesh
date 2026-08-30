"""Deterministic runner compatibility, upgrade and deployment declarations."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from enum import StrEnum
from typing import Annotated, cast

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

SemVer = Annotated[
    str,
    StringConstraints(
        max_length=32,
        pattern=r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$"
    ),
]
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


class ReleaseModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class Compatibility(StrEnum):
    COMPATIBLE = "COMPATIBLE"
    RUNNER_TOO_OLD = "RUNNER_TOO_OLD"
    RUNNER_TOO_NEW = "RUNNER_TOO_NEW"
    SDK_UNSUPPORTED = "SDK_UNSUPPORTED"


class UpgradeState(StrEnum):
    READY = "READY"
    UPDATE_AVAILABLE = "UPDATE_AVAILABLE"
    DRAINING = "DRAINING"
    CANARY = "CANARY"
    INSTALLING = "INSTALLING"
    SELF_TEST = "SELF_TEST"
    ROLLBACK = "ROLLBACK"
    BLOCKED = "BLOCKED"


class RunnerRelease(ReleaseModel):
    version: SemVer
    sdk_minimum: SemVer
    sdk_maximum: SemVer
    package_digest: Digest
    signature_identity_digest: Digest
    release_channel: Name = "stable"
    release_digest: Digest

    @model_validator(mode="after")
    def validate_release(self) -> RunnerRelease:
        if _semver(self.sdk_minimum) > _semver(self.sdk_maximum):
            raise ValueError("runner SDK range is invalid")
        if self.release_digest != _digest(self.model_dump(exclude={"release_digest"})):
            raise ValueError("runner release digest does not match")
        return self

    @classmethod
    def issue(cls, **values: object) -> RunnerRelease:
        return cast(RunnerRelease, _issue(cls, values, "release_digest"))


class RunnerVersionPolicy(ReleaseModel):
    policy_id: Name
    minimum_runner_version: SemVer
    maximum_runner_version: SemVer
    supported_sdk_minimum: SemVer
    supported_sdk_maximum: SemVer
    allowed_channels: tuple[Name, ...] = ("stable",)
    canary_pools: tuple[Name, ...] = ()
    policy_digest: Digest

    @model_validator(mode="after")
    def validate_policy(self) -> RunnerVersionPolicy:
        if _semver(self.minimum_runner_version) > _semver(self.maximum_runner_version):
            raise ValueError("runner version range is invalid")
        if _semver(self.supported_sdk_minimum) > _semver(self.supported_sdk_maximum):
            raise ValueError("supported SDK range is invalid")
        if not self.allowed_channels or len(self.allowed_channels) != len(
            set(self.allowed_channels)
        ):
            raise ValueError("allowed release channels must be non-empty and unique")
        if len(self.canary_pools) != len(set(self.canary_pools)):
            raise ValueError("canary pools must be unique")
        if self.policy_digest != _digest(self.model_dump(exclude={"policy_digest"})):
            raise ValueError("runner version policy digest does not match")
        return self

    @classmethod
    def issue(cls, **values: object) -> RunnerVersionPolicy:
        return cast(RunnerVersionPolicy, _issue(cls, values, "policy_digest"))


def evaluate_compatibility(
    runner_version: str, adapter_sdk_version: str, policy: RunnerVersionPolicy
) -> Compatibility:
    runner = _semver(runner_version)
    sdk = _semver(adapter_sdk_version)
    if runner < _semver(policy.minimum_runner_version):
        return Compatibility.RUNNER_TOO_OLD
    if runner > _semver(policy.maximum_runner_version):
        return Compatibility.RUNNER_TOO_NEW
    if not _semver(policy.supported_sdk_minimum) <= sdk <= _semver(
        policy.supported_sdk_maximum
    ):
        return Compatibility.SDK_UNSUPPORTED
    return Compatibility.COMPATIBLE


def upgrade_state(
    *,
    current_version: str,
    target: RunnerRelease,
    policy: RunnerVersionPolicy,
    runner_pool: str,
    active_tasks: int,
    self_test_passed: bool | None = None,
) -> UpgradeState:
    if target.release_channel not in policy.allowed_channels:
        return UpgradeState.BLOCKED
    target_version = _semver(target.version)
    if not (
        _semver(policy.minimum_runner_version)
        <= target_version
        <= _semver(policy.maximum_runner_version)
    ):
        return UpgradeState.BLOCKED
    if _semver(target.sdk_minimum) > _semver(
        policy.supported_sdk_maximum
    ) or _semver(target.sdk_maximum) < _semver(policy.supported_sdk_minimum):
        return UpgradeState.BLOCKED
    if _semver(current_version) >= target_version:
        return UpgradeState.READY
    if active_tasks > 0:
        return UpgradeState.DRAINING
    if self_test_passed is False:
        return UpgradeState.ROLLBACK
    if self_test_passed is True:
        return UpgradeState.READY
    if runner_pool in policy.canary_pools:
        return UpgradeState.CANARY
    return UpgradeState.UPDATE_AVAILABLE


class DeploymentProfileName(StrEnum):
    DEVELOPER = "developer"
    STANDARD = "standard"
    REGULATED = "regulated"


class DeploymentProfile(ReleaseModel):
    name: DeploymentProfileName
    isolation: Name
    external_secret_provider_required: bool
    mtls_required: bool
    customer_local_evidence: bool
    dual_approval_required: bool
    unmet_controls: tuple[Name, ...] = Field(default=(), max_length=32)
    production_capable: bool = False

    @model_validator(mode="after")
    def validate_profile(self) -> DeploymentProfile:
        if len(self.unmet_controls) != len(set(self.unmet_controls)):
            raise ValueError("unmet controls must be unique")
        if self.name is DeploymentProfileName.DEVELOPER and self.production_capable:
            raise ValueError("developer profile cannot be production capable")
        if self.production_capable and self.unmet_controls:
            raise ValueError("profiles with unmet controls are not production capable")
        if self.name is not DeploymentProfileName.DEVELOPER and (
            not self.external_secret_provider_required or not self.mtls_required
        ):
            raise ValueError("non-developer profiles require external secrets and mTLS")
        return self


def default_deployment_profiles() -> tuple[DeploymentProfile, ...]:
    return (
        DeploymentProfile(
            name=DeploymentProfileName.DEVELOPER,
            isolation="local.process",
            external_secret_provider_required=False,
            mtls_required=False,
            customer_local_evidence=False,
            dual_approval_required=False,
            unmet_controls=("mtls", "container.isolation", "external.secrets"),
        ),
        DeploymentProfile(
            name=DeploymentProfileName.STANDARD,
            isolation="container",
            external_secret_provider_required=True,
            mtls_required=True,
            customer_local_evidence=False,
            dual_approval_required=False,
            unmet_controls=("deployment.supplied",),
        ),
        DeploymentProfile(
            name=DeploymentProfileName.REGULATED,
            isolation="dedicated.vm",
            external_secret_provider_required=True,
            mtls_required=True,
            customer_local_evidence=True,
            dual_approval_required=True,
            unmet_controls=("customer.infrastructure.supplied",),
        ),
    )


def _issue(model_type: type[BaseModel], values: Mapping[str, object], field: str) -> BaseModel:
    payload = dict(values)
    unsigned = model_type.model_construct(_fields_set=set(payload), **payload)
    payload[field] = _digest(unsigned.model_dump(exclude={field}))
    return model_type.model_validate(payload)


def _semver(value: str) -> tuple[int, int, int]:
    match = re_full_semver(value)
    if match is None:
        raise ValueError("invalid semantic version")
    return tuple(int(part) for part in match)  # type: ignore[return-value]


def re_full_semver(value: str) -> tuple[str, str, str] | None:
    parts = value.split(".")
    if len(parts) != 3 or any(not part.isdigit() for part in parts):
        return None
    if any(len(part) > 1 and part.startswith("0") for part in parts):
        return None
    return cast(tuple[str, str, str], tuple(parts))


def _digest(value: object) -> str:
    def canonical(item: object) -> object:
        if isinstance(item, StrEnum):
            return item.value
        if isinstance(item, Mapping):
            return {str(key): canonical(inner) for key, inner in item.items()}
        if isinstance(item, (tuple, list)):
            return [canonical(inner) for inner in item]
        return item

    encoded = json.dumps(
        canonical(value), ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode()
    return "sha256:" + hashlib.sha256(encoded).hexdigest()
