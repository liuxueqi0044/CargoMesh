from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from cargomesh.runner.release import (
    Compatibility,
    DeploymentProfileName,
    RunnerRelease,
    RunnerVersionPolicy,
    UpgradeState,
    default_deployment_profiles,
    evaluate_compatibility,
    upgrade_state,
)
from cargomesh.runner.security import (
    BrowserSessionKind,
    BrowserSessionLease,
    EgressRule,
    IsolationClass,
    ResourceLimits,
    SandboxSpec,
    WorkloadClass,
)

NOW = datetime(2040, 1, 2, tzinfo=UTC)
DIGEST = "sha256:" + "a" * 64


def limits() -> ResourceLimits:
    return ResourceLimits(
        cpu_millis=1000,
        memory_mebibytes=512,
        disk_mebibytes=1024,
        process_count=32,
        deadline_seconds=300,
        maximum_artifact_bytes=1024,
    )


def test_effectful_sandbox_requires_isolation_and_exact_egress() -> None:
    spec = SandboxSpec.issue(
        sandbox_id="booking-write",
        workload_class=WorkloadClass.EFFECTFUL_WRITE,
        isolation=IsolationClass.CONTAINER,
        limits=limits(),
        egress=(EgressRule(host="carrier.example", port=443),),
        production_pool=True,
    )
    assert spec.read_only_root
    assert not spec.docker_socket_allowed

    with pytest.raises(ValueError, match="effectful"):
        SandboxSpec.issue(
            sandbox_id="unsafe-write",
            workload_class=WorkloadClass.EFFECTFUL_WRITE,
            isolation=IsolationClass.PROCESS,
            limits=limits(),
        )


def test_ai_repair_is_separate_from_production() -> None:
    SandboxSpec.issue(
        sandbox_id="repair",
        workload_class=WorkloadClass.AI_REPAIR,
        isolation=IsolationClass.VM,
        limits=limits(),
        repair_zone=True,
    )
    with pytest.raises(ValueError, match="AI repair"):
        SandboxSpec.issue(
            sandbox_id="repair-prod",
            workload_class=WorkloadClass.AI_REPAIR,
            isolation=IsolationClass.VM,
            limits=limits(),
            repair_zone=True,
            production_pool=True,
        )


def test_browser_profiles_are_opaque_and_scope_bound() -> None:
    lease = BrowserSessionLease.issue(
        lease_id="session-1",
        tenant_id="tenant-a",
        environment_id="production",
        runner_id="runner-1",
        task_id="task-1",
        kind=BrowserSessionKind.SEALED_STORAGE_STATE,
        profile_ref="profile-17",
        account_identity_digest=DIGEST,
        expires_at=NOW + timedelta(minutes=10),
    )
    assert "profile-17" in lease.model_dump_json()

    with pytest.raises(ValueError, match="cannot reference"):
        BrowserSessionLease.issue(
            lease_id="session-2",
            tenant_id="tenant-a",
            environment_id="production",
            runner_id="runner-1",
            task_id="task-1",
            kind=BrowserSessionKind.EPHEMERAL,
            profile_ref="profile-17",
            expires_at=NOW + timedelta(minutes=10),
        )


def release() -> RunnerRelease:
    return RunnerRelease.issue(
        version="1.2.0",
        sdk_minimum="1.0.0",
        sdk_maximum="1.9.0",
        package_digest=DIGEST,
        signature_identity_digest="sha256:" + "b" * 64,
    )


def version_policy() -> RunnerVersionPolicy:
    return RunnerVersionPolicy.issue(
        policy_id="runner-stable",
        minimum_runner_version="1.0.0",
        maximum_runner_version="1.9.0",
        supported_sdk_minimum="1.0.0",
        supported_sdk_maximum="1.9.0",
        canary_pools=("canary",),
    )


def test_version_compatibility_and_upgrade_states() -> None:
    policy = version_policy()
    assert evaluate_compatibility("1.1.0", "1.5.0", policy) is Compatibility.COMPATIBLE
    assert evaluate_compatibility("0.9.0", "1.5.0", policy) is Compatibility.RUNNER_TOO_OLD
    assert evaluate_compatibility("1.1.0", "2.0.0", policy) is Compatibility.SDK_UNSUPPORTED
    assert (
        upgrade_state(
            current_version="1.1.0",
            target=release(),
            policy=policy,
            runner_pool="default",
            active_tasks=1,
        )
        is UpgradeState.DRAINING
    )
    assert (
        upgrade_state(
            current_version="1.1.0",
            target=release(),
            policy=policy,
            runner_pool="canary",
            active_tasks=0,
        )
        is UpgradeState.CANARY
    )
    assert (
        upgrade_state(
            current_version="1.1.0",
            target=release(),
            policy=policy,
            runner_pool="default",
            active_tasks=0,
            self_test_passed=False,
        )
        is UpgradeState.ROLLBACK
    )


def test_deployment_profiles_never_overclaim_external_controls() -> None:
    profiles = default_deployment_profiles()
    assert tuple(profile.name for profile in profiles) == (
        DeploymentProfileName.DEVELOPER,
        DeploymentProfileName.STANDARD,
        DeploymentProfileName.REGULATED,
    )
    assert all(not profile.production_capable for profile in profiles)
    assert all(profile.unmet_controls for profile in profiles)
