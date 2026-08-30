from __future__ import annotations

import pytest
from pydantic import ValidationError

from cargomesh.credentials.models import SecretRef
from cargomesh.platform.deployment import LocalDeploymentProfile, PrivateDeploymentProfile
from cargomesh.runner.release import DeploymentProfile, DeploymentProfileName


def digest(char: str) -> str:
    return "sha256:" + char * 64


def private_values() -> dict[str, object]:
    return {
        "deployment_id": "private-1",
        "tenant_id": "tenant-a",
        "environment_id": "prod",
        "artifact_digest": digest("a"),
        "artifact_store": "artifact://internal",
        "database_endpoint": "postgres://internal-db",
        "tls_mode": "mTLS",
        "ingress_policy": ("api.only",),
        "egress_policy": ("carrier.allow",),
        "runner_pool": "private.runners",
        "runner_profile": DeploymentProfile(
            name=DeploymentProfileName.STANDARD,
            isolation="container",
            external_secret_provider_required=True,
            mtls_required=True,
            customer_local_evidence=False,
            dual_approval_required=False,
            production_capable=True,
        ),
        "identity_secret_provider": "vault",
        "identity_secret_ref": SecretRef(provider="vault", key="identity-ref"),
    }


def test_local_profile_is_explicitly_non_production_and_digest_bound() -> None:
    profile = LocalDeploymentProfile.issue(
        deployment_id="local-1",
        tenant_id="tenant-a",
        environment_id="dev",
        artifact_digest=digest("a"),
        database_path="state/cargomesh.sqlite3",
        secret_refs=(SecretRef(provider="memory", key="local-ref"),),
    )
    assert not profile.production_ready
    assert not profile.resources_created
    assert profile.profile_digest.startswith("sha256:")
    values = profile.model_dump()
    values["database_path"] = "other.sqlite3"
    with pytest.raises(ValidationError):
        LocalDeploymentProfile.model_validate(values)


def test_local_path_and_inline_secret_are_rejected() -> None:
    with pytest.raises(ValidationError):
        LocalDeploymentProfile.issue(
            deployment_id="local-1",
            tenant_id="tenant-a",
            environment_id="dev",
            artifact_digest=digest("a"),
            database_path="C:\\secret.sqlite3",
        )
    with pytest.raises(ValueError):
        SecretRef(provider="memory", key="inline-secret-value")


def test_private_profile_requires_strict_controls_and_matching_secret_provider() -> None:
    profile = PrivateDeploymentProfile.issue(**private_values())
    assert profile.configuration_complete
    assert not profile.production_ready
    assert not profile.resources_created
    assert profile.identity_secret_ref.provider == "vault"

    values = private_values()
    values["tls_mode"] = "TLS"
    with pytest.raises(ValidationError):
        PrivateDeploymentProfile.issue(**values)

    values = private_values()
    values["identity_secret_provider"] = "other-vault"
    with pytest.raises(ValidationError):
        PrivateDeploymentProfile.issue(**values)


def test_private_profile_rejects_secret_like_resource_references() -> None:
    values = private_values()
    values["database_endpoint"] = "postgres://user:password@db"
    with pytest.raises(ValidationError):
        PrivateDeploymentProfile.issue(**values)


def test_private_profile_reuses_and_enforces_runner_deployment_contract() -> None:
    values = private_values()
    values["runner_profile"] = DeploymentProfile(
        name=DeploymentProfileName.DEVELOPER,
        isolation="local.process",
        external_secret_provider_required=False,
        mtls_required=False,
        customer_local_evidence=False,
        dual_approval_required=False,
    )
    with pytest.raises(ValidationError, match="production-capable runner"):
        PrivateDeploymentProfile.issue(**values)
