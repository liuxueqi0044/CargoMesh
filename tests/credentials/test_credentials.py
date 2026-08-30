from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest

from cargomesh.credentials import (
    CredentialBinding,
    CredentialBindingConflict,
    CredentialBindingNotFound,
    EnvironmentSecretProvider,
    InMemorySecretProvider,
    ResolveContext,
    SecretLease,
    SecretLeaseClosed,
    SecretLeaseExpired,
    SecretProviderError,
    SecretRef,
    SQLiteCredentialBindingStore,
)


def context(tenant: str = "tenant-a", environment: str = "prod") -> ResolveContext:
    return ResolveContext(
        tenant_id=tenant, environment_id=environment, adapter="carrier", capability="read"
    )


def reference(key: str = "carrier") -> SecretRef:
    return SecretRef(provider="env", key=key)


def binding(
    tenant: str = "tenant-a", environment: str = "prod", revision: int = 1
) -> CredentialBinding:
    return CredentialBinding.issue(
        tenant_id=tenant,
        environment_id=environment,
        adapter="carrier",
        capability="read",
        secrets={"account": reference()},
        revision=revision,
    )


@pytest.mark.parametrize(
    "key", ["../secret", "/tmp/x", "C:\\secret", "a/b", "a=b", "password", "api_token"]
)
def test_secret_ref_rejects_paths_inline_values_and_secret_names(key: str) -> None:
    with pytest.raises(ValueError):
        reference(key)


def test_environment_provider_is_allowlist_only(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CARGOMESH_CARRIER", "opaque-value")
    provider = EnvironmentSecretProvider({"carrier": "CARGOMESH_CARRIER"})
    with provider.resolve(reference(), context()) as lease:
        assert lease.value == b"opaque-value"
    with pytest.raises(SecretProviderError) as exc:
        provider.resolve(SecretRef(provider="env", key="other"), context())
    assert exc.value.code == "secret_not_allowlisted"


def test_lease_expires_and_closes_on_exception() -> None:
    now = datetime.now(UTC)
    clock_value = [now]
    lease = SecretLease(b"secret", now + timedelta(seconds=1), clock=lambda: clock_value[0])
    with pytest.raises(RuntimeError), lease:
        assert lease.value == b"secret"
        raise RuntimeError("failure")
    assert lease.closed
    with pytest.raises(SecretLeaseClosed):
        _ = lease.value

    second = SecretLease(b"secret", now + timedelta(seconds=1), clock=lambda: clock_value[0])
    clock_value[0] = now + timedelta(seconds=1)
    with pytest.raises(SecretLeaseExpired):
        _ = second.value
    assert second.closed


def test_lease_wipes_mutable_buffers() -> None:
    lease = SecretLease(b"secret", datetime.now(UTC) + timedelta(seconds=10))
    buffer = next(iter(lease._buffers.values()))
    lease.close()
    assert bytes(buffer) == b"\x00" * len(buffer)


def test_in_memory_provider_is_ephemeral() -> None:
    provider = InMemorySecretProvider({"carrier": "secret"})
    lease = provider.resolve(SecretRef(provider="memory", key="carrier"), context())
    with lease as value:
        assert value.value == b"secret"
    with pytest.raises(SecretLeaseClosed):
        _ = lease.value


def test_binding_store_replay_conflict_revision_and_isolation() -> None:
    with SQLiteCredentialBindingStore() as store:
        first = binding()
        assert store.put(first) == first
        assert store.put(first) == first
        with pytest.raises(CredentialBindingConflict):
            store.put(CredentialBinding.issue(
                tenant_id=first.tenant_id,
                environment_id=first.environment_id,
                adapter=first.adapter,
                capability=first.capability,
                secrets={"other": SecretRef(provider="env", key="carrier2")},
                revision=1,
            ))
        replacement = CredentialBinding.issue(
            tenant_id=first.tenant_id,
            environment_id=first.environment_id,
            adapter=first.adapter,
            capability=first.capability,
            secrets={"account": SecretRef(provider="env", key="carrier2")},
            revision=2,
        )
        assert store.replace(replacement).revision == 2
        with pytest.raises(CredentialBindingConflict):
            store.replace(replacement)
        assert store.get("tenant-a", "other", "carrier", "read") is None
        assert store.get("tenant-a", "prod", "carrier", "read") == replacement
        with pytest.raises(CredentialBindingNotFound):
            store.replace(binding("missing"))


def test_binding_store_detects_tamper_and_stores_no_resolved_secret() -> None:
    with SQLiteCredentialBindingStore() as store:
        value = binding()
        store.put(value)
        row = store._connection.execute(
            "SELECT binding_json FROM credential_bindings"
        ).fetchone()
        assert "opaque-value" not in row["binding_json"]
        store._connection.execute(
            "UPDATE credential_bindings SET binding_json=?",
            (json.dumps({"bad": "data"}),),
        )
        with pytest.raises(Exception) as exc:
            store.get("tenant-a", "prod", "carrier", "read")
        assert "opaque-value" not in str(exc.value)
