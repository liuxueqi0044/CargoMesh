from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import pytest
from temporalio.exceptions import ApplicationError

from cargomesh.credentials import (
    CredentialBinding,
    InMemorySecretProvider,
    ResolveContext,
    SecretLease,
    SecretProvider,
    SecretProviderError,
    SecretRef,
    SQLiteCredentialBindingStore,
)
from cargomesh.runtime.adapters import (
    AdapterActivities,
    AdapterRegistry,
    CredentialAwareAdapterExecutor,
    CredentialLeaseSet,
)
from cargomesh.runtime.models import AdapterInvocation, AdapterResult

SECRET = b"integration-only-secret"


def _ref(key: str = "carrier-handle") -> SecretRef:
    return SecretRef(provider="memory", key=key)


def _binding(
    *,
    tenant: str = "tenant-a",
    environment: str = "production",
    refs: dict[str, SecretRef] | None = None,
) -> CredentialBinding:
    return CredentialBinding.issue(
        tenant_id=tenant,
        environment_id=environment,
        adapter="carrier",
        capability="shipment.read",
        secrets=refs or {"account": _ref()},
        revision=1,
    )


def _invocation(binding: CredentialBinding, **changes: object) -> AdapterInvocation:
    values: dict[str, object] = {
        "transaction_id": "tx-1",
        "tenant_id": binding.tenant_id,
        "environment_id": binding.environment_id,
        "step_id": "step-1",
        "capability": binding.capability,
        "adapter": binding.adapter,
        "operation": "fetch",
        "input": {},
        "credential_binding_digest": binding.binding_digest,
    }
    values.update(changes)
    return AdapterInvocation.model_validate(values)


class RecordingProvider:
    """Provider fixture that lets tests verify every issued lease is closed."""

    def __init__(self, values: dict[str, bytes], *, fail_key: str | None = None) -> None:
        self.values = values
        self.fail_key = fail_key
        self.leases: list[SecretLease] = []

    def resolve(self, ref: SecretRef, context: ResolveContext) -> SecretLease:
        del context
        if ref.key == self.fail_key:
            raise SecretProviderError("secret_unavailable")
        try:
            value = self.values[ref.key]
        except KeyError as exc:
            raise SecretProviderError("secret_not_found") from exc
        lease = SecretLease(value, datetime.now(UTC) + timedelta(seconds=30), name=ref.key)
        self.leases.append(lease)
        return lease


class SuccessExecutor:
    def __init__(self) -> None:
        self.calls = 0
        self.credentials = None
        self.seen: list[bytes] = []

    async def execute_with_credentials(
        self, invocation: AdapterInvocation, credentials: CredentialLeaseSet
    ) -> AdapterResult:
        self.calls += 1
        self.credentials = credentials
        self.seen.append(credentials.read("account"))
        assert invocation.tenant_id
        return AdapterResult(output={"ok": True})


class FailingExecutor(SuccessExecutor):
    async def execute_with_credentials(
        self, invocation: AdapterInvocation, credentials: CredentialLeaseSet
    ) -> AdapterResult:
        self.calls += 1
        self.credentials = credentials
        self.seen.append(credentials.read("account"))
        raise RuntimeError(SECRET.decode())


def _registry(
    binding: CredentialBinding,
    executor: CredentialAwareAdapterExecutor,
    provider: SecretProvider,
    *,
    include_provider: bool = True,
) -> tuple[AdapterActivities, object, CredentialAwareAdapterExecutor]:
    store = SQLiteCredentialBindingStore()
    store.put(binding)
    registry = AdapterRegistry()
    registry.register_credential_aware("carrier", executor)
    activities = AdapterActivities(
        registry,
        credential_bindings=store,
        secret_providers={"memory": provider} if include_provider else {},
    )
    return activities, provider, executor


def test_secret_is_available_only_during_credential_aware_call() -> None:
    binding = _binding()
    provider = InMemorySecretProvider({"carrier-handle": SECRET})
    executor = SuccessExecutor()
    activities, _, _ = _registry(binding, executor, provider)
    result = asyncio.run(activities.execute(_invocation(binding)))
    assert result.output["ok"] is True
    assert executor.seen == [SECRET]
    assert executor.credentials is not None
    with pytest.raises(RuntimeError):
        executor.credentials.read("account")
    assert SECRET not in repr(executor.credentials).encode()


def test_lease_set_closes_on_adapter_failure() -> None:
    binding = _binding()
    provider = RecordingProvider({"carrier-handle": SECRET})
    executor = FailingExecutor()
    activities, _, _ = _registry(binding, executor, provider)
    with pytest.raises(ApplicationError) as raised:
        asyncio.run(activities.execute(_invocation(binding)))
    assert SECRET.decode() not in str(raised.value)
    assert SECRET.decode() not in repr(raised.value)
    assert provider.leases and all(lease.closed for lease in provider.leases)
    with pytest.raises(RuntimeError):
        _ = provider.leases[0].value


def test_partial_resolution_closes_already_issued_leases() -> None:
    binding = _binding(
        refs={"account": _ref(), "region": _ref("missing-handle")}
    )
    provider = RecordingProvider({"carrier-handle": SECRET}, fail_key="missing-handle")
    executor = SuccessExecutor()
    activities, _, _ = _registry(binding, executor, provider)
    with pytest.raises(ApplicationError) as raised:
        asyncio.run(activities.execute(_invocation(binding)))
    assert raised.value.type == "credential_unavailable"
    assert executor.calls == 0
    assert provider.leases and all(lease.closed for lease in provider.leases)


@pytest.mark.parametrize(
    "changes",
    [
        {"tenant_id": "tenant-b"},
        {"environment_id": "staging"},
        {"adapter": "other-adapter"},
        {"capability": "shipment.write"},
        {"credential_binding_digest": "sha256:" + "0" * 64},
    ],
)
def test_scope_or_digest_mismatch_fails_closed(changes: dict[str, object]) -> None:
    binding = _binding()
    provider = RecordingProvider({"carrier-handle": SECRET})
    executor = SuccessExecutor()
    activities, _, _ = _registry(binding, executor, provider)
    with pytest.raises(ApplicationError) as raised:
        asyncio.run(activities.execute(_invocation(binding, **changes)))
    assert raised.value.type == "credential_unavailable"
    assert executor.calls == 0
    assert SECRET.decode() not in str(raised.value)


def test_missing_provider_fails_closed_without_invoking_adapter() -> None:
    binding = _binding()
    executor = SuccessExecutor()
    activities, _, _ = _registry(
        binding,
        executor,
        RecordingProvider({"carrier-handle": SECRET}),
        include_provider=False,
    )
    with pytest.raises(ApplicationError) as raised:
        asyncio.run(activities.execute(_invocation(binding)))
    assert raised.value.type == "credential_unavailable"
    assert executor.calls == 0
    assert SECRET.decode() not in repr(raised.value)
