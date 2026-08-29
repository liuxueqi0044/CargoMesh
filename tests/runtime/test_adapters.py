from __future__ import annotations

import asyncio

import pytest

from cargomesh.runtime.adapters import (
    AdapterExecutionError,
    AdapterRegistry,
    SyntheticTrackingAdapter,
)
from cargomesh.runtime.models import AdapterInvocation


def invocation(*, adapter: str = "synthetic.track", operation: str = "fetch") -> AdapterInvocation:
    return AdapterInvocation(
        transaction_id="txn-1",
        tenant_id="tenant-a",
        step_id="fetch",
        adapter=adapter,
        operation=operation,
        input={},
    )


def test_registry_invokes_synthetic_adapter_without_carrier_claim() -> None:
    registry = AdapterRegistry()
    registry.register("synthetic.track", SyntheticTrackingAdapter())

    result = asyncio.run(registry.invoke(invocation()))

    assert result.output["synthetic"] is True
    assert result.output["events"] == []
    assert "No carrier transaction" in result.output["notice"]


def test_registry_fails_closed_for_unknown_adapter_and_operation() -> None:
    registry = AdapterRegistry()
    registry.register("synthetic.track", SyntheticTrackingAdapter())

    with pytest.raises(AdapterExecutionError) as unknown:
        asyncio.run(registry.invoke(invocation(adapter="missing.adapter")))
    assert unknown.value.code == "adapter_not_found"
    assert unknown.value.retryable is False

    with pytest.raises(AdapterExecutionError) as operation:
        asyncio.run(registry.invoke(invocation(operation="submit")))
    assert operation.value.code == "operation_not_supported"
