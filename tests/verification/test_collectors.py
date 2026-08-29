from __future__ import annotations

import asyncio
from datetime import UTC, datetime

import pytest

from cargomesh.verification.collectors import (
    EvidenceCollectionError,
    EvidenceCollectorRegistry,
)
from cargomesh.verification.models import (
    EvidenceChannel,
    EvidenceCollectionInvocation,
    EvidenceObservation,
)

NOW = datetime(2026, 2, 3, 4, 5, 6, tzinfo=UTC)


def _invocation(collector_id: str = "ledger-collector") -> EvidenceCollectionInvocation:
    return EvidenceCollectionInvocation(
        tenant_id="tenant-1",
        transaction_id="transaction-1",
        step_id="ledger-check",
        collector_id=collector_id,
        operation="fetch",
    )


def _observation() -> EvidenceObservation:
    return EvidenceObservation.issue(
        evidence_id="evidence-1",
        tenant_id="tenant-1",
        transaction_id="transaction-1",
        source_record_id="record-1",
        source_system="synthetic.ledger",
        channel=EvidenceChannel.SYSTEM_RECORD,
        collector_id="ledger-collector",
        collection_id="collection-1",
        observed_at=NOW,
        claims={"shipment.status": "IN_TRANSIT"},
    )


class StaticCollector:
    async def collect(self, invocation: EvidenceCollectionInvocation) -> EvidenceObservation:
        assert invocation.operation == "fetch"
        return _observation()


class UnsafeCollector:
    async def collect(self, invocation: EvidenceCollectionInvocation) -> EvidenceObservation:
        del invocation
        raise RuntimeError("untrusted upstream details")


class SafeFailingCollector:
    async def collect(self, invocation: EvidenceCollectionInvocation) -> EvidenceObservation:
        del invocation
        raise EvidenceCollectionError("upstream_safe", "safe upstream failure", retryable=True)


class InvalidCollector:
    async def collect(self, invocation: EvidenceCollectionInvocation) -> EvidenceObservation:
        del invocation
        return object()  # type: ignore[return-value]


def test_registry_collects_only_registered_evidence_collectors() -> None:
    registry = EvidenceCollectorRegistry()
    collector = StaticCollector()
    registry.register("ledger-collector", collector)

    result = asyncio.run(registry.collect(_invocation()))

    assert result == _observation()
    with pytest.raises(ValueError, match="already registered"):
        registry.register("ledger-collector", collector)


def test_registry_returns_safe_not_found_and_internal_errors() -> None:
    registry = EvidenceCollectorRegistry()

    with pytest.raises(EvidenceCollectionError) as missing:
        asyncio.run(registry.collect(_invocation()))
    assert (missing.value.code, missing.value.retryable) == ("evidence_collector_not_found", False)

    registry.register("ledger-collector", UnsafeCollector())
    with pytest.raises(EvidenceCollectionError) as internal:
        asyncio.run(registry.collect(_invocation()))
    assert (internal.value.code, internal.value.retryable) == ("evidence_collector_internal", False)
    assert "untrusted" not in internal.value.message


def test_registry_preserves_safe_errors_and_rejects_invalid_results() -> None:
    registry = EvidenceCollectorRegistry()
    registry.register("ledger-collector", SafeFailingCollector())

    with pytest.raises(EvidenceCollectionError) as safe:
        asyncio.run(registry.collect(_invocation()))
    assert (safe.value.code, safe.value.retryable) == ("upstream_safe", True)

    invalid_registry = EvidenceCollectorRegistry()
    invalid_registry.register("ledger-collector", InvalidCollector())
    with pytest.raises(EvidenceCollectionError) as invalid:
        asyncio.run(invalid_registry.collect(_invocation()))
    assert invalid.value.code == "invalid_evidence_observation"
