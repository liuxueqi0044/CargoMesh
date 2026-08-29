from __future__ import annotations

import asyncio
from datetime import UTC, datetime

import pytest
from temporalio.exceptions import ApplicationError

from cargomesh.ir.enums import VerificationLevel
from cargomesh.verification.activities import VerificationActivities
from cargomesh.verification.collectors import EvidenceCollectorRegistry
from cargomesh.verification.models import (
    EvidenceChannel,
    EvidenceCollectionInvocation,
    EvidenceCollectionSpec,
    EvidenceObservation,
    ExecutionSource,
    VerificationClaimRule,
    VerificationInvocation,
    VerificationPlan,
    VerificationVerdict,
)
from cargomesh.verification.store import SQLiteEvidenceStore

NOW = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)


class FixedCollector:
    def __init__(self, observation: EvidenceObservation) -> None:
        self.observation = observation
        self.invocations: list[EvidenceCollectionInvocation] = []

    async def collect(
        self, invocation: EvidenceCollectionInvocation
    ) -> EvidenceObservation:
        self.invocations.append(invocation)
        return self.observation


def observation(*, transaction_id: str = "txn-1") -> EvidenceObservation:
    return EvidenceObservation.issue(
        evidence_id="evidence-1",
        tenant_id="tenant-a",
        transaction_id=transaction_id,
        source_record_id="record-1",
        source_system="synthetic.ledger",
        channel=EvidenceChannel.SYSTEM_RECORD,
        collector_id="test.collector",
        collection_id="evidence-collection-1",
        observed_at=NOW,
        claims={
            "shipment.reference": "CBR-001",
            "shipment.status": "IN_TRANSIT",
        },
        synthetic=True,
    )


def invocation() -> VerificationInvocation:
    return VerificationInvocation(
        tenant_id="tenant-a",
        transaction_id="txn-1",
        business_digest="sha256:" + "a" * 64,
        plan=VerificationPlan(
            required_level=VerificationLevel.L2,
            collectors=(
                EvidenceCollectionSpec(
                    step_id="collect-ledger",
                    collector_id="test.collector",
                    operation="fetch",
                    input={"carrier_booking_reference": "CBR-001"},
                ),
            ),
            claim_rules=(
                VerificationClaimRule(
                    claim="shipment.reference",
                    expected_pointer="/transaction/subject/carrier_booking_reference",
                ),
                VerificationClaimRule(
                    claim="shipment.status",
                    expected_pointer="/outputs/0/output/data/shipment.status",
                ),
            ),
        ),
        execution_document={
            "transaction": {
                "subject": {"carrier_booking_reference": "CBR-001"}
            },
            "outputs": [
                {"output": {"data": {"shipment.status": "IN_TRANSIT"}}}
            ],
        },
        execution_sources=(
            ExecutionSource(
                source_system="synthetic.portal",
                channel=EvidenceChannel.BROWSER,
                adapter_id="synthetic.browser.track",
                collection_id="execution-collection-1",
                synthetic=True,
            ),
        ),
    )


def test_activity_persists_receipt_before_returning_verified_report() -> None:
    collected = observation()
    collector = FixedCollector(collected)
    registry = EvidenceCollectorRegistry()
    registry.register("test.collector", collector)

    with SQLiteEvidenceStore(":memory:") as store:
        activities = VerificationActivities(registry, store, clock=lambda: NOW)
        report = asyncio.run(activities.verify(invocation()))

        assert store.get("tenant-a", collected.evidence_id) == collected

    assert report.verdict is VerificationVerdict.VERIFIED
    assert report.achieved_level is VerificationLevel.L2
    assert report.synthetic is True
    assert len(collector.invocations) == 1


def test_activity_rejects_cross_transaction_evidence_before_persistence() -> None:
    registry = EvidenceCollectorRegistry()
    registry.register("test.collector", FixedCollector(observation(transaction_id="other")))

    with SQLiteEvidenceStore(":memory:") as store:
        activities = VerificationActivities(registry, store, clock=lambda: NOW)
        with pytest.raises(ApplicationError) as error:
            asyncio.run(activities.verify(invocation()))
        assert store.get("tenant-a", "evidence-1") is None

    assert error.value.type == "evidence_identity_mismatch"
    assert error.value.non_retryable is True


def test_activity_exposes_only_safe_missing_collector_code() -> None:
    store = SQLiteEvidenceStore(":memory:")
    activities = VerificationActivities(EvidenceCollectorRegistry(), store, clock=lambda: NOW)
    try:
        with pytest.raises(ApplicationError) as error:
            asyncio.run(activities.verify(invocation()))
    finally:
        store.close()

    assert error.value.type == "evidence_collector_not_found"
    assert error.value.non_retryable is True
