from __future__ import annotations

import asyncio
from datetime import UTC, datetime

import pytest
from temporalio.exceptions import ApplicationError

from cargomesh.ir.enums import RiskClass, VerificationLevel
from cargomesh.routing.models import (
    DataClassification,
    ExecutionChannel,
    RouteCandidate,
    RouteOutcomeKind,
)
from cargomesh.routing.store import SQLiteRouteOutcomeStore
from cargomesh.runtime.adapters import (
    AdapterActivities,
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


def route_candidate() -> RouteCandidate:
    return RouteCandidate.issue(
        candidate_id="synthetic.track",
        capability="shipment.track.read",
        adapter="synthetic.track",
        operation="fetch",
        channel=ExecutionChannel.API,
        baseline_success_bps=9900,
        expected_latency_ms=25,
        cost_micros=1,
        maximum_risk_class=RiskClass.READ_ONLY,
        maximum_data_classification=DataClassification.INTERNAL,
        maximum_verification_level=VerificationLevel.L3,
    )


def test_activity_records_success_and_failure_without_business_payloads() -> None:
    registry = AdapterRegistry()
    registry.register("synthetic.track", SyntheticTrackingAdapter())
    store = SQLiteRouteOutcomeStore()
    ticks = iter((1.0, 1.025, 2.0, 2.040))
    attempts = iter((2, 3))
    activities = AdapterActivities(
        registry,
        outcome_store=store,
        clock=lambda: datetime(2026, 1, 1, tzinfo=UTC),
        monotonic=lambda: next(ticks),
        attempt_provider=lambda: next(attempts),
    )
    routed = invocation().model_copy(update={"route_candidate_id": "synthetic.track"})

    asyncio.run(activities.execute(routed))
    with pytest.raises(ApplicationError):
        asyncio.run(
            activities.execute(routed.model_copy(update={"operation": "submit"}))
        )

    outcomes = store.replay("tenant-a", route_candidate(), 10)
    assert {outcome.kind for outcome in outcomes} == {
        RouteOutcomeKind.SUCCESS,
        RouteOutcomeKind.TERMINAL_FAILURE,
    }
    assert {outcome.latency_ms for outcome in outcomes} == {25, 40}
    assert {outcome.temporal_attempt for outcome in outcomes} == {2, 3}
    serialized = " ".join(outcome.model_dump_json() for outcome in outcomes)
    assert "No carrier transaction" not in serialized
    store.close()
