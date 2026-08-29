from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from cargomesh.ir import ShipmentSubject, TransactionCommand
from cargomesh.ir.enums import VerificationLevel
from cargomesh.routing.models import RouteOutcome, RouteOutcomeKind
from cargomesh.routing.store import SQLiteRouteOutcomeStore
from cargomesh.runtime import (
    CapabilityBinding,
    MissingCapabilityBinding,
    StaticExecutionPlanner,
    synthetic_browser_tracking_planner,
    synthetic_optimized_tracking_planner,
    synthetic_verified_browser_tracking_planner,
)


def command() -> TransactionCommand:
    return TransactionCommand(
        tenant_id="tenant-a",
        external_reference="customer-1",
        subject=ShipmentSubject(carrier_booking_reference="CBR-1"),
    )


def test_static_planner_builds_deterministic_explicit_step() -> None:
    planner = StaticExecutionPlanner(
        {
            "shipment.track.read": CapabilityBinding(
                adapter="synthetic.track", operation="fetch"
            )
        }
    )
    first = planner.build(
        command(), transaction_id="txn-1", business_digest="sha256:" + "a" * 64
    )
    second = planner.build(
        command(), transaction_id="txn-1", business_digest="sha256:" + "a" * 64
    )

    assert first == second
    assert first.steps[0].adapter == "synthetic.track"
    assert first.steps[0].input["transaction"]["subject"]["carrier_booking_reference"] == "CBR-1"


def test_static_planner_fails_closed_without_binding() -> None:
    with pytest.raises(MissingCapabilityBinding, match=r"shipment\.track\.read"):
        StaticExecutionPlanner({}).build(
            command(), transaction_id="txn-1", business_digest="sha256:" + "a" * 64
        )


def test_board_3_browser_binding_preserves_the_ir_input_shape() -> None:
    plan = synthetic_browser_tracking_planner().build(
        command(), transaction_id="txn-1", business_digest="sha256:" + "a" * 64
    )

    assert plan.steps[0].adapter == "synthetic.browser.track"
    assert plan.steps[0].operation == "fetch"
    assert plan.steps[0].input["transaction"]["subject"]["carrier_booking_reference"] == "CBR-1"


def test_board_4_binding_adds_separate_ledger_verification() -> None:
    plan = synthetic_verified_browser_tracking_planner().build(
        command(), transaction_id="txn-1", business_digest="sha256:" + "a" * 64
    )

    assert plan.verification is not None
    assert plan.verification.required_level is VerificationLevel.L1
    assert plan.verification.collectors[0].collector_id == "synthetic.evidence.track"
    assert plan.verification.collectors[0].input == {
        "carrier_booking_reference": "CBR-1"
    }
    assert {rule.claim for rule in plan.verification.claim_rules} == {
        "shipment.reference",
        "shipment.status",
    }


def test_board_5_optimizer_freezes_api_ranking_and_safe_browser_fallback() -> None:
    store = SQLiteRouteOutcomeStore()
    evaluated_at = datetime(2026, 1, 1, tzinfo=UTC)
    plan = synthetic_optimized_tracking_planner(
        store, clock=lambda: evaluated_at
    ).build(command(), transaction_id="txn-1", business_digest="sha256:" + "a" * 64)

    assert plan.steps[0].route_candidate_id == "synthetic.api.track"
    assert [item.candidate_id for item in plan.steps[0].route_fallbacks] == [
        "synthetic.browser.track"
    ]
    assert plan.routing_decisions[0].selected_candidate_id == "synthetic.api.track"
    store.close()


def test_board_5_open_circuit_selects_browser_before_workflow_start() -> None:
    store = SQLiteRouteOutcomeStore()
    evaluated_at = datetime(2026, 1, 1, tzinfo=UTC)
    for attempt in range(1, 4):
        store.append(
            RouteOutcome.issue(
                event_id=f"event-{attempt}",
                tenant_id="tenant-a",
                transaction_id=f"txn-{attempt}",
                step_id="read",
                candidate_id="synthetic.api.track",
                temporal_attempt=1,
                kind=RouteOutcomeKind.RETRYABLE_FAILURE,
                latency_ms=50,
                failure_code="api_server_error",
                occurred_at=evaluated_at - timedelta(seconds=4 - attempt),
            )
        )
    plan = synthetic_optimized_tracking_planner(
        store, clock=lambda: evaluated_at
    ).build(command(), transaction_id="txn-4", business_digest="sha256:" + "a" * 64)

    assert plan.steps[0].route_candidate_id == "synthetic.browser.track"
    assert "circuit_open" in next(
        item
        for item in plan.routing_decisions[0].evaluations
        if item.candidate_id == "synthetic.api.track"
    ).rejection_reasons
    store.close()
