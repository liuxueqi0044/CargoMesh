from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from cargomesh.ir.enums import RiskClass, VerificationLevel
from cargomesh.routing.models import (
    DataClassification,
    ExecutionChannel,
    RouteCandidate,
    RouteOutcome,
    RouteOutcomeKind,
    RoutingPolicy,
)


def candidate() -> RouteCandidate:
    return RouteCandidate.issue(
        candidate_id="carrier.api.track",
        capability="shipment.track.read",
        adapter="carrier.api.track",
        operation="fetch",
        channel=ExecutionChannel.API,
        baseline_success_bps=9900,
        expected_latency_ms=100,
        cost_micros=10,
        maximum_risk_class=RiskClass.READ_ONLY,
        maximum_data_classification=DataClassification.INTERNAL,
        maximum_verification_level=VerificationLevel.L2,
    )


def test_candidate_and_policy_are_digest_bound() -> None:
    profile = candidate()
    policy = RoutingPolicy.issue(policy_id="tenant.default", version="1.0.0")

    for model, field, value in (
        (profile, "cost_micros", 999),
        (policy, "maximum_cost_micros", 1),
    ):
        payload = model.model_dump(mode="python")
        payload[field] = value
        with pytest.raises(ValidationError, match="digest does not match"):
            type(model).model_validate(payload)


def test_outcome_requires_safe_failure_shape_and_digest() -> None:
    outcome = RouteOutcome.issue(
        event_id="event-1",
        tenant_id="tenant-a",
        transaction_id="txn-1",
        step_id="read",
        candidate_id="carrier.api.track",
        temporal_attempt=1,
        kind=RouteOutcomeKind.RETRYABLE_FAILURE,
        latency_ms=15,
        failure_code="api_timeout",
        occurred_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    payload = outcome.model_dump(mode="python")
    payload["latency_ms"] = 16
    with pytest.raises(ValidationError, match="digest does not match"):
        RouteOutcome.model_validate(payload)
    with pytest.raises(ValidationError, match="failure code"):
        RouteOutcome.issue(
            event_id="event-2",
            tenant_id="tenant-a",
            transaction_id="txn-1",
            step_id="read",
            candidate_id="carrier.api.track",
            temporal_attempt=1,
            kind=RouteOutcomeKind.SUCCESS,
            latency_ms=1,
            failure_code="impossible",
            occurred_at=datetime(2026, 1, 1, tzinfo=UTC),
        )
