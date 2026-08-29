from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from cargomesh.ir.enums import RiskClass, VerificationLevel
from cargomesh.routing.engine import NoEligibleRoute, select_route
from cargomesh.routing.models import (
    DataClassification,
    ExecutionChannel,
    RouteCandidate,
    RouteHealthSnapshot,
    RouteHealthStatus,
    RoutingPolicy,
    RoutingRequest,
)

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def candidate(candidate_id: str, **overrides: object) -> RouteCandidate:
    values: dict[str, object] = {
        "candidate_id": candidate_id,
        "capability": "shipment.track.read",
        "adapter": candidate_id,
        "operation": "fetch",
        "channel": ExecutionChannel.API,
        "baseline_success_bps": 9900,
        "baseline_sample_weight": 10,
        "expected_latency_ms": 100,
        "cost_micros": 10,
        "static_priority": 10,
        "maximum_risk_class": RiskClass.READ_ONLY,
        "maximum_data_classification": DataClassification.INTERNAL,
        "maximum_verification_level": VerificationLevel.L3,
        "fallback_on_error_codes": ("api_timeout",),
    }
    values.update(overrides)
    return RouteCandidate.issue(**values)


def policy(**overrides: object) -> RoutingPolicy:
    values: dict[str, object] = {
        "policy_id": "tenant.default",
        "version": "1.0.0",
        "maximum_risk_class": RiskClass.READ_ONLY,
        "maximum_data_classification": DataClassification.INTERNAL,
        "maximum_latency_ms": 10_000,
        "maximum_cost_micros": 1_000,
    }
    values.update(overrides)
    return RoutingPolicy.issue(**values)


def request() -> RoutingRequest:
    return RoutingRequest(
        tenant_id="tenant-a",
        capability="shipment.track.read",
        risk_class=RiskClass.READ_ONLY,
        data_classification=DataClassification.INTERNAL,
        required_verification_level=VerificationLevel.L1,
        evaluated_at=NOW,
    )


def health(
    candidate_id: str,
    *,
    status: RouteHealthStatus = RouteHealthStatus.UNKNOWN,
    successes: int = 0,
    failures: int = 0,
    latency: int | None = None,
) -> RouteHealthSnapshot:
    sample = successes + failures
    if sample == 0:
        return RouteHealthSnapshot(
            tenant_id="tenant-a",
            candidate_id=candidate_id,
            evaluated_at=NOW,
            status=RouteHealthStatus.UNKNOWN,
            sample_count=0,
            success_count=0,
            retryable_failure_count=0,
            terminal_failure_count=0,
            consecutive_failures=0,
        )
    return RouteHealthSnapshot(
        tenant_id="tenant-a",
        candidate_id=candidate_id,
        evaluated_at=NOW,
        status=status,
        sample_count=sample,
        success_count=successes,
        retryable_failure_count=failures,
        terminal_failure_count=0,
        consecutive_failures=failures,
        observed_success_bps=successes * 10_000 // sample,
        p95_latency_ms=latency or 100,
        last_outcome_at=NOW - timedelta(seconds=1),
        circuit_open_until=(NOW + timedelta(minutes=1))
        if status is RouteHealthStatus.UNAVAILABLE
        else None,
    )


def test_ranking_is_deterministic_and_blends_history_with_baseline() -> None:
    api = candidate("route.api", static_priority=20)
    browser = candidate(
        "route.browser", channel=ExecutionChannel.BROWSER, static_priority=30
    )
    decision = select_route(
        request(),
        (browser, api),
        (health("route.api", successes=1, failures=1), health("route.browser")),
        policy(),
    )

    api_evaluation = next(
        item for item in decision.evaluations if item.candidate_id == "route.api"
    )
    assert api_evaluation.effective_success_bps == 9083
    assert decision.selected_candidate_id == "route.browser"
    assert decision.fallback_candidate_ids == ("route.api",)
    assert decision.decision_digest.startswith("sha256:")
    payload = decision.model_dump(mode="python")
    payload["evaluations"][0]["static_priority"] = 999
    with pytest.raises(ValidationError, match="digest does not match"):
        type(decision).model_validate(payload)


def test_open_circuit_removes_api_and_browser_wins() -> None:
    api = candidate("route.api")
    browser = candidate("route.browser", channel=ExecutionChannel.BROWSER)
    decision = select_route(
        request(),
        (api, browser),
        (
            health(
                "route.api",
                status=RouteHealthStatus.UNAVAILABLE,
                failures=3,
            ),
            health("route.browser"),
        ),
        policy(),
    )
    api_evaluation = next(
        item for item in decision.evaluations if item.candidate_id == "route.api"
    )
    assert "circuit_open" in api_evaluation.rejection_reasons
    assert decision.selected_candidate_id == "route.browser"


def test_hard_gates_are_explicit_and_missing_health_fails_closed() -> None:
    good = candidate("route.good", channel=ExecutionChannel.BROWSER)
    blocked = candidate(
        "route.blocked",
        enabled=False,
        maximum_data_classification=DataClassification.PUBLIC,
        maximum_verification_level=VerificationLevel.L0,
        cost_micros=2_000,
        expected_latency_ms=20_000,
    )
    decision = select_route(
        request(),
        (blocked, good),
        (health("route.good"), health("route.blocked")),
        policy(denied_candidate_ids=("route.blocked",)),
    )
    rejected = next(
        item for item in decision.evaluations if item.candidate_id == "route.blocked"
    )
    assert {
        "candidate_disabled",
        "candidate_denied",
        "candidate_data_classification_unsupported",
        "verification_level_unsupported",
        "cost_limit_exceeded",
        "latency_limit_exceeded",
    } <= set(rejected.rejection_reasons)

    with pytest.raises(NoEligibleRoute):
        select_route(request(), (good,), (), policy())


def test_equal_scores_use_static_priority_then_candidate_id() -> None:
    first = candidate("route.a", static_priority=5)
    second = candidate("route.b", static_priority=5)
    decision = select_route(
        request(),
        (second, first),
        (health("route.b"), health("route.a")),
        policy(),
    )
    assert decision.ranked_candidate_ids == ("route.a", "route.b")
