"""Pure constraint filtering and deterministic execution-path ranking."""

from __future__ import annotations

from collections.abc import Mapping

from cargomesh.ir.enums import RiskClass, VerificationLevel

from .models import (
    DataClassification,
    RouteCandidate,
    RouteDecision,
    RouteEvaluation,
    RouteHealthSnapshot,
    RouteHealthStatus,
    RoutingPolicy,
    RoutingRequest,
)

_RISK_RANK = {
    RiskClass.READ_ONLY: 0,
    RiskClass.REVERSIBLE_WRITE: 1,
    RiskClass.CONSEQUENTIAL_WRITE: 2,
}
_DATA_RANK = {
    DataClassification.PUBLIC: 0,
    DataClassification.INTERNAL: 1,
    DataClassification.CONFIDENTIAL: 2,
    DataClassification.RESTRICTED: 3,
}
_VERIFICATION_RANK = {
    VerificationLevel.L0: 0,
    VerificationLevel.L1: 1,
    VerificationLevel.L2: 2,
    VerificationLevel.L3: 3,
}


class NoEligibleRoute(ValueError):
    code = "no_eligible_route"

    def __init__(self) -> None:
        super().__init__("no execution route satisfies the configured policy")


def select_route(
    request: RoutingRequest,
    candidates: tuple[RouteCandidate, ...],
    health_snapshots: tuple[RouteHealthSnapshot, ...],
    policy: RoutingPolicy,
) -> RouteDecision:
    """Apply hard gates, score eligible routes, and return a digest-bound decision."""

    if not candidates:
        raise NoEligibleRoute()
    if len(candidates) > 16:
        raise ValueError("routing supports at most 16 candidates")
    candidate_ids = [candidate.candidate_id for candidate in candidates]
    if len(candidate_ids) != len(set(candidate_ids)):
        raise ValueError("route candidate ids must be unique")
    health_by_candidate = _validated_health(request, health_snapshots)

    evaluations = tuple(
        _evaluate_candidate(request, candidate, health_by_candidate, policy)
        for candidate in sorted(candidates, key=lambda item: item.candidate_id)
    )
    candidate_by_id = {candidate.candidate_id: candidate for candidate in candidates}
    eligible = [evaluation for evaluation in evaluations if evaluation.eligible]
    if not eligible:
        raise NoEligibleRoute()
    ranked = sorted(
        eligible,
        key=lambda item: (
            -_required_score(item),
            candidate_by_id[item.candidate_id].static_priority,
            item.candidate_id,
        ),
    )
    ranked_ids = tuple(item.candidate_id for item in ranked)
    fallback_ids: tuple[str, ...] = ()
    if request.risk_class is RiskClass.READ_ONLY:
        fallback_ids = tuple(
            candidate_id
            for candidate_id in ranked_ids[1:]
            if not candidate_by_id[candidate_id].requires_approval
        )[: policy.maximum_fallbacks]
    return RouteDecision.issue(
        request=request,
        policy_id=policy.policy_id,
        policy_version=policy.version,
        policy_digest=policy.policy_digest,
        health_snapshots=tuple(
            sorted(health_snapshots, key=lambda item: item.candidate_id)
        ),
        evaluations=evaluations,
        ranked_candidate_ids=ranked_ids,
        selected_candidate_id=ranked_ids[0],
        fallback_candidate_ids=fallback_ids,
    )


def _validated_health(
    request: RoutingRequest,
    snapshots: tuple[RouteHealthSnapshot, ...],
) -> Mapping[str, RouteHealthSnapshot]:
    result: dict[str, RouteHealthSnapshot] = {}
    for snapshot in snapshots:
        if snapshot.candidate_id in result:
            raise ValueError("route health snapshots must be unique")
        if (
            snapshot.tenant_id != request.tenant_id
            or snapshot.evaluated_at != request.evaluated_at
        ):
            raise ValueError("route health snapshot identity does not match request")
        result[snapshot.candidate_id] = snapshot
    return result


def _evaluate_candidate(
    request: RoutingRequest,
    candidate: RouteCandidate,
    health_by_candidate: Mapping[str, RouteHealthSnapshot],
    policy: RoutingPolicy,
) -> RouteEvaluation:
    reasons: set[str] = set()
    health = health_by_candidate.get(candidate.candidate_id)
    if health is None:
        health_status = RouteHealthStatus.UNKNOWN
        effective_success = candidate.baseline_success_bps
        effective_latency = candidate.expected_latency_ms
        reasons.add("health_snapshot_missing")
    else:
        health_status = health.status
        effective_success = _effective_success(candidate, health)
        effective_latency = health.p95_latency_ms or candidate.expected_latency_ms

    if not candidate.enabled:
        reasons.add("candidate_disabled")
    if candidate.capability != request.capability:
        reasons.add("capability_mismatch")
    if candidate.channel not in policy.allowed_channels:
        reasons.add("channel_not_allowed")
    if (
        policy.allowed_candidate_ids
        and candidate.candidate_id not in policy.allowed_candidate_ids
    ):
        reasons.add("candidate_not_allowed")
    if candidate.candidate_id in policy.denied_candidate_ids:
        reasons.add("candidate_denied")
    if _RISK_RANK[request.risk_class] > _RISK_RANK[candidate.maximum_risk_class]:
        reasons.add("candidate_risk_unsupported")
    if _RISK_RANK[request.risk_class] > _RISK_RANK[policy.maximum_risk_class]:
        reasons.add("policy_risk_exceeded")
    if (
        _DATA_RANK[request.data_classification]
        > _DATA_RANK[candidate.maximum_data_classification]
    ):
        reasons.add("candidate_data_classification_unsupported")
    if (
        _DATA_RANK[request.data_classification]
        > _DATA_RANK[policy.maximum_data_classification]
    ):
        reasons.add("policy_data_classification_exceeded")
    required_verification_rank = max(
        _VERIFICATION_RANK[request.required_verification_level],
        _VERIFICATION_RANK[policy.minimum_verification_level],
    )
    if (
        _VERIFICATION_RANK[candidate.maximum_verification_level]
        < required_verification_rank
    ):
        reasons.add("verification_level_unsupported")
    if candidate.cost_micros > policy.maximum_cost_micros:
        reasons.add("cost_limit_exceeded")
    if effective_latency > policy.maximum_latency_ms:
        reasons.add("latency_limit_exceeded")
    if effective_success < policy.minimum_success_bps:
        reasons.add("reliability_below_minimum")
    if health_status is RouteHealthStatus.UNAVAILABLE:
        reasons.add("circuit_open")
    if (
        policy.approval_required_at_or_above is not None
        and _RISK_RANK[request.risk_class]
        >= _RISK_RANK[policy.approval_required_at_or_above]
        and not candidate.requires_approval
    ):
        reasons.add("approval_required")

    if reasons:
        return RouteEvaluation(
            candidate_id=candidate.candidate_id,
            candidate_digest=candidate.profile_digest,
            health_status=health_status,
            eligible=False,
            rejection_reasons=tuple(sorted(reasons)),
            effective_success_bps=effective_success,
            effective_latency_ms=effective_latency,
            cost_micros=candidate.cost_micros,
            static_priority=candidate.static_priority,
        )

    latency_score = _inverse_score(effective_latency, policy.maximum_latency_ms)
    cost_score = _inverse_score(candidate.cost_micros, policy.maximum_cost_micros)
    weights = policy.weights
    weight_total = weights.reliability + weights.latency + weights.cost
    weighted_score = (
        effective_success * weights.reliability
        + latency_score * weights.latency
        + cost_score * weights.cost
    ) // weight_total
    return RouteEvaluation(
        candidate_id=candidate.candidate_id,
        candidate_digest=candidate.profile_digest,
        health_status=health_status,
        eligible=True,
        effective_success_bps=effective_success,
        effective_latency_ms=effective_latency,
        cost_micros=candidate.cost_micros,
        reliability_score_bps=effective_success,
        latency_score_bps=latency_score,
        cost_score_bps=cost_score,
        weighted_score_bps=weighted_score,
        static_priority=candidate.static_priority,
    )


def _effective_success(
    candidate: RouteCandidate, health: RouteHealthSnapshot
) -> int:
    if health.sample_count == 0:
        return candidate.baseline_success_bps
    numerator = (
        candidate.baseline_success_bps * candidate.baseline_sample_weight
        + health.success_count * 10_000
    )
    denominator = candidate.baseline_sample_weight + health.sample_count
    return numerator // denominator


def _inverse_score(value: int, maximum: int) -> int:
    if maximum == 0:
        return 10_000 if value == 0 else 0
    return max(0, 10_000 - (value * 10_000 // maximum))


def _required_score(evaluation: RouteEvaluation) -> int:
    assert evaluation.weighted_score_bps is not None
    return evaluation.weighted_score_bps
