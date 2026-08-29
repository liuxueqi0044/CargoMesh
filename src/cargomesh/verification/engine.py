"""Pure, deterministic verification and evidence-independence evaluation."""

from __future__ import annotations

import math
from datetime import UTC, datetime, timedelta

from pydantic import JsonValue

from cargomesh.ir.enums import VerificationLevel

from .models import (
    ClaimNormalization,
    ClaimOutcome,
    ClaimResult,
    ClaimScalar,
    EvidenceObservation,
    EvidenceReceiptSummary,
    ExecutionSource,
    VerificationInvocation,
    VerificationReport,
    VerificationVerdict,
)

_LEVEL_RANK = {
    VerificationLevel.L0: 0,
    VerificationLevel.L1: 1,
    VerificationLevel.L2: 2,
    VerificationLevel.L3: 3,
}
_HALTING_REASONS = frozenset(
    {
        "evidence_claim_missing",
        "evidence_expired",
        "evidence_from_future",
        "evidence_identity_mismatch",
        "evidence_stale",
        "expected_claim_unavailable",
        "independence_insufficient",
    }
)


class ExpectedValueUnavailable(ValueError):
    pass


def evaluate_verification(
    invocation: VerificationInvocation,
    observations: tuple[EvidenceObservation, ...],
    *,
    evaluated_at: datetime,
) -> VerificationReport:
    """Evaluate bounded observations without network, storage, or model calls."""

    if evaluated_at.tzinfo is None or evaluated_at.utcoffset() is None:
        raise ValueError("evaluation time must include a timezone")
    evaluated_at = evaluated_at.astimezone(UTC)
    reasons: set[str] = set()
    identity_valid: list[EvidenceObservation] = []
    fresh: list[EvidenceObservation] = []

    for observation in observations:
        if (
            observation.tenant_id != invocation.tenant_id
            or observation.transaction_id != invocation.transaction_id
        ):
            reasons.add("evidence_identity_mismatch")
            continue
        identity_valid.append(observation)
        if observation.observed_at > evaluated_at + timedelta(
            seconds=invocation.plan.future_clock_skew_seconds
        ):
            reasons.add("evidence_from_future")
            continue
        if evaluated_at - observation.observed_at > timedelta(
            seconds=invocation.plan.max_evidence_age_seconds
        ):
            reasons.add("evidence_stale")
            continue
        if observation.expires_at is not None and observation.expires_at <= evaluated_at:
            reasons.add("evidence_expired")
            continue
        fresh.append(observation)

    achieved_level, independent = _independence_level(
        tuple(fresh), invocation.execution_sources
    )
    if _LEVEL_RANK[achieved_level] < _LEVEL_RANK[invocation.plan.required_level]:
        reasons.add("independence_insufficient")

    claim_results: list[ClaimResult] = []
    for rule in invocation.plan.claim_rules:
        try:
            expected = resolve_json_pointer(invocation.execution_document, rule.expected_pointer)
            expected_scalar = _require_scalar(expected)
        except ExpectedValueUnavailable:
            reasons.add("expected_claim_unavailable")
            claim_results.append(
                ClaimResult(claim=rule.claim, outcome=ClaimOutcome.MISSING)
            )
            continue

        observed_values = tuple(
            observation.claims[rule.claim]
            for observation in independent
            if rule.claim in observation.claims
        )
        normalized_values = {
            _normalized_key(value, rule.normalization) for value in observed_values
        }
        normalized_expected = _normalized_key(expected_scalar, rule.normalization)
        if not observed_values:
            outcome = ClaimOutcome.MISSING
            reasons.add("evidence_claim_missing")
        elif len(normalized_values) > 1:
            outcome = ClaimOutcome.CONFLICT
            reasons.add("evidence_conflict")
        elif next(iter(normalized_values)) != normalized_expected:
            outcome = ClaimOutcome.MISMATCH
            reasons.add("evidence_mismatch")
        else:
            outcome = ClaimOutcome.MATCH
        claim_results.append(
            ClaimResult(
                claim=rule.claim,
                outcome=outcome,
                expected=expected_scalar,
                observed=observed_values,
            )
        )

    outcomes = {result.outcome for result in claim_results}
    if reasons.intersection(_HALTING_REASONS):
        verdict = VerificationVerdict.HALTED
    elif ClaimOutcome.CONFLICT in outcomes or ClaimOutcome.MISMATCH in outcomes:
        verdict = VerificationVerdict.NEEDS_REVIEW
    elif reasons or ClaimOutcome.MISSING in outcomes:
        verdict = VerificationVerdict.HALTED
    else:
        verdict = VerificationVerdict.VERIFIED
        reasons.add("claims_and_independence_verified")

    summaries = tuple(_receipt_summary(observation) for observation in identity_valid)
    return VerificationReport.issue(
        transaction_id=invocation.transaction_id,
        business_digest=invocation.business_digest,
        verdict=verdict,
        required_level=invocation.plan.required_level,
        achieved_level=achieved_level,
        evaluated_at=evaluated_at,
        reasons=tuple(sorted(reasons)),
        claims=tuple(claim_results),
        evidence=summaries,
        synthetic=any(source.synthetic for source in invocation.execution_sources)
        or any(observation.synthetic for observation in identity_valid),
    )


def resolve_json_pointer(document: JsonValue, pointer: str) -> JsonValue:
    current = document
    for raw_token in pointer.split("/")[1:]:
        token = raw_token.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict):
            if token not in current:
                raise ExpectedValueUnavailable("expected JSON Pointer field is missing")
            current = current[token]
        elif isinstance(current, list):
            if not token.isdigit() or (len(token) > 1 and token.startswith("0")):
                raise ExpectedValueUnavailable("expected JSON Pointer index is invalid")
            index = int(token)
            if index >= len(current):
                raise ExpectedValueUnavailable("expected JSON Pointer index is out of range")
            current = current[index]
        else:
            raise ExpectedValueUnavailable("expected JSON Pointer traversed a scalar")
    return current


def _independence_level(
    observations: tuple[EvidenceObservation, ...],
    execution_sources: tuple[ExecutionSource, ...],
) -> tuple[VerificationLevel, tuple[EvidenceObservation, ...]]:
    if not execution_sources:
        return VerificationLevel.L0, ()
    level_one = tuple(
        observation
        for observation in observations
        if all(
            observation.collector_id != source.adapter_id
            and observation.collection_id != source.collection_id
            for source in execution_sources
        )
    )
    if not level_one:
        return VerificationLevel.L0, ()
    execution_systems = {source.source_system for source in execution_sources}
    level_two = tuple(
        observation
        for observation in level_one
        if observation.source_system not in execution_systems
    )
    if not level_two:
        return VerificationLevel.L1, level_one
    source_systems = {observation.source_system for observation in level_two}
    channels = {observation.channel for observation in level_two}
    if len(source_systems) >= 2 and len(channels) >= 2:
        return VerificationLevel.L3, level_two
    return VerificationLevel.L2, level_two


def _require_scalar(value: JsonValue) -> ClaimScalar:
    if value is None or isinstance(value, str | int | float | bool):
        if isinstance(value, float) and not math.isfinite(value):
            raise ExpectedValueUnavailable("expected claim must be a finite number")
        return value
    raise ExpectedValueUnavailable("expected claim must resolve to a scalar")


def _normalized_key(value: ClaimScalar, normalization: ClaimNormalization) -> str:
    if normalization is ClaimNormalization.CASEFOLD and isinstance(value, str):
        value = value.casefold()
    return f"{type(value).__name__}:{value!r}"


def _receipt_summary(observation: EvidenceObservation) -> EvidenceReceiptSummary:
    return EvidenceReceiptSummary(
        evidence_id=observation.evidence_id,
        source_record_id=observation.source_record_id,
        source_system=observation.source_system,
        channel=observation.channel,
        collector_id=observation.collector_id,
        collection_id=observation.collection_id,
        observed_at=observation.observed_at,
        content_digest=observation.content_digest,
        synthetic=observation.synthetic,
    )
