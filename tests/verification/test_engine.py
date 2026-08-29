from __future__ import annotations

from datetime import UTC, datetime, timedelta

from cargomesh.ir.enums import VerificationLevel
from cargomesh.verification.engine import evaluate_verification
from cargomesh.verification.models import (
    ClaimNormalization,
    ClaimOutcome,
    EvidenceChannel,
    EvidenceCollectionSpec,
    EvidenceObservation,
    ExecutionSource,
    VerificationClaimRule,
    VerificationInvocation,
    VerificationPlan,
    VerificationVerdict,
)

NOW = datetime(2026, 2, 3, 4, 5, 6, tzinfo=UTC)
DIGEST = "sha256:" + "a" * 64


def _plan(
    required_level: VerificationLevel = VerificationLevel.L2,
    *,
    normalization: ClaimNormalization = ClaimNormalization.EXACT,
    max_age: int = 3600,
    future_skew: int = 300,
) -> VerificationPlan:
    return VerificationPlan(
        required_level=required_level,
        collectors=(
            EvidenceCollectionSpec(
                step_id="ledger-check", collector_id="ledger-collector", operation="fetch"
            ),
        ),
        claim_rules=(
            VerificationClaimRule(
                claim="shipment.status",
                expected_pointer="/execution/status",
                normalization=normalization,
            ),
        ),
        max_evidence_age_seconds=max_age,
        future_clock_skew_seconds=future_skew,
    )


def _source(**changes: object) -> ExecutionSource:
    values: dict[str, object] = {
        "source_system": "synthetic.portal",
        "channel": EvidenceChannel.BROWSER,
        "adapter_id": "synthetic-browser",
        "collection_id": "execution-collection",
    }
    values.update(changes)
    return ExecutionSource.model_validate(values)


def _observation(**changes: object) -> EvidenceObservation:
    values: dict[str, object] = {
        "evidence_id": "evidence-1",
        "tenant_id": "tenant-1",
        "transaction_id": "transaction-1",
        "source_record_id": "ledger-record-1",
        "source_system": "synthetic.ledger",
        "channel": EvidenceChannel.SYSTEM_RECORD,
        "collector_id": "ledger-collector",
        "collection_id": "ledger-collection",
        "observed_at": NOW,
        "claims": {"shipment.status": "IN_TRANSIT"},
    }
    values.update(changes)
    return EvidenceObservation.issue(**values)


def _invocation(
    plan: VerificationPlan, sources: tuple[ExecutionSource, ...] = (_source(),)
) -> VerificationInvocation:
    return VerificationInvocation(
        tenant_id="tenant-1",
        transaction_id="transaction-1",
        business_digest=DIGEST,
        plan=plan,
        execution_document={"execution": {"status": "IN_TRANSIT"}},
        execution_sources=sources,
    )


def test_independence_levels_l0_through_l3() -> None:
    l0 = evaluate_verification(
        _invocation(_plan(VerificationLevel.L1), ()), (_observation(),), evaluated_at=NOW
    )
    l1 = evaluate_verification(
        _invocation(_plan(VerificationLevel.L1)),
        (_observation(source_system="synthetic.portal"),),
        evaluated_at=NOW,
    )
    l2 = evaluate_verification(
        _invocation(_plan(VerificationLevel.L2)), (_observation(),), evaluated_at=NOW
    )
    l3 = evaluate_verification(
        _invocation(_plan(VerificationLevel.L3)),
        (
            _observation(),
            _observation(
                evidence_id="evidence-2",
                source_record_id="ledger-record-2",
                source_system="partner.ledger",
                channel=EvidenceChannel.API,
                collector_id="partner-collector",
                collection_id="partner-collection",
            ),
        ),
        evaluated_at=NOW,
    )

    assert (l0.achieved_level, l0.verdict) == (VerificationLevel.L0, VerificationVerdict.HALTED)
    assert (l1.achieved_level, l1.verdict) == (VerificationLevel.L1, VerificationVerdict.VERIFIED)
    assert (l2.achieved_level, l2.verdict) == (VerificationLevel.L2, VerificationVerdict.VERIFIED)
    assert (l3.achieved_level, l3.verdict) == (VerificationLevel.L3, VerificationVerdict.VERIFIED)


def test_exact_casefold_conflict_mismatch_and_missing_claim_results() -> None:
    exact_mismatch = evaluate_verification(
        _invocation(_plan(VerificationLevel.L2)),
        (_observation(claims={"shipment.status": "in_transit"}),),
        evaluated_at=NOW,
    )
    casefold_match = evaluate_verification(
        _invocation(_plan(VerificationLevel.L2, normalization=ClaimNormalization.CASEFOLD)),
        (_observation(claims={"shipment.status": "in_transit"}),),
        evaluated_at=NOW,
    )
    conflict = evaluate_verification(
        _invocation(_plan(VerificationLevel.L2)),
        (
            _observation(),
            _observation(
                evidence_id="evidence-2",
                source_record_id="ledger-record-2",
                claims={"shipment.status": "DELAYED"},
            ),
        ),
        evaluated_at=NOW,
    )
    missing = evaluate_verification(
        _invocation(_plan(VerificationLevel.L2)),
        (_observation(claims={"shipment.reference": "CBR-001"}),),
        evaluated_at=NOW,
    )
    insufficient_mismatch = evaluate_verification(
        _invocation(_plan(VerificationLevel.L2)),
        (
            _observation(
                source_system="synthetic.portal",
                claims={"shipment.status": "DELAYED"},
            ),
        ),
        evaluated_at=NOW,
    )

    assert exact_mismatch.claims[0].outcome is ClaimOutcome.MISMATCH
    assert exact_mismatch.verdict is VerificationVerdict.NEEDS_REVIEW
    assert casefold_match.claims[0].outcome is ClaimOutcome.MATCH
    assert casefold_match.verdict is VerificationVerdict.VERIFIED
    assert conflict.claims[0].outcome is ClaimOutcome.CONFLICT
    assert conflict.verdict is VerificationVerdict.NEEDS_REVIEW
    assert missing.claims[0].outcome is ClaimOutcome.MISSING
    assert missing.verdict is VerificationVerdict.HALTED
    assert insufficient_mismatch.verdict is VerificationVerdict.HALTED
    assert "independence_insufficient" in insufficient_mismatch.reasons


def test_stale_future_and_identity_mismatch_halt_verification() -> None:
    stale = evaluate_verification(
        _invocation(_plan(max_age=60)),
        (_observation(observed_at=NOW - timedelta(seconds=61)),),
        evaluated_at=NOW,
    )
    future = evaluate_verification(
        _invocation(_plan(future_skew=0)),
        (_observation(observed_at=NOW + timedelta(seconds=1)),),
        evaluated_at=NOW,
    )
    expired = evaluate_verification(
        _invocation(_plan()),
        (
            _observation(
                observed_at=NOW - timedelta(seconds=2),
                expires_at=NOW - timedelta(seconds=1),
            ),
        ),
        evaluated_at=NOW,
    )
    wrong_identity = evaluate_verification(
        _invocation(_plan()), (_observation(tenant_id="other-tenant"),), evaluated_at=NOW
    )

    assert stale.verdict is VerificationVerdict.HALTED
    assert "evidence_stale" in stale.reasons
    assert future.verdict is VerificationVerdict.HALTED
    assert "evidence_from_future" in future.reasons
    assert expired.verdict is VerificationVerdict.HALTED
    assert "evidence_expired" in expired.reasons
    assert wrong_identity.verdict is VerificationVerdict.HALTED
    assert "evidence_identity_mismatch" in wrong_identity.reasons
