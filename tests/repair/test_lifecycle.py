from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

import pytest

from cargomesh.repair.lifecycle import (
    CanaryThresholds,
    RepairLifecycle,
    RepairLifecycleError,
    RepairLifecycleState,
    SQLiteRepairLifecycle,
    VerifiedCanaryEvidence,
)
from cargomesh.repair.models import (
    CanaryResult,
    RepairApproval,
    RepairCandidate,
    RepairProposal,
    RepairRequest,
    RepairUsage,
    ValidationReport,
)

DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64
DIGEST_C = "sha256:" + "c" * 64
NOW = datetime(2042, 1, 1, tzinfo=UTC)


def _request() -> RepairRequest:
    return RepairRequest.issue(
        tenant_id="tenant-a",
        environment_id="production",
        job_id="repair-1",
        drift_report_digest=DIGEST_A,
        base_package_digest=DIGEST_B,
        sanitized_fixture_digest=DIGEST_C,
        allowed_paths=("tracking.recipe.json",),
    )


def _candidate(request: RepairRequest) -> RepairCandidate:
    return RepairCandidate.issue(
        job_id=request.job_id,
        request_digest=request.request_digest,
        base_package_digest=request.base_package_digest,
        candidate_package_digest=DIGEST_A,
        changed_paths=("tracking.recipe.json",),
        usage=RepairUsage(
            model_calls=1,
            input_tokens=1,
            output_tokens=1,
            cost_units=1,
            files=1,
            candidate_bytes=1,
            validation_seconds=1,
        ),
        result_code="candidate_validated",
    )


def _proposal(
    request: RepairRequest,
    candidate: RepairCandidate,
) -> tuple[ValidationReport, RepairProposal]:
    report = ValidationReport.issue(
        candidate_digest=candidate.candidate_digest,
        tck_report_digest=DIGEST_A,
        security_report_digest=DIGEST_B,
        passed=True,
        check_codes=("tck_passed", "security_passed"),
        duration_seconds=1,
    )
    return report, RepairProposal.issue(
        request_digest=request.request_digest,
        candidate_digest=candidate.candidate_digest,
        validation_report_digest=report.report_digest,
        result_code="proposal_ready",
        created_at=NOW,
    )


@dataclass
class Approval:
    verified: bool = True

    def verify(
        self,
        approval: RepairApproval,
        proposal: RepairProposal,
        request: RepairRequest,
    ) -> bool:
        return self.verified


class Canary:
    def run(self, proposal: RepairProposal) -> CanaryResult:
        return CanaryResult.issue(
            proposal_digest=proposal.proposal_digest,
            passed=False,
            observation_codes=("untrusted_canary_value",),
        )


@dataclass
class Evidence:
    violations: int = 0

    def verify(
        self, canary: CanaryResult, proposal: RepairProposal, request: RepairRequest
    ) -> VerifiedCanaryEvidence:
        return VerifiedCanaryEvidence.issue(
            proposal_digest=proposal.proposal_digest,
            evidence_source="independent.monitor",
            source_record_digest=DIGEST_C,
            observation_count=10,
            success_count=10,
            invariant_violation_count=self.violations,
            verified=True,
        )


@dataclass
class Deployment:
    promotes: bool = True
    rollbacks: list[str] | None = None

    def promote(self, candidate_package_digest: str, previous_package_digest: str) -> bool:
        return self.promotes

    def rollback(self, previous_package_digest: str) -> None:
        if self.rollbacks is None:
            self.rollbacks = []
        self.rollbacks.append(previous_package_digest)


def _lifecycle(evidence: Evidence, deployment: Deployment) -> RepairLifecycle:
    return RepairLifecycle(
        transitions=SQLiteRepairLifecycle(),
        approval_verifier=Approval(),
        canary_executor=Canary(),
        evidence_verifier=evidence,
        deployment=deployment,
        thresholds=CanaryThresholds.issue(
            minimum_observations=5,
            minimum_success_ppm=900_000,
        ),
    )


def test_lifecycle_requires_all_steps_and_promotes_from_independent_integer_evidence() -> None:
    request = _request()
    candidate = _candidate(request)
    report, proposal = _proposal(request, candidate)
    deployment = Deployment()
    lifecycle = _lifecycle(Evidence(), deployment)
    approval = RepairApproval.issue(
        proposal_digest=proposal.proposal_digest,
        principal_digest=DIGEST_A,
        approval_attestation_digest=DIGEST_B,
        approved=True,
        decision_code="approved",
    )

    lifecycle.record_candidate(request, candidate)
    lifecycle.record_validation(request, candidate, report)
    lifecycle.record_proposal(request, candidate, report, proposal)
    lifecycle.approve(request, proposal, approval)
    decision, rollback = lifecycle.canary(request, candidate, proposal)
    release = lifecycle.promote(request, candidate, proposal, decision)

    assert decision.passed is True
    assert rollback is None
    assert release.released is True
    with pytest.raises(RepairLifecycleError):
        lifecycle.record_candidate(request, candidate)


def test_invariant_violation_forces_rollback_and_transition_skips_fail_closed() -> None:
    request = _request()
    candidate = _candidate(request)
    report, proposal = _proposal(request, candidate)
    deployment = Deployment()
    lifecycle = _lifecycle(Evidence(violations=1), deployment)
    approval = RepairApproval.issue(
        proposal_digest=proposal.proposal_digest,
        principal_digest=DIGEST_A,
        approval_attestation_digest=DIGEST_B,
        approved=True,
        decision_code="approved",
    )

    lifecycle.record_candidate(request, candidate)
    lifecycle.record_validation(request, candidate, report)
    lifecycle.record_proposal(request, candidate, report, proposal)
    lifecycle.approve(request, proposal, approval)
    decision, rollback = lifecycle.canary(request, candidate, proposal)

    assert decision.passed is False
    assert rollback is not None and rollback.previous_package_digest == request.base_package_digest
    assert deployment.rollbacks == [request.base_package_digest]

    store = SQLiteRepairLifecycle()
    with pytest.raises(RepairLifecycleError):
        store.append(request, DIGEST_A, RepairLifecycleState.APPROVED, "skipped")


def test_expired_proposal_fails_before_canary_or_deployment() -> None:
    request = _request()
    candidate = _candidate(request)
    report, proposal = _proposal(request, candidate)
    deployment = Deployment()
    lifecycle = _lifecycle(Evidence(), deployment)
    approval = RepairApproval.issue(
        proposal_digest=proposal.proposal_digest,
        principal_digest=DIGEST_A,
        approval_attestation_digest=DIGEST_B,
        approved=True,
        decision_code="approved",
    )
    lifecycle.record_candidate(request, candidate)
    lifecycle.record_validation(request, candidate, report)
    lifecycle.record_proposal(request, candidate, report, proposal)
    with pytest.raises(RepairLifecycleError, match="expired"):
        lifecycle.approve(request, proposal, approval, now=proposal.expires_at)
    assert deployment.rollbacks is None
