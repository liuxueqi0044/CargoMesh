"""Contract and rejection tests for repair metadata."""

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from cargomesh.repair.models import (
    CanaryResult,
    ReleaseResult,
    RepairApproval,
    RepairBudget,
    RepairCandidate,
    RepairProposal,
    RepairRequest,
    RepairTransition,
    RepairUsage,
    ValidationReport,
)


def digest(seed: str) -> str:
    import hashlib

    return "sha256:" + hashlib.sha256(seed.encode()).hexdigest()


def request(**updates: object) -> RepairRequest:
    values: dict[str, object] = {
        "tenant_id": "tenant-a",
        "environment_id": "staging",
        "job_id": "repair-1",
        "drift_report_digest": digest("drift"),
        "base_package_digest": digest("base"),
        "sanitized_fixture_digest": digest("fixture"),
        "allowed_paths": ("adapter/config.json", "adapter/recipe.json"),
    }
    values.update(updates)
    return RepairRequest.issue(**values)


def usage(**updates: int) -> RepairUsage:
    values = {
        "model_calls": 1,
        "input_tokens": 10,
        "output_tokens": 5,
        "cost_units": 2,
        "files": 1,
        "candidate_bytes": 20,
        "validation_seconds": 1,
    }
    values.update(updates)
    return RepairUsage(**values)


def test_request_is_frozen_and_digest_bound() -> None:
    item = request()
    assert item.digest.startswith("sha256:")
    with pytest.raises(ValidationError):
        item.tenant_id = "other"  # type: ignore[misc]

    tampered = item.model_dump()
    tampered["job_id"] = "other-job"
    with pytest.raises(ValidationError):
        RepairRequest.model_validate(tampered)


@pytest.mark.parametrize(
    "path",
    [
        "/absolute.json",
        "../escape.json",
        "adapter/../escape.json",
        "adapter\\config.json",
        "adapter/config.py",
        "adapter/config.json/extra.json",
        ".hidden.json",
    ],
)
def test_request_rejects_non_allowlisted_paths(path: str) -> None:
    with pytest.raises(ValidationError):
        request(allowed_paths=(path,))


def test_request_rejects_duplicate_paths_and_extra_secret_fields() -> None:
    with pytest.raises(ValidationError):
        request(allowed_paths=("adapter/config.json", "adapter/config.json"))

    values = request().model_dump()
    values["credential_value"] = "super-secret"
    with pytest.raises(ValidationError) as caught:
        RepairRequest.model_validate(values)
    assert "super-secret" not in str(caught.value)


def test_budget_and_usage_are_bounded_and_digest_bound() -> None:
    budget = RepairBudget.issue(
        max_model_calls=2,
        max_input_tokens=100,
        max_output_tokens=100,
        max_cost_units=50,
        max_files=2,
        max_candidate_bytes=1000,
        max_validation_seconds=30,
    )
    assert budget.digest.startswith("sha256:")
    with pytest.raises(ValidationError):
        RepairBudget.model_validate({**budget.model_dump(), "max_files": 3})
    with pytest.raises(ValidationError):
        RepairUsage(
            model_calls=-1,
            input_tokens=0,
            output_tokens=0,
            cost_units=0,
            files=0,
            candidate_bytes=0,
            validation_seconds=0,
        )


def test_lifecycle_contracts_store_only_digests_and_safe_codes() -> None:
    req = request()
    candidate = RepairCandidate.issue(
        job_id=req.job_id,
        request_digest=req.digest,
        base_package_digest=req.base_package_digest,
        candidate_package_digest=digest("candidate"),
        changed_paths=("adapter/config.json",),
        usage=usage(),
        result_code="candidate_ready",
    )
    report = ValidationReport.issue(
        candidate_digest=candidate.candidate_digest,
        tck_report_digest=digest("tck"),
        security_report_digest=digest("security"),
        passed=True,
        check_codes=("syntax_ok",),
        duration_seconds=1,
    )
    proposal = RepairProposal.issue(
        request_digest=req.digest,
        candidate_digest=candidate.candidate_digest,
        validation_report_digest=report.report_digest,
        result_code="proposal_ready",
    )
    approval = RepairApproval.issue(
        proposal_digest=proposal.proposal_digest,
        principal_digest=digest("principal"),
        approval_attestation_digest=digest("attestation"),
        approved=True,
        decision_code="approved",
    )
    canary = CanaryResult.issue(
        proposal_digest=proposal.proposal_digest,
        passed=True,
        observation_codes=("healthy",),
    )
    release = ReleaseResult.issue(
        previous_package_digest=req.base_package_digest,
        candidate_package_digest=candidate.candidate_package_digest,
        released=True,
        result_code="released",
    )
    transition = RepairTransition.issue(
        tenant_id=req.tenant_id,
        environment_id=req.environment_id,
        job_id=req.job_id,
        request_digest=req.digest,
        subject_digest=proposal.proposal_digest,
        from_state="proposed",
        to_state="approved",
        event_code="approval_recorded",
    )
    for item in (candidate, report, proposal, approval, canary, release, transition):
        assert "prompt" not in item.model_dump()
        assert "response" not in item.model_dump()
    assert approval.approval_attestation_digest == digest("attestation")


def test_proposal_expiry_and_transition_time_are_strict() -> None:
    created = datetime.now(UTC)
    with pytest.raises(ValidationError):
        RepairProposal.issue(
            request_digest=digest("r"),
            candidate_digest=digest("c"),
            validation_report_digest=digest("v"),
            result_code="proposal_ready",
            created_at=created,
            expires_at=created,
        )
    with pytest.raises(ValidationError):
        RepairTransition.issue(
            tenant_id="tenant-a",
            environment_id="staging",
            job_id="repair-1",
            request_digest=digest("request"),
            subject_digest=digest("subject"),
            from_state="a",
            to_state="b",
            event_code="changed",
            occurred_at=created.replace(tzinfo=None),
        )
    assert (
        RepairProposal.issue(
            request_digest=digest("r"),
            candidate_digest=digest("c"),
            validation_report_digest=digest("v"),
            result_code="proposal_ready",
            created_at=created,
            expires_at=created + timedelta(minutes=1),
        ).expires_at
        > created
    )


def test_transition_digest_binds_scope_and_subject() -> None:
    item = RepairTransition.issue(
        tenant_id="tenant-a",
        environment_id="staging",
        job_id="repair-1",
        request_digest=digest("request"),
        subject_digest=digest("candidate"),
        from_state="candidate",
        to_state="validated",
        event_code="validation_recorded",
    )
    tampered = item.model_dump()
    tampered["tenant_id"] = "tenant-b"
    with pytest.raises(ValidationError):
        RepairTransition.model_validate(tampered)
    tampered = item.model_dump()
    tampered["subject_digest"] = digest("other-subject")
    with pytest.raises(ValidationError):
        RepairTransition.model_validate(tampered)
