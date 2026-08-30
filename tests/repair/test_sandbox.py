from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

import pytest

from cargomesh.repair.budget import SQLiteRepairBudgetLedger
from cargomesh.repair.models import RepairBudget, RepairRequest, RepairUsage
from cargomesh.repair.sandbox import (
    GateResult,
    IsolatedRepairSandbox,
    ModelRepairResponse,
    RepairSandboxError,
)

DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64
DIGEST_C = "sha256:" + "c" * 64


@dataclass
class Model:
    response: ModelRepairResponse
    calls: int = 0

    def propose(
        self,
        request: RepairRequest,
        diagnostic_codes: tuple[str, ...],
    ) -> ModelRepairResponse:
        self.calls += 1
        assert request.sanitized_fixture_digest == DIGEST_C
        assert diagnostic_codes in {(), ("portal_drift",)}
        return self.response


class Base:
    def read_package(self, package_digest: str) -> dict[str, bytes]:
        assert package_digest == DIGEST_A
        return {"manifest.json": b'{"version":1}', "tracking.recipe.json": b'{"path":"old"}'}


class Loader:
    def load(self, files: Mapping[str, bytes]) -> str:
        value = files["tracking.recipe.json"]
        assert value in {b'{"path":"old"}', b'{"path":"new"}'}
        return DIGEST_A if value == b'{"path":"old"}' else DIGEST_B


@dataclass
class Gate:
    result: GateResult

    def validate(self, package_digest: str, *, timeout_seconds: int) -> GateResult:
        assert package_digest == DIGEST_B
        assert timeout_seconds == 10
        return self.result


def _request() -> RepairRequest:
    return RepairRequest.issue(
        tenant_id="tenant-a",
        environment_id="production",
        job_id="repair-1",
        drift_report_digest=DIGEST_B,
        base_package_digest=DIGEST_A,
        sanitized_fixture_digest=DIGEST_C,
        allowed_paths=("tracking.recipe.json",),
    )


def _budget() -> RepairBudget:
    return RepairBudget.issue(
        max_model_calls=1,
        max_input_tokens=10,
        max_output_tokens=10,
        max_cost_units=10,
        max_files=1,
        max_candidate_bytes=100,
        max_validation_seconds=10,
    )


def _usage(*, files: int = 1, candidate_bytes: int = 14) -> RepairUsage:
    return RepairUsage(
        model_calls=1,
        input_tokens=1,
        output_tokens=1,
        cost_units=1,
        files=files,
        candidate_bytes=candidate_bytes,
        validation_seconds=2,
    )


def _sandbox(*, security_passed: bool = True) -> tuple[IsolatedRepairSandbox, Model]:
    model = Model(
        ModelRepairResponse(
            base_package_digest=DIGEST_A,
            replacements={"tracking.recipe.json": b'{"path":"new"}'},
            usage=_usage(),
        )
    )
    tck = Gate(GateResult(True, ("tck_passed",), DIGEST_B, duration_seconds=1))
    security = Gate(
        GateResult(
            security_passed,
            ("security_passed",),
            DIGEST_C,
            () if security_passed else ("security_gate_failed",),
            1,
        )
    )
    return (
        IsolatedRepairSandbox(
            model_gateway=model,
            base_packages=Base(),
            package_loader=Loader(),
            tck_gate=tck,
            security_gate=security,
            budget_ledger=SQLiteRepairBudgetLedger(),
        ),
        model,
    )


def test_sandbox_builds_proposal_only_after_loader_tck_and_security_gates() -> None:
    sandbox, model = _sandbox()
    outcome = sandbox.generate_and_validate(
        _request(),
        _budget(),
        _usage(),
        attempt_id="attempt-1",
        diagnostic_codes=("portal_drift",),
    )

    assert model.calls == 1
    assert outcome.validation.passed is True
    assert outcome.proposal is not None
    assert outcome.candidate.changed_paths == ("tracking.recipe.json",)
    assert "new" not in outcome.candidate.model_dump_json()
    with pytest.raises(RepairSandboxError) as replay:
        sandbox.generate_and_validate(
            _request(),
            _budget(),
            _usage(),
            attempt_id="attempt-1",
            diagnostic_codes=("portal_drift",),
        )
    assert replay.value.code == "repair_attempt_replayed"
    assert model.calls == 1


def test_sandbox_rejects_forbidden_path_and_never_proposes_on_security_failure() -> None:
    sandbox, _ = _sandbox(security_passed=False)
    outcome = sandbox.generate_and_validate(
        _request(),
        _budget(),
        _usage(),
        attempt_id="attempt-1",
        diagnostic_codes=("portal_drift",),
    )
    assert outcome.validation.passed is False
    assert outcome.proposal is None

    bad_model = Model(
        ModelRepairResponse(
            base_package_digest=DIGEST_A,
            replacements={"../adapter.py": b"{}"},
            usage=_usage(candidate_bytes=2),
        )
    )
    bad = IsolatedRepairSandbox(
        model_gateway=bad_model,
        base_packages=Base(),
        package_loader=Loader(),
        tck_gate=Gate(GateResult(True, ("tck_passed",), DIGEST_B)),
        security_gate=Gate(GateResult(True, ("security_passed",), DIGEST_C)),
        budget_ledger=SQLiteRepairBudgetLedger(),
    )
    with pytest.raises(RepairSandboxError) as forbidden:
        bad.generate_and_validate(
            _request(),
            _budget(),
            _usage(candidate_bytes=2),
            attempt_id="attempt-2",
        )
    assert forbidden.value.code == "candidate_path_forbidden"


def test_base_provider_failure_is_sanitized_before_model_call() -> None:
    class BrokenBase:
        def read_package(self, package_digest: str) -> Mapping[str, bytes]:
            del package_digest
            raise RuntimeError("credential=must-not-leak")

    sandbox, model = _sandbox()
    sandbox._base_packages = BrokenBase()
    with pytest.raises(RepairSandboxError) as caught:
        sandbox.generate_and_validate(
            _request(), _budget(), _usage(), attempt_id="attempt-provider"
        )
    assert caught.value.code == "base_package_invalid"
    assert "must-not-leak" not in str(caught.value)
    assert model.calls == 0
