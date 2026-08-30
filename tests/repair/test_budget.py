"""Transactional and isolation tests for the repair budget ledger."""

from concurrent.futures import ThreadPoolExecutor

import pytest

from cargomesh.repair.budget import (
    BudgetConflict,
    BudgetExceeded,
    RepairBudgetError,
    SQLiteRepairBudgetLedger,
)
from cargomesh.repair.models import RepairBudget, RepairRequest, RepairUsage


def digest(seed: str) -> str:
    import hashlib

    return "sha256:" + hashlib.sha256(seed.encode()).hexdigest()


def request(
    *, tenant: str = "tenant-a", environment: str = "staging", job: str = "job-1"
) -> RepairRequest:
    return RepairRequest.issue(
        tenant_id=tenant,
        environment_id=environment,
        job_id=job,
        drift_report_digest=digest(f"drift-{tenant}-{environment}-{job}"),
        base_package_digest=digest("base"),
        sanitized_fixture_digest=digest("fixture"),
        allowed_paths=("adapter/config.json",),
    )


def budget(*, calls: int = 2) -> RepairBudget:
    return RepairBudget.issue(
        max_model_calls=calls,
        max_input_tokens=100,
        max_output_tokens=100,
        max_cost_units=20,
        max_files=2,
        max_candidate_bytes=1000,
        max_validation_seconds=30,
    )


def usage(*, calls: int = 1) -> RepairUsage:
    return RepairUsage(
        model_calls=calls,
        input_tokens=10,
        output_tokens=5,
        cost_units=2,
        files=1,
        candidate_bytes=20,
        validation_seconds=1,
    )


def test_reserve_replay_conflict_and_finalize(tmp_path) -> None:
    ledger = SQLiteRepairBudgetLedger(tmp_path / "budget.sqlite3")
    req = request()
    plan = budget(calls=2)
    first = ledger.reserve(req, plan, usage(), reservation_id="r-1")
    assert first.status == "RESERVED"
    assert ledger.reserve(req, plan, usage(), reservation_id="r-1") == first

    with pytest.raises(BudgetConflict) as conflict:
        ledger.reserve(req, plan, usage(calls=2), reservation_id="r-1")
    assert conflict.value.code == "budget_conflict"

    finalized = ledger.finalize(first, usage(calls=0))
    assert finalized.status == "FINALIZED"
    assert finalized.actual == usage(calls=0)
    assert ledger.finalize(first, usage(calls=0)) == finalized
    with pytest.raises(BudgetConflict):
        ledger.finalize(first, usage(calls=1))

    assert (
        ledger.get(
            "r-1", tenant_id=req.tenant_id, environment_id=req.environment_id, job_id=req.job_id
        )
        == finalized
    )
    assert (
        ledger.get("r-1", tenant_id="other", environment_id=req.environment_id, job_id=req.job_id)
        is None
    )
    ledger.close()


def test_reserve_is_scoped_and_budget_cannot_change(tmp_path) -> None:
    ledger = SQLiteRepairBudgetLedger(tmp_path / "budget.sqlite3")
    req = request()
    ledger.reserve(req, budget(calls=2), usage(), reservation_id="r-1")
    with pytest.raises(BudgetConflict):
        ledger.reserve(req, budget(calls=10), usage(), reservation_id="r-2")

    other_scope = request(tenant="tenant-b")
    assert (
        ledger.reserve(other_scope, budget(calls=2), usage(), reservation_id="r-2").tenant_id
        == "tenant-b"
    )
    ledger.close()


def test_request_digest_is_frozen_for_one_scoped_job(tmp_path) -> None:
    ledger = SQLiteRepairBudgetLedger(tmp_path / "budget-request.sqlite3")
    req = request()
    plan = budget(calls=2)
    ledger.reserve(req, plan, usage(), reservation_id="r-1")
    changed = RepairRequest.issue(
        tenant_id=req.tenant_id,
        environment_id=req.environment_id,
        job_id=req.job_id,
        drift_report_digest=digest("different-drift"),
        base_package_digest=req.base_package_digest,
        sanitized_fixture_digest=req.sanitized_fixture_digest,
        allowed_paths=req.allowed_paths,
    )
    with pytest.raises(BudgetConflict):
        ledger.reserve(changed, plan, usage(), reservation_id="r-2")
    ledger.close()


def test_over_budget_and_finalize_over_reservation_fail_closed(tmp_path) -> None:
    ledger = SQLiteRepairBudgetLedger(tmp_path / "budget.sqlite3")
    req = request()
    plan = budget(calls=1)
    first = ledger.reserve(req, plan, usage(), reservation_id="r-1")
    with pytest.raises(BudgetExceeded) as exceeded:
        ledger.reserve(req, plan, usage(), reservation_id="r-2")
    assert exceeded.value.code == "budget_exceeded"
    with pytest.raises(BudgetExceeded):
        ledger.finalize(first, usage(calls=2))
    ledger.close()


def test_tampered_record_is_not_returned(tmp_path) -> None:
    ledger = SQLiteRepairBudgetLedger(tmp_path / "budget.sqlite3")
    req = request()
    ledger.reserve(req, budget(), usage(), reservation_id="r-1")
    ledger._connection.execute(  # type: ignore[attr-defined]
        "UPDATE repair_budget_reservations SET reserved_json=? WHERE reservation_id=?",
        (usage(calls=2).model_dump_json(), "r-1"),
    )
    with pytest.raises(RepairBudgetError) as invalid:
        ledger.get(
            "r-1", tenant_id=req.tenant_id, environment_id=req.environment_id, job_id=req.job_id
        )
    assert invalid.value.code == "budget_record_invalid"
    ledger.close()


def test_concurrent_reservations_are_atomic(tmp_path) -> None:
    ledger = SQLiteRepairBudgetLedger(tmp_path / "budget.sqlite3")
    req = request()
    plan = budget(calls=1)

    def reserve(index: int) -> str:
        try:
            ledger.reserve(req, plan, usage(), reservation_id=f"r-{index}")
            return "ok"
        except BudgetExceeded:
            return "exceeded"

    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(pool.map(reserve, range(8)))
    assert outcomes.count("ok") == 1
    assert outcomes.count("exceeded") == 7
    ledger.close()
