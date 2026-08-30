from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import patch

from temporalio.exceptions import ActivityError, ApplicationError

from cargomesh.ir.enums import RiskClass, VerificationLevel
from cargomesh.runtime.models import (
    AdapterInvocation,
    AdapterResult,
    CompensationSpec,
    ExecutionPlan,
    ExecutionStatus,
    ExecutionStep,
    RetryPolicySpec,
)
from cargomesh.runtime.temporal import CargoMeshTransactionWorkflow
from cargomesh.verification.activities import VERIFY_TRANSACTION_ACTIVITY
from cargomesh.verification.models import (
    ClaimOutcome,
    ClaimResult,
    EvidenceChannel,
    EvidenceCollectionSpec,
    EvidenceReceiptSummary,
    VerificationClaimRule,
    VerificationPlan,
    VerificationReport,
    VerificationVerdict,
)


def activity_error(code: str) -> ActivityError:
    error = ActivityError(
        "failed",
        scheduled_event_id=1,
        started_event_id=2,
        identity="test",
        activity_type="adapter",
        activity_id="write",
        retry_state=None,
    )
    error.__cause__ = ApplicationError("bounded failure", type=code, non_retryable=True)
    return error


def report(verdict: VerificationVerdict = VerificationVerdict.VERIFIED) -> VerificationReport:
    return VerificationReport.issue(
        transaction_id="txn-1",
        business_digest="sha256:" + "a" * 64,
        verdict=verdict,
        required_level=VerificationLevel.L2,
        achieved_level=VerificationLevel.L2,
        evaluated_at=datetime(2026, 1, 1, tzinfo=UTC),
        reasons=("ledger_readback",),
        evidence=(
            EvidenceReceiptSummary(
                evidence_id="evidence-1",
                source_record_id="booking-1",
                source_system="synthetic.booking.ledger",
                channel=EvidenceChannel.SYSTEM_RECORD,
                collector_id="synthetic.booking.ledger",
                collection_id="collection-1",
                observed_at=datetime(2026, 1, 1, tzinfo=UTC),
                content_digest="sha256:" + "b" * 64,
            ),
        ),
        claims=(
            ClaimResult(
                claim="booking.status",
                outcome=ClaimOutcome.MATCH,
                expected="RECEIVED",
                observed=("RECEIVED",),
            ),
        ),
    )


def verification() -> VerificationPlan:
    return VerificationPlan(
        required_level=VerificationLevel.L2,
        collectors=(
            EvidenceCollectionSpec(
                step_id="collect-booking-ledger",
                collector_id="synthetic.booking.ledger",
                operation="fetch",
            ),
        ),
        claim_rules=(
            VerificationClaimRule(
                claim="booking.status",
                expected_pointer="/transaction/parameters/expected_status",
            ),
        ),
    )


def execution_plan(
    *steps: ExecutionStep, verification_plan: VerificationPlan | None = None
) -> ExecutionPlan:
    maximum_risk = (
        RiskClass.CONSEQUENTIAL_WRITE
        if any(step.risk_class is RiskClass.CONSEQUENTIAL_WRITE for step in steps)
        else RiskClass.REVERSIBLE_WRITE
    )
    return ExecutionPlan(
        transaction_id="txn-1",
        tenant_id="tenant-a",
        business_digest="sha256:" + "a" * 64,
        risk_class=maximum_risk,
        verification_level=VerificationLevel.L2,
        steps=steps,
        verification=verification_plan,
    )


def unknown_write() -> ExecutionStep:
    return ExecutionStep(
        step_id="submit-booking",
        capability="booking.submit",
        adapter="synthetic.booking.api",
        operation="create",
        risk_class=RiskClass.CONSEQUENTIAL_WRITE,
        input={"transaction": {"external_reference": "customer-1"}},
        retry=RetryPolicySpec(maximum_attempts=1),
        unknown_effect_error_codes=("booking_effect_unknown",),
    )


def test_unknown_effect_is_read_back_without_resubmit_or_compensation() -> None:
    calls: list[str] = []

    async def invoke(activity: str, _invocation: object, **_options: object) -> object:
        calls.append(activity)
        if activity == VERIFY_TRANSACTION_ACTIVITY:
            return report()
        raise activity_error("booking_effect_unknown")

    workflow = CargoMeshTransactionWorkflow()
    with (
        patch(
            "cargomesh.runtime.temporal.workflow.info",
            return_value=SimpleNamespace(workflow_id="wf-1"),
        ),
        patch("cargomesh.runtime.temporal.workflow.execute_activity", side_effect=invoke),
    ):
        result = asyncio.run(
            workflow.run(execution_plan(unknown_write(), verification_plan=verification()))
        )

    assert result.status is ExecutionStatus.VERIFIED
    assert result.failure_code == "booking_effect_unknown"
    assert calls == ["cargomesh.execute-adapter", VERIFY_TRANSACTION_ACTIVITY]


def test_unknown_effect_without_verification_halts_without_retry() -> None:
    calls = 0

    async def invoke(_activity: str, _invocation: object, **_options: object) -> object:
        nonlocal calls
        calls += 1
        raise activity_error("booking_effect_unknown")

    workflow = CargoMeshTransactionWorkflow()
    with (
        patch(
            "cargomesh.runtime.temporal.workflow.info",
            return_value=SimpleNamespace(workflow_id="wf-1"),
        ),
        patch("cargomesh.runtime.temporal.workflow.execute_activity", side_effect=invoke),
    ):
        result = asyncio.run(workflow.run(execution_plan(unknown_write())))

    assert result.status is ExecutionStatus.HALTED
    assert calls == 1


def test_compensation_receives_only_a_recorded_effect_reference() -> None:
    invocations: list[AdapterInvocation] = []

    async def invoke(
        _activity: str, invocation: AdapterInvocation, **_options: object
    ) -> AdapterResult:
        invocations.append(invocation)
        if invocation.operation == "fail":
            raise activity_error("bounded_failure")
        return AdapterResult(effect_reference="CBRR-100")

    reversible = ExecutionStep(
        step_id="write",
        capability="booking.submit",
        adapter="synthetic.booking.api",
        operation="create",
        risk_class=RiskClass.REVERSIBLE_WRITE,
        compensation=CompensationSpec(
            adapter="synthetic.booking.api",
            operation="cancel",
            capability="booking.cancel",
            include_effect_reference=True,
        ),
    )
    failing = ExecutionStep(
        step_id="fail",
        capability="booking.draft.prepare",
        adapter="test.adapter",
        operation="fail",
        depends_on=("write",),
    )
    workflow = CargoMeshTransactionWorkflow()
    with (
        patch(
            "cargomesh.runtime.temporal.workflow.info",
            return_value=SimpleNamespace(workflow_id="wf-1"),
        ),
        patch("cargomesh.runtime.temporal.workflow.execute_activity", side_effect=invoke),
    ):
        result = asyncio.run(workflow.run(execution_plan(reversible, failing)))

    assert result.status is ExecutionStatus.HALTED
    assert invocations[-1].operation == "cancel"
    assert invocations[-1].capability == "booking.cancel"
    assert invocations[-1].input == {"effect_reference": "CBRR-100"}


def test_compensation_never_guesses_a_missing_effect_reference() -> None:
    invocations: list[AdapterInvocation] = []

    async def invoke(
        _activity: str, invocation: AdapterInvocation, **_options: object
    ) -> AdapterResult:
        invocations.append(invocation)
        raise activity_error("bounded_failure")

    write = ExecutionStep(
        step_id="write",
        capability="booking.submit",
        adapter="synthetic.booking.api",
        operation="create",
        risk_class=RiskClass.REVERSIBLE_WRITE,
        compensation=CompensationSpec(
            adapter="synthetic.booking.api",
            operation="cancel",
            capability="booking.cancel",
            include_effect_reference=True,
        ),
    )
    workflow = CargoMeshTransactionWorkflow()
    with (
        patch(
            "cargomesh.runtime.temporal.workflow.info",
            return_value=SimpleNamespace(workflow_id="wf-1"),
        ),
        patch("cargomesh.runtime.temporal.workflow.execute_activity", side_effect=invoke),
    ):
        result = asyncio.run(workflow.run(execution_plan(write)))

    assert result.status is ExecutionStatus.HALTED
    assert result.failure_code == "compensation_reference_missing"
    assert [invocation.operation for invocation in invocations] == ["create"]
