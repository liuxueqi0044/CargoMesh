from __future__ import annotations

import pytest
from pydantic import ValidationError

from cargomesh.ir.enums import RiskClass, VerificationLevel
from cargomesh.runtime import (
    CompensationSpec,
    ExecutionPlan,
    ExecutionStatus,
    ExecutionStep,
    InvalidExecutionTransition,
    RouteFallbackSpec,
    transition,
)


def plan_with(*steps: ExecutionStep, risk: RiskClass = RiskClass.READ_ONLY) -> ExecutionPlan:
    return ExecutionPlan(
        transaction_id="txn-1",
        tenant_id="tenant-a",
        business_digest="sha256:" + "a" * 64,
        risk_class=risk,
        verification_level=VerificationLevel.L1,
        steps=steps,
    )


def test_plan_rejects_forward_dependencies_and_secret_material() -> None:
    with pytest.raises(ValidationError, match="unknown or forward dependencies"):
        plan_with(
            ExecutionStep(
                step_id="second",
                capability="shipment.track.read",
                adapter="synthetic.track",
                operation="fetch",
                depends_on=("first",),
            ),
            ExecutionStep(
                step_id="first",
                capability="shipment.track.read",
                adapter="synthetic.track",
                operation="fetch",
            ),
        )

    with pytest.raises(ValidationError, match="secret material"):
        ExecutionStep(
            step_id="fetch",
            capability="shipment.track.read",
            adapter="synthetic.track",
            operation="fetch",
            input={"auth_token": "do-not-persist"},
        )


def test_read_only_plan_rejects_compensation() -> None:
    with pytest.raises(ValidationError, match="read-only"):
        plan_with(
            ExecutionStep(
                step_id="fetch",
                capability="shipment.track.read",
                adapter="synthetic.track",
                operation="fetch",
                compensation=CompensationSpec(
                    adapter="synthetic.track", operation="undo"
                ),
            )
        )


def test_effectful_step_rejects_automatic_route_fallback() -> None:
    with pytest.raises(ValidationError, match="restricted to read-only"):
        ExecutionStep(
            step_id="write",
            capability="booking.create",
            adapter="carrier.api",
            operation="create",
            risk_class=RiskClass.REVERSIBLE_WRITE,
            route_candidate_id="carrier.api",
            fallback_on_error_codes=("api_timeout",),
            route_fallbacks=(
                RouteFallbackSpec(
                    candidate_id="carrier.browser",
                    adapter="carrier.browser",
                    operation="create",
                ),
            ),
        )


def test_state_machine_is_explicit_and_terminal() -> None:
    assert transition(ExecutionStatus.ACCEPTED, ExecutionStatus.RUNNING) is ExecutionStatus.RUNNING
    assert (
        transition(ExecutionStatus.RUNNING, ExecutionStatus.EXECUTED_UNVERIFIED)
        is ExecutionStatus.EXECUTED_UNVERIFIED
    )
    assert (
        transition(ExecutionStatus.RUNNING, ExecutionStatus.VERIFYING)
        is ExecutionStatus.VERIFYING
    )
    assert (
        transition(ExecutionStatus.VERIFYING, ExecutionStatus.VERIFIED)
        is ExecutionStatus.VERIFIED
    )
    with pytest.raises(InvalidExecutionTransition):
        transition(ExecutionStatus.EXECUTED_UNVERIFIED, ExecutionStatus.RUNNING)
