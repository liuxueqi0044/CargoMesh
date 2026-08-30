"""Safety-reviewed execution plan for the synthetic Booking vertical slice."""

from __future__ import annotations

from typing import cast

from pydantic import JsonValue

from cargomesh.ir import BookingParameters, BookingSubject, TransactionCommand
from cargomesh.ir.enums import RiskClass, TransactionType
from cargomesh.runtime.models import (
    CompensationSpec,
    ExecutionPlan,
    ExecutionStep,
    RetryPolicySpec,
)
from cargomesh.verification.models import (
    EvidenceCollectionSpec,
    VerificationClaimRule,
    VerificationPlan,
)


class SyntheticBookingPlanner:
    """Compile one approved, idempotent, independently verified booking write."""

    def build(
        self,
        command: TransactionCommand,
        *,
        transaction_id: str,
        business_digest: str,
    ) -> ExecutionPlan:
        if (
            command.transaction_type is not TransactionType.BOOKING_CREATE
            or not isinstance(command.subject, BookingSubject)
            or not isinstance(command.parameters, BookingParameters)
        ):
            raise ValueError("synthetic booking planner only accepts booking.create")
        if command.subject.carrier_profile != "synthetic.dcsa.booking":
            raise ValueError("synthetic booking planner requires the explicit synthetic profile")
        transaction = cast(
            dict[str, JsonValue],
            command.model_dump(mode="json", exclude={"transaction_id", "requested_at"}),
        )
        prepare = ExecutionStep(
            step_id="prepare-booking-draft",
            capability="booking.draft.prepare",
            adapter="synthetic.booking.draft",
            operation="prepare",
            risk_class=RiskClass.READ_ONLY,
            input={"transaction": transaction},
            retry=RetryPolicySpec(maximum_attempts=1),
        )
        submit = ExecutionStep(
            step_id="submit-booking",
            capability="booking.submit",
            adapter="synthetic.booking.api",
            operation="submit",
            risk_class=RiskClass.CONSEQUENTIAL_WRITE,
            input={"transaction": transaction},
            depends_on=(prepare.step_id,),
            retry=RetryPolicySpec(
                maximum_attempts=1,
                non_retryable_error_types=(
                    "booking_effect_unknown",
                    "booking_schema_rejected",
                ),
            ),
            requires_approval=True,
            approval_timeout_seconds=86_400,
            compensation=CompensationSpec(
                adapter="synthetic.booking.api",
                operation="cancel",
                capability="booking.cancel",
                risk_class=RiskClass.REVERSIBLE_WRITE,
                include_effect_reference=True,
                retry=RetryPolicySpec(maximum_attempts=1),
            ),
            unknown_effect_error_codes=("booking_effect_unknown",),
        )
        verification = VerificationPlan(
            required_level=command.verification_requirements.minimum_independence_level,
            collectors=(
                EvidenceCollectionSpec(
                    step_id="collect-booking-ledger",
                    collector_id="synthetic.booking.ledger",
                    operation="fetch",
                    input={"external_reference": command.external_reference},
                ),
            ),
            claim_rules=(
                VerificationClaimRule(
                    claim="booking.external_reference",
                    expected_pointer="/transaction/external_reference",
                ),
                VerificationClaimRule(
                    claim="booking.status",
                    expected_pointer="/transaction/parameters/expected_status",
                ),
            ),
        )
        return ExecutionPlan(
            transaction_id=transaction_id,
            tenant_id=command.tenant_id,
            business_digest=business_digest,
            risk_class=RiskClass.CONSEQUENTIAL_WRITE,
            verification_level=command.verification_requirements.minimum_independence_level,
            steps=(prepare, submit),
            verification=verification,
        )


def synthetic_booking_planner() -> SyntheticBookingPlanner:
    return SyntheticBookingPlanner()


__all__ = ["SyntheticBookingPlanner", "synthetic_booking_planner"]
