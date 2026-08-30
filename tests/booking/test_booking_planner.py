from __future__ import annotations

import asyncio

import pytest

from cargomesh.booking.draft import BookingDraftAdapter
from cargomesh.booking.planner import synthetic_booking_planner
from cargomesh.ir import (
    BookingAgent,
    BookingCommodity,
    BookingLocation,
    BookingParameters,
    BookingSubject,
    Capability,
    CargoGrossWeight,
    RequestedBookingEquipment,
    RequestedEffect,
    RiskClass,
    ShipmentSubject,
    TransactionCommand,
    TransactionType,
    VerificationLevel,
    VerificationRequirements,
)
from cargomesh.runtime.models import AdapterInvocation


def booking() -> TransactionCommand:
    return TransactionCommand(
        tenant_id="tenant-a",
        transaction_type=TransactionType.BOOKING_CREATE,
        external_reference="customer-booking-100",
        subject=BookingSubject(carrier_profile="synthetic.dcsa.booking"),
        parameters=BookingParameters(
            receipt_type_at_origin="CY",
            delivery_type_at_destination="CY",
            cargo_movement_type_at_origin="FCL",
            cargo_movement_type_at_destination="FCL",
            service_contract_reference="SC-100",
            is_equipment_substitution_allowed=False,
            shipment_locations=(
                BookingLocation(location_type_code="POL", un_location_code="CNSGH"),
                BookingLocation(location_type_code="POD", un_location_code="NLRTM"),
            ),
            requested_equipments=(
                RequestedBookingEquipment(
                    iso_equipment_code="22G1",
                    units=1,
                    is_shipper_owned=False,
                    cargo_gross_weight=CargoGrossWeight(value=12_000, unit="KGM"),
                    commodities=(BookingCommodity(commodity_type="Mobile phones"),),
                ),
            ),
            booking_agent=BookingAgent(party_name="CargoMesh Test Agent"),
        ),
        requested_effects=(
            RequestedEffect.BOOKING_REQUEST_ACCEPTED,
            RequestedEffect.BOOKING_RECEIVED_VERIFIED,
        ),
        verification_requirements=VerificationRequirements(
            minimum_independence_level=VerificationLevel.L2
        ),
        risk_class=RiskClass.CONSEQUENTIAL_WRITE,
        required_capabilities=(
            Capability.BOOKING_DRAFT_PREPARE,
            Capability.BOOKING_SUBMIT,
        ),
    )


def test_plan_freezes_approval_single_attempt_recovery_and_independent_evidence() -> None:
    plan = synthetic_booking_planner().build(
        booking(), transaction_id="txn-1", business_digest="sha256:" + "a" * 64
    )

    assert [step.step_id for step in plan.steps] == [
        "prepare-booking-draft",
        "submit-booking",
    ]
    submit = plan.steps[1]
    assert submit.requires_approval is True
    assert submit.retry.maximum_attempts == 1
    assert submit.route_fallbacks == ()
    assert submit.unknown_effect_error_codes == ("booking_effect_unknown",)
    assert submit.compensation is not None
    assert submit.compensation.capability == "booking.cancel"
    assert submit.compensation.include_effect_reference is True
    assert plan.verification is not None
    assert plan.verification.required_level is VerificationLevel.L2
    assert plan.verification.collectors[0].collector_id == "synthetic.booking.ledger"


def test_planner_rejects_tracking_and_non_synthetic_profiles() -> None:
    planner = synthetic_booking_planner()
    with pytest.raises(ValueError, match="only accepts"):
        planner.build(
            TransactionCommand(
                tenant_id="tenant-a",
                external_reference="track-1",
                subject=ShipmentSubject(carrier_booking_reference="CBR-1"),
            ),
            transaction_id="txn-1",
            business_digest="sha256:" + "a" * 64,
        )
    with pytest.raises(ValueError, match="explicit synthetic"):
        planner.build(
            booking().model_copy(
                update={"subject": BookingSubject(carrier_profile="real.carrier")}
            ),
            transaction_id="txn-1",
            business_digest="sha256:" + "a" * 64,
        )


def test_draft_adapter_validates_and_fingerprints_without_an_effect() -> None:
    transaction = booking().model_dump(mode="json", exclude={"transaction_id", "requested_at"})
    result = asyncio.run(
        BookingDraftAdapter().execute(
            AdapterInvocation(
                transaction_id="txn-1",
                tenant_id="tenant-a",
                step_id="prepare-booking-draft",
                capability="booking.draft.prepare",
                adapter="synthetic.booking.draft",
                operation="prepare",
                input={"transaction": transaction},
            )
        )
    )

    assert result.output["synthetic"] is True
    assert str(result.output["draft_digest"]).startswith("sha256:")
    assert result.effect_reference is None
