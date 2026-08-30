from __future__ import annotations

import pytest
from pydantic import ValidationError

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
    TransactionCommand,
    TransactionType,
    VerificationLevel,
    VerificationRequirements,
)


def parameters(**updates: object) -> BookingParameters:
    values: dict[str, object] = {
        "receipt_type_at_origin": "CY",
        "delivery_type_at_destination": "CY",
        "cargo_movement_type_at_origin": "FCL",
        "cargo_movement_type_at_destination": "FCL",
        "service_contract_reference": "SC-100",
        "is_equipment_substitution_allowed": False,
        "shipment_locations": (
            BookingLocation(location_type_code="POL", un_location_code="CNSGH"),
            BookingLocation(location_type_code="POD", un_location_code="NLRTM"),
        ),
        "requested_equipments": (
            RequestedBookingEquipment(
                iso_equipment_code="22G1",
                units=1,
                is_shipper_owned=False,
                cargo_gross_weight=CargoGrossWeight(value=12_000, unit="KGM"),
                commodities=(BookingCommodity(commodity_type="Mobile phones"),),
            ),
        ),
        "booking_agent": BookingAgent(party_name="CargoMesh Test Agent"),
    }
    values.update(updates)
    return BookingParameters.model_validate(values)


def command(**updates: object) -> TransactionCommand:
    values: dict[str, object] = {
        "tenant_id": "tenant-a",
        "transaction_type": TransactionType.BOOKING_CREATE,
        "external_reference": "customer-booking-100",
        "subject": BookingSubject(carrier_profile="synthetic.dcsa.booking"),
        "parameters": parameters(),
        "requested_effects": (
            RequestedEffect.BOOKING_REQUEST_ACCEPTED,
            RequestedEffect.BOOKING_RECEIVED_VERIFIED,
        ),
        "verification_requirements": VerificationRequirements(
            minimum_independence_level=VerificationLevel.L2
        ),
        "risk_class": RiskClass.CONSEQUENTIAL_WRITE,
        "required_capabilities": (
            Capability.BOOKING_DRAFT_PREPARE,
            Capability.BOOKING_SUBMIT,
        ),
    }
    values.update(updates)
    return TransactionCommand.model_validate(values)


def test_booking_command_is_a_strict_consequential_write_bundle() -> None:
    booking = command()

    assert booking.transaction_type is TransactionType.BOOKING_CREATE
    assert booking.risk_class is RiskClass.CONSEQUENTIAL_WRITE
    assert booking.verification_requirements.minimum_independence_level is VerificationLevel.L2


def test_booking_contract_reference_is_exclusive() -> None:
    with pytest.raises(ValidationError, match="exactly one"):
        parameters(
            service_contract_reference="SC-100",
            extended_contract_quotation_reference="QUOTE-100",
        )


def test_booking_requires_one_pol_and_one_pod() -> None:
    with pytest.raises(ValidationError, match="exactly one POL"):
        parameters(
            shipment_locations=(
                BookingLocation(location_type_code="POL", un_location_code="CNSGH"),
                BookingLocation(location_type_code="POL", un_location_code="CNNGB"),
            )
        )


def test_booking_rejects_low_independence_verification() -> None:
    with pytest.raises(ValidationError, match="verification level L2"):
        command(
            verification_requirements=VerificationRequirements(
                minimum_independence_level=VerificationLevel.L1
            )
        )


def test_tracking_defaults_cannot_be_relabelled_as_booking() -> None:
    with pytest.raises(ValidationError, match=r"booking\.create requires booking"):
        TransactionCommand(
            tenant_id="tenant-a",
            transaction_type=TransactionType.BOOKING_CREATE,
            external_reference="bad",
            subject=BookingSubject(carrier_profile="synthetic.dcsa.booking"),
        )
