from __future__ import annotations

import pytest
from pydantic import ValidationError

from cargomesh.booking.contracts import map_ir_to_booking


def _parameters() -> dict[str, object]:
    return {
        "receipt_type_at_origin": "CY",
        "delivery_type_at_destination": "CY",
        "cargo_movement_type_at_origin": "FCL",
        "cargo_movement_type_at_destination": "FCL",
        "service_contract_reference": "SVC-1",
        "is_equipment_substitution_allowed": False,
        "shipment_locations": [
            {"location_type_code": "POL", "un_location_code": "NLAMS"},
            {"location_type_code": "POD", "un_location_code": "USNYC"},
        ],
        "requested_equipments": [
            {
                "iso_equipment_code": "22G1",
                "units": 1,
                "is_shipper_owned": False,
                "cargo_gross_weight": {"value": 100, "unit": "KGM"},
                "commodities": [{"commodity_type": "Widgets"}],
            }
        ],
        "booking_agent": {"party_name": "Agent"},
    }


def test_mapper_emits_exact_dcsa_create_shape() -> None:
    request = map_ir_to_booking({"parameters": _parameters()})
    assert request.to_dcsa() == {
        "receiptTypeAtOrigin": "CY",
        "deliveryTypeAtDestination": "CY",
        "cargoMovementTypeAtOrigin": "FCL",
        "cargoMovementTypeAtDestination": "FCL",
        "serviceContractReference": "SVC-1",
        "isEquipmentSubstitutionAllowed": False,
        "shipmentLocations": [
            {"location": {"UNLocationCode": "NLAMS"}, "locationTypeCode": "POL"},
            {"location": {"UNLocationCode": "USNYC"}, "locationTypeCode": "POD"},
        ],
        "requestedEquipments": [
            {
                "ISOEquipmentCode": "22G1",
                "units": 1,
                "isShipperOwned": False,
                "cargoGrossWeight": {"value": 100.0, "unit": "KGM"},
                "commodities": [{"commodityType": "Widgets"}],
            }
        ],
        "documentParties": {"bookingAgent": {"partyName": "Agent"}},
    }


def test_contract_rejects_wrong_locations_contract_and_weight() -> None:
    values = _parameters()
    values["service_contract_reference"] = None
    values["extended_contract_quotation_reference"] = None
    with pytest.raises((ValidationError, ValueError)):
        map_ir_to_booking({"parameters": values})

    values = _parameters()
    values["shipment_locations"] = [
        {"location_type_code": "POL", "un_location_code": "NLAMS"},
        {"location_type_code": "POL", "un_location_code": "USNYC"},
    ]
    with pytest.raises((ValidationError, ValueError)):
        map_ir_to_booking({"parameters": values})


def test_extended_quotation_supersedes_deprecated_reference() -> None:
    values = _parameters()
    values.pop("service_contract_reference")
    values["contract_quotation_reference"] = "OLD"
    values["extended_contract_quotation_reference"] = "NEW"
    wire = map_ir_to_booking({"parameters": values}).to_dcsa()
    assert wire["extendedContractQuotationReference"] == "NEW"
    assert "contractQuotationReference" not in wire
