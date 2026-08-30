"""Strict, reviewed minimum DCSA Booking 2.0.5 wire contracts.

The Python names are deliberately snake_case, while ``to_dcsa`` emits only
the names from the pinned BKG OpenAPI document.  The mapper accepts the
future IR's snake_case transaction representation and does not pass unknown
transaction data through to a carrier.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

BookingIdentifier = Annotated[
    str, StringConstraints(strip_whitespace=True, min_length=1, max_length=256)
]
BookingCode = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=64,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$",
    ),
]
ContractReference = Annotated[
    str, StringConstraints(strip_whitespace=True, min_length=1, max_length=30)
]
QuotationReference = Annotated[
    str, StringConstraints(strip_whitespace=True, min_length=1, max_length=35)
]
ExtendedQuotationReference = Annotated[
    str, StringConstraints(strip_whitespace=True, min_length=1, max_length=70)
]
EquipmentCode = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=4)]
CarrierReference = Annotated[
    str, StringConstraints(strip_whitespace=True, min_length=1, max_length=100)
]


class BookingModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=True,
        str_strip_whitespace=True,
    )


class BookingLocation(BookingModel):
    """The minimum DCSA ``Location`` form, identified by UN/LOCODE."""

    un_location_code: Annotated[
        str, StringConstraints(strip_whitespace=True, min_length=5, max_length=5)
    ] = Field(alias="UNLocationCode", pattern=r"^[A-Z]{2}[A-Z2-9]{3}$")


class BookingShipmentLocation(BookingModel):
    location: BookingLocation
    location_type_code: Literal["POL", "POD"] = Field(alias="locationTypeCode")


class BookingWeight(BookingModel):
    value: float = Field(gt=0, le=100_000_000)
    unit: Literal["KGM", "LBR"]


class BookingCommodity(BookingModel):
    commodity_type: Annotated[
        str, StringConstraints(strip_whitespace=True, min_length=1, max_length=550)
    ] = Field(alias="commodityType")
    cargo_gross_weight: BookingWeight | None = Field(default=None, alias="cargoGrossWeight")


class BookingEquipment(BookingModel):
    equipment_size_type: EquipmentCode = Field(alias="ISOEquipmentCode")
    units: int = Field(ge=1, le=10_000)
    is_shipper_owned: bool = Field(alias="isShipperOwned")
    cargo_gross_weight: BookingWeight | None = Field(default=None, alias="cargoGrossWeight")
    commodities: tuple[BookingCommodity, ...] = Field(min_length=1, max_length=32)

    @model_validator(mode="after")
    def validate_weight(self) -> BookingEquipment:
        if self.cargo_gross_weight is None and any(
            commodity.cargo_gross_weight is None for commodity in self.commodities
        ):
            raise ValueError("equipment cargo weight is missing")
        return self


class BookingAgent(BookingModel):
    """DCSA ``BookingAgent`` nested in ``documentParties``."""

    party_name: Annotated[
        str, StringConstraints(strip_whitespace=True, min_length=1, max_length=70)
    ] = Field(alias="partyName")


# Kept as a public compatibility name for callers of the initial draft.  It
# intentionally has the exact BookingAgent wire shape; party roles are
# represented by the DCSA documentParties property, not a fabricated field.
BookingParty = BookingAgent


class BookingDocumentParties(BookingModel):
    booking_agent: BookingAgent = Field(alias="bookingAgent")


class BookingCreateRequest(BookingModel):
    """Reviewed dry-container subset of DCSA ``CreateBooking``.

    ``carrierBookingRequestReference`` is a response property in BKG 2.0.5,
    and is therefore intentionally not part of this request model.
    """

    receipt_type_at_origin: Literal["CY", "SD", "CFS"] = Field(alias="receiptTypeAtOrigin")
    delivery_type_at_destination: Literal["CY", "SD", "CFS"] = Field(
        alias="deliveryTypeAtDestination"
    )
    cargo_movement_type_at_origin: Literal["FCL", "LCL"] = Field(alias="cargoMovementTypeAtOrigin")
    cargo_movement_type_at_destination: Literal["FCL", "LCL"] = Field(
        alias="cargoMovementTypeAtDestination"
    )
    service_contract_reference: ContractReference | None = Field(
        default=None, alias="serviceContractReference"
    )
    contract_quotation_reference: QuotationReference | None = Field(
        default=None, alias="contractQuotationReference"
    )
    extended_contract_quotation_reference: ExtendedQuotationReference | None = Field(
        default=None, alias="extendedContractQuotationReference"
    )
    is_equipment_substitution_allowed: bool = Field(alias="isEquipmentSubstitutionAllowed")
    shipment_locations: tuple[BookingShipmentLocation, ...] = Field(
        min_length=2, max_length=16, alias="shipmentLocations"
    )
    requested_equipments: tuple[BookingEquipment, ...] = Field(
        min_length=1, max_length=32, alias="requestedEquipments"
    )
    document_parties: BookingDocumentParties = Field(alias="documentParties")

    @model_validator(mode="after")
    def validate_business_rules(self) -> BookingCreateRequest:
        quotation_values = (
            self.contract_quotation_reference,
            self.extended_contract_quotation_reference,
        )
        if (self.service_contract_reference is None) == all(
            value is None for value in quotation_values
        ):
            raise ValueError("exactly one service contract or quotation reference is required")
        location_types = [item.location_type_code for item in self.shipment_locations]
        if location_types.count("POL") != 1 or location_types.count("POD") != 1:
            raise ValueError("booking requires exactly one POL and exactly one POD")
        codes = [item.location.un_location_code for item in self.shipment_locations]
        if len(codes) != len(set(codes)):
            raise ValueError("booking shipment locations must be distinct")
        return self

    def to_dcsa(self) -> dict[str, Any]:
        data = self.model_dump(by_alias=True, exclude_none=True, mode="json")
        # BKG 2.0.5 deprecates contractQuotationReference.  When both
        # quotation forms are supplied, the extended form takes precedence.
        if self.extended_contract_quotation_reference is not None:
            data.pop("contractQuotationReference", None)
        return data


class BookingCreateResponse(BookingModel):
    """Exact BKG 2.0.5 POST 202 response (one property only)."""

    carrier_booking_request_reference: CarrierReference = Field(
        alias="carrierBookingRequestReference"
    )


class BookingGetResponse(BookingModel):
    carrier_booking_request_reference: CarrierReference = Field(
        alias="carrierBookingRequestReference"
    )
    booking_status: Literal[
        "RECEIVED",
        "PENDING_UPDATE",
        "UPDATE_RECEIVED",
        "CONFIRMED",
        "PENDING_AMENDMENT",
        "REJECTED",
        "DECLINED",
        "CANCELLED",
        "COMPLETED",
    ] = Field(alias="bookingStatus")


class BookingCancellationRequest(BookingModel):
    booking_status: Literal["CANCELLED"] = Field(alias="bookingStatus")


class BookingCancellationResponse(BookingModel):
    carrier_booking_request_reference: CarrierReference = Field(
        alias="carrierBookingRequestReference"
    )
    booking_status: Literal["CANCELLED"] = Field(alias="bookingStatus")


def map_ir_to_booking(transaction: dict[str, Any]) -> BookingCreateRequest:
    """Map a transaction's snake_case parameters into the exact wire model."""

    nested = transaction.get("transaction")
    if isinstance(nested, dict):
        transaction = nested
    source = transaction.get("parameters", transaction)
    if not isinstance(source, dict):
        raise ValueError("booking transaction parameters are invalid")

    def first(*keys: str) -> Any:
        for key in keys:
            if key in source:
                return source[key]
            if key in transaction:
                return transaction[key]
        return None

    raw_locations = first("shipment_locations")
    if raw_locations is None:
        # This compatibility input is accepted only by the mapper; it is
        # always converted to the DCSA shipmentLocations array.
        raw_pol = first("port_of_loading", "pol")
        raw_pod = first("port_of_discharge", "pod")
        raw_locations = [
            {"location": raw_pol, "location_type_code": "POL"},
            {"location": raw_pod, "location_type_code": "POD"},
        ]
    normalized_locations: list[dict[str, Any]] = []
    if isinstance(raw_locations, (list, tuple)):
        for item in raw_locations:
            if not isinstance(item, dict):
                normalized_locations.append(item)
                continue
            location = item.get("location")
            if location is None and item.get("un_location_code") is not None:
                location = {"un_location_code": item["un_location_code"]}
            normalized_locations.append(
                {
                    "location": location,
                    "location_type_code": item.get(
                        "location_type_code", item.get("locationTypeCode")
                    ),
                }
            )
    else:
        normalized_locations = [raw_locations]

    raw_equipments = first("requested_equipments", "equipment")
    if raw_equipments is None:
        raw_equipments = []
    normalized_equipments: list[dict[str, Any]] = []
    if isinstance(raw_equipments, (list, tuple)):
        for item in raw_equipments:
            if not isinstance(item, dict):
                normalized_equipments.append(item)
                continue
            equipment_code = item.get(
                "ISOEquipmentCode",
                item.get("iso_equipment_code", item.get("equipment_size_type")),
            )
            shipper_owned = item.get("isShipperOwned", item.get("is_shipper_owned"))
            equipment_weight = item.get("cargoGrossWeight", item.get("cargo_gross_weight"))
            commodities = item.get("commodities", ())
            clean_commodities = [
                {
                    "commodityType": commodity.get(
                        "commodityType", commodity.get("commodity_type")
                    ),
                    "cargoGrossWeight": commodity.get(
                        "cargoGrossWeight", commodity.get("cargo_gross_weight")
                    ),
                }
                for commodity in commodities
                if isinstance(commodity, dict)
            ]
            normalized_equipments.append(
                {
                    "ISOEquipmentCode": equipment_code,
                    "units": item.get("units"),
                    "isShipperOwned": shipper_owned,
                    "cargoGrossWeight": equipment_weight,
                    "commodities": clean_commodities,
                }
            )

    payload: dict[str, Any] = {
        "receipt_type_at_origin": first("receipt_type_at_origin"),
        "delivery_type_at_destination": first("delivery_type_at_destination"),
        "cargo_movement_type_at_origin": first("cargo_movement_type_at_origin"),
        "cargo_movement_type_at_destination": first("cargo_movement_type_at_destination"),
        "service_contract_reference": first("service_contract_reference"),
        "contract_quotation_reference": first("contract_quotation_reference"),
        "extended_contract_quotation_reference": first("extended_contract_quotation_reference"),
        "is_equipment_substitution_allowed": first("is_equipment_substitution_allowed"),
        "shipment_locations": normalized_locations,
        "requested_equipments": normalized_equipments,
        "document_parties": first("document_parties"),
    }
    # IR stores booking_agent directly, while the DCSA request nests it.
    if payload["document_parties"] is None:
        agent = first("booking_agent")
        payload["document_parties"] = {"booking_agent": agent}
    try:
        return BookingCreateRequest.model_validate(payload)
    except Exception as exc:
        raise ValueError("booking transaction does not match the reviewed subset") from exc


booking_from_transaction = map_ir_to_booking

__all__ = [
    "BookingAgent",
    "BookingCancellationRequest",
    "BookingCancellationResponse",
    "BookingCode",
    "BookingCommodity",
    "BookingCreateRequest",
    "BookingCreateResponse",
    "BookingDocumentParties",
    "BookingEquipment",
    "BookingGetResponse",
    "BookingIdentifier",
    "BookingLocation",
    "BookingParty",
    "BookingShipmentLocation",
    "BookingWeight",
    "EquipmentCode",
    "booking_from_transaction",
    "map_ir_to_booking",
]
