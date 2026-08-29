from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from cargomesh.mapping import (
    DCSATNTQueryV2,
    DCSATNTV2Mapper,
    MappingContext,
    MappingError,
    MappingFidelity,
)


def test_dcsa_query_requires_a_business_reference() -> None:
    with pytest.raises(ValidationError, match="requires at least one"):
        DCSATNTQueryV2(eventType="SHIPMENT")


def test_comma_separated_dcsa_values_compile_to_typed_ir() -> None:
    query = DCSATNTQueryV2(
        eventType="SHIPMENT,EQUIPMENT",
        carrierBookingReference="CBR-123",
        equipmentEventTypeCode="GTIN,GTOT",
        UNLocationCode="CNSHA",
        sort="eventCreatedDateTime:DESC",
        limit=50,
    )
    result = DCSATNTV2Mapper().to_ir(
        query,
        MappingContext(
            tenant_id="tenant-a",
            requested_at=datetime(2026, 8, 30, tzinfo=UTC),
        ),
    )

    command = result.require_supported()
    assert command.subject.carrier_booking_reference == "CBR-123"
    assert [event.value for event in command.parameters.event_types] == [
        "SHIPMENT",
        "EQUIPMENT",
    ]
    assert command.parameters.equipment_event_type_codes == ("GTIN", "GTOT")
    assert command.external_reference == "CBR-123"
    assert any(
        diagnostic.fidelity is MappingFidelity.DEFAULTED
        for diagnostic in result.diagnostics
    )


def test_supported_dcsa_query_round_trips() -> None:
    mapper = DCSATNTV2Mapper()
    query = DCSATNTQueryV2(
        eventType=["TRANSPORT"],
        transportDocumentReference="BOL-123",
        transportCallID="TC-7",
        carrierVoyageNumber="VY-9",
        **{
            "eventCreatedDateTime:gte": "2026-08-01T00:00:00Z",
            "eventCreatedDateTime:lt": "2026-09-01T00:00:00Z",
        },
        cursor="cursor-token",
    )
    mapped = mapper.to_ir(
        query,
        MappingContext(tenant_id="tenant-a", external_reference="customer-ref"),
    )
    round_trip = mapper.from_ir(mapped.value)

    assert not round_trip.has_blocking_diagnostics
    assert round_trip.value.model_dump(by_alias=True, exclude_none=True) == query.model_dump(
        by_alias=True, exclude_none=True
    )


def test_dcsa_date_time_operator_cannot_be_silently_ambiguous() -> None:
    with pytest.raises(ValidationError, match="equivalent"):
        DCSATNTQueryV2.model_validate(
            {
                "carrierBookingReference": "CBR-123",
                "eventCreatedDateTime": "2026-08-01T00:00:00Z",
                "eventCreatedDateTime:eq": "2026-08-01T00:00:00Z",
            }
        )


def test_dcsa_query_rejects_code_outside_pinned_standard() -> None:
    with pytest.raises(ValidationError, match="Input should be"):
        DCSATNTQueryV2(
            carrierBookingReference="CBR-123",
            shipmentEventTypeCode="NOT",
        )


def test_ir_extensions_make_reverse_mapping_explicitly_lossy() -> None:
    mapper = DCSATNTV2Mapper()
    command = mapper.to_ir(
        DCSATNTQueryV2(transportDocumentReference="BOL-123"),
        MappingContext(tenant_id="tenant-a"),
    ).value.model_copy(
        update={"extensions": {"example.com/private-filter/v1": {"flag": True}}}
    )
    result = mapper.from_ir(command)

    assert result.has_blocking_diagnostics
    with pytest.raises(MappingError, match="EXTENSIONS_NOT_REPRESENTABLE"):
        result.require_supported()


def test_ir_code_outside_tnt_2_3_is_a_blocking_reverse_diagnostic() -> None:
    mapper = DCSATNTV2Mapper()
    command = mapper.to_ir(
        DCSATNTQueryV2(transportDocumentReference="BOL-123"),
        MappingContext(tenant_id="tenant-a"),
    ).value
    command = command.model_copy(
        update={
            "parameters": command.parameters.model_copy(
                update={"transport_event_type_codes": ("OMIT",)}
            )
        }
    )

    result = mapper.from_ir(command)

    assert result.has_blocking_diagnostics
    assert any(item.code == "CODE_NOT_IN_DCSA_TNT_2_3" for item in result.diagnostics)
