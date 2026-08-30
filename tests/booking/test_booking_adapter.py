from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta

import httpx2
import pytest

from cargomesh.booking.adapter import BookingHttpAdapter, BookingHttpAdapterConfig
from cargomesh.credentials.lease import SecretLease
from cargomesh.runtime.adapters import AdapterExecutionError, CredentialLeaseSet
from cargomesh.runtime.models import AdapterInvocation


def _input() -> dict[str, object]:
    return {
        "external_reference": "EXT-1",
        "parameters": {
            "receipt_type_at_origin": "CY",
            "delivery_type_at_destination": "CY",
            "cargo_movement_type_at_origin": "FCL",
            "cargo_movement_type_at_destination": "FCL",
            "extended_contract_quotation_reference": "Q-1",
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
        },
    }


def _invocation(operation: str = "submit") -> AdapterInvocation:
    return AdapterInvocation(
        transaction_id="txn-1",
        tenant_id="tenant-1",
        step_id="submit-booking",
        adapter="booking",
        operation=operation,
        input=_input() if operation == "submit" else {"effect_reference": "CBR-1"},
    )


def _leases() -> CredentialLeaseSet:
    expiry = datetime.now(UTC) + timedelta(minutes=1)
    return CredentialLeaseSet({"api_key": SecretLease(b"opaque-token", expiry)})


def test_submit_posts_exact_wire_shape_then_reads_status() -> None:
    requests: list[httpx2.Request] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        requests.append(request)
        if request.method == "POST":
            return httpx2.Response(
                202,
                headers={"content-type": "application/json"},
                json={"carrierBookingRequestReference": "CBR-1"},
            )
        return httpx2.Response(
            200,
            headers={"content-type": "application/json"},
            json={"carrierBookingRequestReference": "CBR-1", "bookingStatus": "RECEIVED"},
        )

    adapter = BookingHttpAdapter(
        BookingHttpAdapterConfig("http://carrier.test", transport=httpx2.MockTransport(handler))
    )
    leases = _leases()
    result = asyncio.run(adapter.execute_with_credentials(_invocation(), leases))
    payload = json.loads(requests[0].content)
    assert result.effect_reference == "CBR-1"
    assert set(payload) == {
        "receiptTypeAtOrigin",
        "deliveryTypeAtDestination",
        "cargoMovementTypeAtOrigin",
        "cargoMovementTypeAtDestination",
        "extendedContractQuotationReference",
        "isEquipmentSubstitutionAllowed",
        "shipmentLocations",
        "requestedEquipments",
        "documentParties",
    }
    assert [request.url.path for request in requests] == ["/v2/bookings", "/v2/bookings/CBR-1"]
    assert requests[0].headers["idempotency-key"] == "EXT-1"
    leases.close()


def test_post_schema_rejection_is_bounded_and_never_retries() -> None:
    def handler(_: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(
            400, headers={"content-type": "application/json"}, json={"secret": "x"}
        )

    adapter = BookingHttpAdapter(
        BookingHttpAdapterConfig("http://carrier.test", transport=httpx2.MockTransport(handler))
    )
    with pytest.raises(AdapterExecutionError) as raised:
        asyncio.run(adapter.execute_with_credentials(_invocation(), _leases()))
    assert raised.value.code == "booking_schema_rejected"
    assert "secret" not in str(raised.value)


def test_cancel_uses_effect_reference_and_empty_dsca_response() -> None:
    request_paths: list[str] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        request_paths.append(request.url.path)
        return httpx2.Response(202)

    adapter = BookingHttpAdapter(
        BookingHttpAdapterConfig("http://carrier.test", transport=httpx2.MockTransport(handler))
    )
    result = asyncio.run(adapter.execute_with_credentials(_invocation("cancel"), _leases()))
    assert result.effect_reference == "CBR-1"
    assert request_paths == ["/v2/bookings/CBR-1"]


def test_post_requires_dsca_202_exactly() -> None:
    def handler(_: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(
            200,
            headers={"content-type": "application/json"},
            json={"carrierBookingRequestReference": "CBR-1"},
        )

    adapter = BookingHttpAdapter(
        BookingHttpAdapterConfig("http://carrier.test", transport=httpx2.MockTransport(handler))
    )
    with pytest.raises(AdapterExecutionError) as raised:
        asyncio.run(adapter.execute_with_credentials(_invocation(), _leases()))
    assert raised.value.code == "booking_effect_unknown"
