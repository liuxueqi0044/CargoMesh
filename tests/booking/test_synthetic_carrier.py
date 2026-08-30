from __future__ import annotations

from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from cargomesh.booking.synthetic_carrier import (
    SYNTHETIC_FAULT_HEADER,
    SQLiteSyntheticCarrierStore,
    SyntheticCarrierError,
    create_synthetic_carrier,
    create_synthetic_ledger,
)

NOW = datetime(2040, 1, 2, 3, 4, 5, tzinfo=UTC)


def booking_payload(**overrides: object) -> dict[str, object]:
    values: dict[str, object] = {
        "receiptTypeAtOrigin": "CY",
        "deliveryTypeAtDestination": "CY",
        "cargoMovementTypeAtOrigin": "FCL",
        "cargoMovementTypeAtDestination": "FCL",
        "serviceContractReference": "service-contract-1",
        "isEquipmentSubstitutionAllowed": False,
        "shipmentLocations": [
            {"location": {"UNLocationCode": "NLRTM"}, "locationTypeCode": "POL"},
            {"location": {"UNLocationCode": "USNYC"}, "locationTypeCode": "POD"},
        ],
        "requestedEquipments": [
            {
                "ISOEquipmentCode": "22G1",
                "units": 1,
                "isShipperOwned": False,
                "cargoGrossWeight": {"value": 100, "unit": "KGM"},
                "commodities": [
                    {
                        "commodityType": "general cargo",
                        "cargoGrossWeight": {"value": 100, "unit": "KGM"},
                    }
                ],
            }
        ],
        "documentParties": {"bookingAgent": {"partyName": "CargoMesh test agent"}},
    }
    values.update(overrides)
    return values


def clients() -> tuple[TestClient, TestClient, SQLiteSyntheticCarrierStore]:
    store = SQLiteSyntheticCarrierStore()
    carrier = TestClient(create_synthetic_carrier(store, clock=lambda: NOW))
    ledger = TestClient(create_synthetic_ledger(store))
    return carrier, ledger, store


def create(carrier: TestClient, external_reference: str = "external-reference-1"):
    return carrier.post(
        "/v2/bookings",
        json=booking_payload(),
        headers={"Idempotency-Key": external_reference},
    )


def test_create_is_exact_202_then_get_and_separate_ledger_readback() -> None:
    carrier, ledger, _ = clients()

    created = create(carrier)
    reference = created.json()["carrierBookingRequestReference"]
    fetched = carrier.get(f"/v2/bookings/{reference}")
    observed = ledger.get("/synthetic-ledger/bookings/by-external-reference/external-reference-1")

    assert created.status_code == 202
    assert set(created.json()) == {"carrierBookingRequestReference"}
    assert reference.startswith("CBRR-")
    assert fetched.status_code == 200
    assert fetched.json() == {
        "carrierBookingRequestReference": reference,
        "bookingStatus": "RECEIVED",
    }
    assert observed.status_code == 200
    assert observed.json()["carrierBookingRequestReference"] == reference
    assert observed.json()["externalReference"] == "external-reference-1"
    assert observed.json()["bookingStatus"] == "RECEIVED"
    assert observed.json()["recordDigest"].startswith("sha256:")
    assert observed.json()["synthetic"] is True


def test_exact_external_reference_idempotency_replays_or_conflicts() -> None:
    carrier, _, _ = clients()

    first = create(carrier)
    replay = create(carrier)
    conflict = carrier.post(
        "/v2/bookings",
        json=booking_payload(isEquipmentSubstitutionAllowed=True),
        headers={"Idempotency-Key": "external-reference-1"},
    )

    assert first.status_code == replay.status_code == 202
    assert first.json() == replay.json()
    assert conflict.status_code == 409
    assert conflict.json()["error"]["code"] == "booking_idempotency_conflict"
    assert "service-contract-1" not in conflict.text


def test_reject_before_effect_and_response_loss_are_explicit_and_safe() -> None:
    carrier, ledger, _ = clients()
    rejected = carrier.post(
        "/v2/bookings",
        json=booking_payload(),
        headers={
            "Idempotency-Key": "rejected-reference",
            SYNTHETIC_FAULT_HEADER: "reject-before-effect",
        },
    )
    absent = ledger.get("/synthetic-ledger/bookings/by-external-reference/rejected-reference")
    lost = carrier.post(
        "/v2/bookings",
        json=booking_payload(),
        headers={
            "Idempotency-Key": "lost-reference",
            SYNTHETIC_FAULT_HEADER: "effect-then-lose-response",
        },
    )
    replay = create(carrier, "lost-reference")

    assert rejected.status_code == 422
    assert rejected.json()["error"]["code"] == "synthetic_rejected"
    assert absent.status_code == 404
    assert lost.status_code == 503
    assert lost.json()["error"]["code"] == "synthetic_response_lost"
    assert replay.status_code == 202


def test_ledger_fault_modes_are_only_synthetic_and_do_not_change_carrier_record() -> None:
    carrier, ledger, _ = clients()
    reference = create(carrier).json()["carrierBookingRequestReference"]

    missing = ledger.get(
        "/synthetic-ledger/bookings/by-external-reference/external-reference-1",
        headers={SYNTHETIC_FAULT_HEADER: "ledger-missing"},
    )
    conflict = ledger.get(
        "/synthetic-ledger/bookings/by-external-reference/external-reference-1",
        headers={SYNTHETIC_FAULT_HEADER: "ledger-conflict"},
    )
    carrier_record = carrier.get(f"/v2/bookings/{reference}")

    assert missing.status_code == 404
    assert missing.json()["error"]["code"] == "synthetic_ledger_not_found"
    assert conflict.status_code == 200
    assert conflict.json()["bookingStatus"] == "CONFLICT"
    assert carrier_record.json()["bookingStatus"] == "RECEIVED"


def test_cancellation_is_idempotent_and_cancellation_fault_has_no_effect() -> None:
    carrier, _, _ = clients()
    reference = create(carrier).json()["carrierBookingRequestReference"]
    failed = carrier.patch(
        f"/v2/bookings/{reference}",
        json={"bookingStatus": "CANCELLED"},
        headers={SYNTHETIC_FAULT_HEADER: "cancellation-failure"},
    )
    still_received = carrier.get(f"/v2/bookings/{reference}")
    cancelled = carrier.patch(f"/v2/bookings/{reference}", json={"bookingStatus": "CANCELLED"})
    replay = carrier.patch(f"/v2/bookings/{reference}", json={"bookingStatus": "CANCELLED"})

    assert failed.status_code == 503
    assert failed.json()["error"]["code"] == "synthetic_cancellation_failed"
    assert still_received.json()["bookingStatus"] == "RECEIVED"
    assert cancelled.status_code == replay.status_code == 202
    assert cancelled.content == replay.content == b""


def test_invalid_synthetic_fault_and_missing_idempotency_key_fail_safely() -> None:
    carrier, _, _ = clients()
    no_key = carrier.post("/v2/bookings", json=booking_payload())
    invalid_fault = carrier.post(
        "/v2/bookings",
        json=booking_payload(),
        headers={"Idempotency-Key": "reference", SYNTHETIC_FAULT_HEADER: "unknown"},
    )

    assert no_key.status_code == 400
    assert no_key.json()["error"]["code"] == "synthetic_idempotency_key_required"
    assert invalid_fault.status_code == 400
    assert invalid_fault.json()["error"]["code"] == "synthetic_fault_invalid"


def test_digest_bound_store_rejects_tampered_record() -> None:
    carrier, _, store = clients()
    reference = create(carrier).json()["carrierBookingRequestReference"]
    store._connection.execute(
        "UPDATE synthetic_bookings SET record_digest=? "
        "WHERE carrier_booking_request_reference=?",
        ("sha256:" + "0" * 64, reference),
    )

    with pytest.raises(SyntheticCarrierError) as caught:
        store.get(reference)

    assert caught.value.code == "synthetic_carrier_integrity_error"
