from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import httpx2

from cargomesh.booking.adapter import BookingHttpAdapter, BookingHttpAdapterConfig
from cargomesh.booking.evidence import (
    BookingEvidenceCollector,
    BookingEvidenceCollectorConfig,
)
from cargomesh.booking.planner import synthetic_booking_planner
from cargomesh.booking.synthetic_carrier import (
    SQLiteSyntheticCarrierStore,
    create_synthetic_carrier,
    create_synthetic_ledger,
)
from cargomesh.credentials import SecretLease
from cargomesh.ir import TransactionCommand
from cargomesh.runtime.adapters import CredentialLeaseSet
from cargomesh.runtime.models import AdapterInvocation
from cargomesh.verification.engine import evaluate_verification
from cargomesh.verification.models import (
    EvidenceCollectionInvocation,
    VerificationInvocation,
    VerificationVerdict,
)


def booking() -> TransactionCommand:
    return TransactionCommand.model_validate(
        {
            "tenant_id": "tenant-a",
            "transaction_type": "booking.create",
            "external_reference": "customer-booking-100",
            "subject": {
                "kind": "booking",
                "carrier_profile": "synthetic.dcsa.booking",
            },
            "parameters": {
                "receipt_type_at_origin": "CY",
                "delivery_type_at_destination": "CY",
                "cargo_movement_type_at_origin": "FCL",
                "cargo_movement_type_at_destination": "FCL",
                "service_contract_reference": "SC-100",
                "is_equipment_substitution_allowed": False,
                "shipment_locations": [
                    {"location_type_code": "POL", "un_location_code": "CNSGH"},
                    {"location_type_code": "POD", "un_location_code": "NLRTM"},
                ],
                "requested_equipments": [
                    {
                        "iso_equipment_code": "22G1",
                        "units": 1,
                        "is_shipper_owned": False,
                        "cargo_gross_weight": {"value": 12_000, "unit": "KGM"},
                        "commodities": [{"commodity_type": "Mobile phones"}],
                    }
                ],
                "booking_agent": {"party_name": "CargoMesh Test Agent"},
            },
            "requested_effects": [
                "booking_request_accepted",
                "booking_received_verified",
            ],
            "verification_requirements": {"minimum_independence_level": "L2"},
            "risk_class": "CONSEQUENTIAL_WRITE",
            "required_capabilities": ["booking.draft.prepare", "booking.submit"],
        }
    )


def test_synthetic_submit_and_independent_ledger_reach_l2_verified() -> None:
    command = booking()
    plan = synthetic_booking_planner().build(
        command,
        transaction_id="txn-1",
        business_digest="sha256:" + "a" * 64,
    )
    store = SQLiteSyntheticCarrierStore()
    carrier = create_synthetic_carrier(store)
    ledger = create_synthetic_ledger(store)
    adapter = BookingHttpAdapter(
        BookingHttpAdapterConfig(
            "http://carrier.test", transport=httpx2.ASGITransport(app=carrier)
        )
    )
    collector = BookingEvidenceCollector(
        BookingEvidenceCollectorConfig(
            "http://ledger.test", transport=httpx2.ASGITransport(app=ledger)
        )
    )
    submit = plan.steps[1]
    leases = CredentialLeaseSet(
        {
            "api_key": SecretLease(
                b"synthetic-only",
                datetime.now(UTC) + timedelta(minutes=1),
                name="api_key",
            )
        }
    )
    try:
        result = asyncio.run(
            adapter.execute_with_credentials(
                AdapterInvocation(
                    transaction_id=plan.transaction_id,
                    tenant_id=plan.tenant_id,
                    step_id=submit.step_id,
                    capability=submit.capability,
                    adapter=submit.adapter,
                    operation=submit.operation,
                    input=submit.input,
                ),
                leases,
            )
        )
    finally:
        leases.close()
    verification = plan.verification
    assert verification is not None
    collection = verification.collectors[0]
    observation = asyncio.run(
        collector.collect(
            EvidenceCollectionInvocation(
                tenant_id=plan.tenant_id,
                transaction_id=plan.transaction_id,
                step_id=collection.step_id,
                collector_id=collection.collector_id,
                operation=collection.operation,
                input=collection.input,
            )
        )
    )
    transaction = submit.input["transaction"]
    assert isinstance(transaction, dict)
    assert result.execution_source is not None
    report = evaluate_verification(
        VerificationInvocation(
            tenant_id=plan.tenant_id,
            transaction_id=plan.transaction_id,
            business_digest=plan.business_digest,
            plan=verification,
            execution_document={
                "transaction": transaction,
                "outputs": [result.model_dump(mode="json")],
            },
            execution_sources=(result.execution_source,),
        ),
        (observation,),
        evaluated_at=datetime.now(UTC),
    )

    assert report.verdict is VerificationVerdict.VERIFIED
    assert report.achieved_level.value == "L2"
    assert report.synthetic is True
    assert result.effect_reference is not None
