from __future__ import annotations

import pytest

from cargomesh.ir import ShipmentSubject, TransactionCommand
from cargomesh.runtime import (
    CapabilityBinding,
    MissingCapabilityBinding,
    StaticExecutionPlanner,
)


def command() -> TransactionCommand:
    return TransactionCommand(
        tenant_id="tenant-a",
        external_reference="customer-1",
        subject=ShipmentSubject(carrier_booking_reference="CBR-1"),
    )


def test_static_planner_builds_deterministic_explicit_step() -> None:
    planner = StaticExecutionPlanner(
        {
            "shipment.track.read": CapabilityBinding(
                adapter="synthetic.track", operation="fetch"
            )
        }
    )
    first = planner.build(
        command(), transaction_id="txn-1", business_digest="sha256:" + "a" * 64
    )
    second = planner.build(
        command(), transaction_id="txn-1", business_digest="sha256:" + "a" * 64
    )

    assert first == second
    assert first.steps[0].adapter == "synthetic.track"
    assert first.steps[0].input["transaction"]["subject"]["carrier_booking_reference"] == "CBR-1"


def test_static_planner_fails_closed_without_binding() -> None:
    with pytest.raises(MissingCapabilityBinding, match=r"shipment\.track\.read"):
        StaticExecutionPlanner({}).build(
            command(), transaction_id="txn-1", business_digest="sha256:" + "a" * 64
        )
