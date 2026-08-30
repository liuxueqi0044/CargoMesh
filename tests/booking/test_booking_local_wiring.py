from __future__ import annotations

import asyncio

from cargomesh.api.runtime_server import _parser as runtime_parser
from cargomesh.booking.local import (
    SYNTHETIC_BOOKING_ADAPTER,
    synthetic_booking_credential_store,
    synthetic_booking_policy_provider,
)
from cargomesh.booking.planner import synthetic_booking_planner
from cargomesh.policy import PolicyEffect
from cargomesh.runtime.policy import apply_execution_policy
from cargomesh.runtime.worker import _parser as worker_parser

from .test_booking_vertical_slice import booking


def test_local_booking_policy_and_both_credential_scopes_freeze_into_plan() -> None:
    plan = synthetic_booking_planner().build(
        booking(), transaction_id="txn-1", business_digest="sha256:" + "a" * 64
    )
    credentials = synthetic_booking_credential_store(
        tenant_id="tenant-a", environment_id="local"
    )
    try:
        frozen = asyncio.run(
            apply_execution_policy(
                plan,
                synthetic_booking_policy_provider(
                    tenant_id="tenant-a", environment_id="local"
                ),
                environment_id="local",
                principal_ref="runtime.service",
                credential_bindings=credentials,
            )
        )
    finally:
        credentials.close()

    assert [decision.effect for decision in frozen.policy_decisions] == [
        PolicyEffect.ALLOW,
        PolicyEffect.REQUIRE_APPROVAL,
        PolicyEffect.ALLOW,
    ]
    submit = frozen.steps[1]
    assert submit.credential_binding_digest is not None
    assert submit.compensation is not None
    assert submit.compensation.credential_binding_digest is not None
    assert submit.adapter == SYNTHETIC_BOOKING_ADAPTER


def test_booking_runtime_flags_are_explicit_and_share_scope_defaults() -> None:
    runtime = runtime_parser().parse_args(["--enable-synthetic-booking-binding"])
    worker = worker_parser().parse_args(
        [
            "--enable-synthetic-booking-adapter",
            "--enable-synthetic-booking-verifier",
        ]
    )

    assert runtime.synthetic_booking_tenant == worker.synthetic_booking_tenant == "tenant-a"
    assert runtime.synthetic_booking_environment == worker.synthetic_booking_environment == "local"
    assert worker.synthetic_booking_url == "http://127.0.0.1:8091"
    assert worker.synthetic_booking_ledger_url == "http://127.0.0.1:8092"
