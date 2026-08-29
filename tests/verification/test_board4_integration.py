from __future__ import annotations

import asyncio
import socket
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime

import pytest
import uvicorn
from fastapi import FastAPI

from cargomesh.adapters.browser import BrowserAdapterConfig, PlaywrightBrowserAdapter
from cargomesh.adapters.package import load_builtin_synthetic_package
from cargomesh.adapters.synthetic_portal import create_synthetic_portal
from cargomesh.ir import ShipmentSubject, TransactionCommand
from cargomesh.ir.enums import VerificationLevel
from cargomesh.runtime.models import AdapterInvocation, StepOutput
from cargomesh.runtime.planner import synthetic_verified_browser_tracking_planner
from cargomesh.verification.activities import VerificationActivities
from cargomesh.verification.collectors import EvidenceCollectorRegistry
from cargomesh.verification.http_collector import (
    SyntheticLedgerHttpCollector,
    SyntheticLedgerHttpCollectorConfig,
)
from cargomesh.verification.models import VerificationInvocation, VerificationVerdict
from cargomesh.verification.store import SQLiteEvidenceStore
from cargomesh.verification.synthetic_evidence import create_synthetic_evidence_service

NOW = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)


@contextmanager
def running_app(application: FastAPI) -> Iterator[str]:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    port = listener.getsockname()[1]
    server = uvicorn.Server(
        uvicorn.Config(application, host="127.0.0.1", port=port, log_level="error")
    )
    thread = threading.Thread(
        target=lambda: asyncio.run(server.serve(sockets=[listener])), daemon=True
    )
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started and thread.is_alive() and time.monotonic() < deadline:
        time.sleep(0.01)
    if not server.started:
        server.should_exit = True
        thread.join(timeout=5)
        raise RuntimeError("local acceptance service did not start")
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        thread.join(timeout=10)
        listener.close()
        if thread.is_alive():
            raise RuntimeError("local acceptance service did not stop")


@pytest.mark.browser
def test_browser_execution_is_verified_by_separate_ledger_source() -> None:
    async def scenario(portal_url: str, evidence_url: str) -> None:
        command = TransactionCommand(
            tenant_id="tenant-a",
            external_reference="customer-1",
            subject=ShipmentSubject(carrier_booking_reference="CBR-001"),
        )
        plan = synthetic_verified_browser_tracking_planner().build(
            command,
            transaction_id="txn-board4",
            business_digest="sha256:" + "a" * 64,
        )
        step = plan.steps[0]
        adapter = PlaywrightBrowserAdapter(
            load_builtin_synthetic_package(),
            BrowserAdapterConfig(base_url=portal_url, default_timeout_ms=10_000),
        )
        async with adapter:
            result = await adapter.execute(
                AdapterInvocation(
                    transaction_id=plan.transaction_id,
                    tenant_id=plan.tenant_id,
                    step_id=step.step_id,
                    adapter=step.adapter,
                    operation=step.operation,
                    input=step.input,
                )
            )

        assert result.execution_source is not None
        assert result.execution_source.source_system == "synthetic.portal"
        assert plan.verification is not None
        output = StepOutput(
            step_id=step.step_id,
            output=result.output,
            execution_source=result.execution_source,
        )
        collectors = EvidenceCollectorRegistry()
        collectors.register(
            "synthetic.evidence.track",
            SyntheticLedgerHttpCollector(
                SyntheticLedgerHttpCollectorConfig(evidence_url)
            ),
        )
        with SQLiteEvidenceStore(":memory:") as receipts:
            report = await VerificationActivities(
                collectors, receipts, clock=lambda: NOW
            ).verify(
                VerificationInvocation(
                    tenant_id=plan.tenant_id,
                    transaction_id=plan.transaction_id,
                    business_digest=plan.business_digest,
                    plan=plan.verification,
                    execution_document={
                        "transaction": step.input["transaction"],
                        "outputs": [output.model_dump(mode="json")],
                    },
                    execution_sources=(result.execution_source,),
                )
            )
            assert report.evidence
            assert (
                receipts.get(plan.tenant_id, report.evidence[0].evidence_id)
                is not None
            )

        assert report.verdict is VerificationVerdict.VERIFIED
        assert report.achieved_level is VerificationLevel.L2
        assert report.synthetic is True

    with (
        running_app(create_synthetic_portal()) as portal_url,
        running_app(
            create_synthetic_evidence_service(clock=lambda: NOW)
        ) as evidence_url,
    ):
        asyncio.run(scenario(portal_url, evidence_url))
