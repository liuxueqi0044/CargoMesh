from __future__ import annotations

import asyncio
import socket
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta

import pytest
import uvicorn
from fastapi import FastAPI

from cargomesh.adapters.browser import BrowserAdapterConfig, PlaywrightBrowserAdapter
from cargomesh.adapters.http_api import (
    SyntheticTrackingHttpAdapter,
    SyntheticTrackingHttpAdapterConfig,
)
from cargomesh.adapters.package import load_builtin_synthetic_package
from cargomesh.adapters.synthetic_api import create_synthetic_tracking_api
from cargomesh.adapters.synthetic_portal import create_synthetic_portal
from cargomesh.ir import ShipmentSubject, TransactionCommand
from cargomesh.ir.enums import VerificationLevel
from cargomesh.routing.models import RouteOutcome, RouteOutcomeKind
from cargomesh.routing.store import SQLiteRouteOutcomeStore
from cargomesh.runtime.models import AdapterInvocation, AdapterResult, ExecutionPlan, StepOutput
from cargomesh.runtime.planner import synthetic_optimized_tracking_planner
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
        raise RuntimeError("local route acceptance service did not start")
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        thread.join(timeout=10)
        listener.close()
        if thread.is_alive():
            raise RuntimeError("local route acceptance service did not stop")


async def verify(
    plan: ExecutionPlan, result: AdapterResult, evidence_url: str
) -> VerificationVerdict:
    verification = plan.verification
    source = result.execution_source
    assert verification is not None and source is not None
    step = plan.steps[0]
    collectors = EvidenceCollectorRegistry()
    collectors.register(
        "synthetic.evidence.track",
        SyntheticLedgerHttpCollector(SyntheticLedgerHttpCollectorConfig(evidence_url)),
    )
    with SQLiteEvidenceStore(":memory:") as receipts:
        report = await VerificationActivities(
            collectors, receipts, clock=lambda: NOW
        ).verify(
            VerificationInvocation(
                tenant_id=plan.tenant_id,
                transaction_id=plan.transaction_id,
                business_digest=plan.business_digest,
                plan=verification,
                execution_document={
                    "transaction": step.input["transaction"],
                    "outputs": [
                        StepOutput(
                            step_id=step.step_id,
                            output=result.output,
                            execution_source=source,
                        ).model_dump(mode="json")
                    ],
                },
                execution_sources=(source,),
            )
        )
    assert report.achieved_level is VerificationLevel.L2
    return report.verdict


@pytest.mark.browser
def test_api_wins_then_open_circuit_selects_verified_browser_path() -> None:
    async def scenario(portal_url: str, api_url: str, evidence_url: str) -> None:
        command = TransactionCommand(
            tenant_id="tenant-a",
            external_reference="customer-1",
            subject=ShipmentSubject(carrier_booking_reference="CBR-001"),
        )
        with SQLiteRouteOutcomeStore(":memory:") as outcomes:
            planner = synthetic_optimized_tracking_planner(
                outcomes, clock=lambda: NOW
            )
            api_plan = planner.build(
                command,
                transaction_id="txn-api",
                business_digest="sha256:" + "a" * 64,
            )
            api_step = api_plan.steps[0]
            assert api_step.route_candidate_id == "synthetic.api.track"
            api_result = await SyntheticTrackingHttpAdapter(
                SyntheticTrackingHttpAdapterConfig(api_url)
            ).execute(
                AdapterInvocation(
                    transaction_id=api_plan.transaction_id,
                    tenant_id=api_plan.tenant_id,
                    step_id=api_step.step_id,
                    adapter=api_step.adapter,
                    operation=api_step.operation,
                    input=api_step.input,
                    route_candidate_id=api_step.route_candidate_id,
                )
            )
            assert await verify(api_plan, api_result, evidence_url) is VerificationVerdict.VERIFIED

            for attempt in range(1, 4):
                outcomes.append(
                    RouteOutcome.issue(
                        event_id=f"api-failure-{attempt}",
                        tenant_id="tenant-a",
                        transaction_id=f"failed-{attempt}",
                        step_id="read",
                        candidate_id="synthetic.api.track",
                        temporal_attempt=1,
                        kind=RouteOutcomeKind.RETRYABLE_FAILURE,
                        latency_ms=50,
                        failure_code="api_server_error",
                        occurred_at=NOW - timedelta(seconds=4 - attempt),
                    )
                )
            browser_plan = planner.build(
                command,
                transaction_id="txn-browser",
                business_digest="sha256:" + "b" * 64,
            )
            browser_step = browser_plan.steps[0]
            assert browser_step.route_candidate_id == "synthetic.browser.track"
            browser = PlaywrightBrowserAdapter(
                load_builtin_synthetic_package(),
                BrowserAdapterConfig(base_url=portal_url, default_timeout_ms=10_000),
            )
            async with browser:
                browser_result = await browser.execute(
                    AdapterInvocation(
                        transaction_id=browser_plan.transaction_id,
                        tenant_id=browser_plan.tenant_id,
                        step_id=browser_step.step_id,
                        adapter=browser_step.adapter,
                        operation=browser_step.operation,
                        input=browser_step.input,
                        route_candidate_id=browser_step.route_candidate_id,
                    )
                )
            assert (
                await verify(browser_plan, browser_result, evidence_url)
                is VerificationVerdict.VERIFIED
            )

    with (
        running_app(create_synthetic_portal()) as portal_url,
        running_app(create_synthetic_tracking_api()) as api_url,
        running_app(create_synthetic_evidence_service(clock=lambda: NOW)) as evidence_url,
    ):
        asyncio.run(scenario(portal_url, api_url, evidence_url))
