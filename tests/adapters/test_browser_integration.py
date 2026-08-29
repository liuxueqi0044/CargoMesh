from __future__ import annotations

import asyncio
import socket
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager

import pytest
import uvicorn
from fastapi import FastAPI
from fastapi.responses import HTMLResponse

from cargomesh.adapters.artifacts import InMemoryArtifactSink
from cargomesh.adapters.browser import BrowserAdapterConfig, PlaywrightBrowserAdapter
from cargomesh.adapters.contracts import (
    BrowserRecipe,
    ClickAction,
    ExtractTextAction,
    LoadedAdapterPackage,
    NavigateAction,
    RoleLocator,
    SignatureProbe,
    TextExpectation,
)
from cargomesh.adapters.package import load_builtin_synthetic_package
from cargomesh.adapters.synthetic_portal import PortalVariant, create_synthetic_portal
from cargomesh.runtime.adapters import AdapterExecutionError, AdapterRegistry
from cargomesh.runtime.models import AdapterInvocation


@contextmanager
def running_app(application: FastAPI) -> Iterator[str]:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    port = listener.getsockname()[1]
    server = uvicorn.Server(
        uvicorn.Config(
            application,
            host="127.0.0.1",
            port=port,
            log_level="error",
        )
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
        raise RuntimeError("synthetic portal did not start")
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        thread.join(timeout=10)
        listener.close()
        if thread.is_alive():
            raise RuntimeError("synthetic portal did not stop")


@contextmanager
def running_portal(variant: PortalVariant = "healthy") -> Iterator[str]:
    with running_app(create_synthetic_portal(variant)) as base_url:
        yield base_url


def invocation(reference: str) -> AdapterInvocation:
    return AdapterInvocation(
        transaction_id=f"txn-{reference.lower()}",
        tenant_id="tenant-a",
        step_id="execute-1-shipment-track-read",
        adapter="synthetic.browser.track",
        operation="fetch",
        input={
            "transaction": {
                "subject": {"carrier_booking_reference": reference},
            }
        },
    )


@pytest.mark.browser
def test_real_browser_executes_recipe_with_a_fresh_context_each_time() -> None:
    async def scenario(base_url: str) -> None:
        adapter = PlaywrightBrowserAdapter(
            load_builtin_synthetic_package(),
            BrowserAdapterConfig(base_url=base_url, default_timeout_ms=10_000),
        )
        registry = AdapterRegistry()
        registry.register("synthetic.browser.track", adapter)
        async with adapter:
            first = await registry.invoke(invocation("CBR-001"))
            assert adapter.active_context_count == 0
            second = await registry.invoke(invocation("CBR-002"))
            assert adapter.active_context_count == 0

        assert first.output["data"] == {
            "shipment.reference": "CBR-001",
            "shipment.status": "IN_TRANSIT",
        }
        assert second.output["data"] == {
            "shipment.reference": "CBR-002",
            "shipment.status": "DELIVERED",
        }
        assert first.output["synthetic"] is True
        assert first.output["portal_signature_digest"].startswith("sha256:")
        assert "SUCCESS" not in first.model_dump_json()
        assert "VERIFIED" not in first.model_dump_json()

    with running_portal() as base_url:
        asyncio.run(scenario(base_url))


@pytest.mark.browser
def test_portal_label_drift_halts_before_actions_and_emits_opaque_trace() -> None:
    async def scenario(base_url: str) -> None:
        sink = InMemoryArtifactSink()
        adapter = PlaywrightBrowserAdapter(
            load_builtin_synthetic_package(),
            BrowserAdapterConfig(
                base_url=base_url,
                default_timeout_ms=500,
                trace_on_failure=True,
            ),
            artifact_sink=sink,
        )
        async with adapter:
            with pytest.raises(AdapterExecutionError) as caught:
                await adapter.execute(invocation("CBR-001"))
            assert adapter.active_context_count == 0

        error = caught.value
        assert error.code == "portal_drift_detected"
        assert error.retryable is False
        artifact = error.diagnostics["artifact"]
        assert isinstance(artifact, dict)
        assert artifact["artifact_id"] in sink.items
        assert "path" not in artifact

    with running_portal("label_drift") as base_url:
        asyncio.run(scenario(base_url))


@pytest.mark.browser
def test_real_browser_aborts_an_external_subresource() -> None:
    application = FastAPI()

    @application.get("/external", response_class=HTMLResponse)
    async def external() -> str:
        return (
            "<!doctype html><html><body><h1>Track shipment</h1>"
            '<img src="http://localhost:9/not-allowed.png" alt="external">'
            "</body></html>"
        )

    built_in = load_builtin_synthetic_package()
    recipe = BrowserRecipe(
        operation="fetch",
        capability="shipment.track.read",
        portal_signatures=(
            SignatureProbe(
                key="heading",
                locator=RoleLocator(role="heading", name="Track shipment"),
                expectation=TextExpectation(mode="equals", value="Track shipment"),
            ),
        ),
        actions=(
            NavigateAction(path="/external", wait_until="load"),
            ExtractTextAction(
                locator=RoleLocator(role="heading", name="Track shipment"),
                output_key="heading",
            ),
        ),
    )
    package = LoadedAdapterPackage(
        manifest=built_in.manifest,
        recipes={"fetch": recipe},
    )

    async def scenario(base_url: str) -> None:
        adapter = PlaywrightBrowserAdapter(
            package,
            BrowserAdapterConfig(base_url=base_url, default_timeout_ms=3_000),
        )
        async with adapter:
            with pytest.raises(AdapterExecutionError) as caught:
                await adapter.execute(invocation("CBR-001"))
            assert adapter.active_context_count == 0

        assert caught.value.code == "external_request_blocked"
        assert caught.value.retryable is False
        assert caught.value.diagnostics["blocked_origins"] == ["http://localhost:9"]

    with running_app(application) as base_url:
        asyncio.run(scenario(base_url))


@pytest.mark.browser
def test_read_only_adapter_aborts_an_http_write() -> None:
    application = FastAPI()

    @application.get("/write", response_class=HTMLResponse)
    async def write_form() -> str:
        return (
            "<!doctype html><html><body><h1>Track shipment</h1>"
            '<form method="post" action="/write"><button type="submit">Submit</button></form>'
            "</body></html>"
        )

    @application.post("/write", response_class=HTMLResponse)
    async def forbidden_write() -> str:
        return "<p>This handler must not be reached.</p>"

    built_in = load_builtin_synthetic_package()
    recipe = BrowserRecipe(
        operation="fetch",
        capability="shipment.track.read",
        portal_signatures=(
            SignatureProbe(
                key="heading",
                locator=RoleLocator(role="heading", name="Track shipment"),
            ),
        ),
        actions=(
            NavigateAction(path="/write", wait_until="load"),
            ClickAction(locator=RoleLocator(role="button", name="Submit")),
            ExtractTextAction(
                locator=RoleLocator(role="heading", name="Track shipment"),
                output_key="heading",
            ),
        ),
    )
    package = LoadedAdapterPackage(
        manifest=built_in.manifest,
        recipes={"fetch": recipe},
    )

    async def scenario(base_url: str) -> None:
        adapter = PlaywrightBrowserAdapter(
            package,
            BrowserAdapterConfig(base_url=base_url, default_timeout_ms=3_000),
        )
        async with adapter:
            with pytest.raises(AdapterExecutionError) as caught:
                await adapter.execute(invocation("CBR-001"))

        assert caught.value.code == "unsafe_http_method_blocked"
        assert caught.value.retryable is False
        assert caught.value.diagnostics["blocked_methods"] == ["POST"]

    with running_app(application) as base_url:
        asyncio.run(scenario(base_url))


@pytest.mark.browser
def test_portal_server_error_is_retryable_and_not_misclassified_as_drift() -> None:
    async def scenario(base_url: str) -> None:
        adapter = PlaywrightBrowserAdapter(
            load_builtin_synthetic_package(),
            BrowserAdapterConfig(base_url=base_url, default_timeout_ms=3_000),
        )
        async with adapter:
            with pytest.raises(AdapterExecutionError) as caught:
                await adapter.execute(invocation("CBR-001"))

        assert caught.value.code == "portal_server_error"
        assert caught.value.retryable is True
        assert caught.value.diagnostics["portal_status"] == 503

    with running_portal("server_error") as base_url:
        asyncio.run(scenario(base_url))
