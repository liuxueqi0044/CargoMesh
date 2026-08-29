"""CargoMesh Temporal worker entry point."""

from __future__ import annotations

import argparse
import asyncio
import os
from collections.abc import Sequence
from pathlib import Path

from temporalio.worker import Worker

from cargomesh.adapters.artifacts import FileArtifactSink
from cargomesh.adapters.browser import BrowserAdapterConfig, PlaywrightBrowserAdapter
from cargomesh.adapters.package import load_builtin_synthetic_package

from .adapters import AdapterActivities, AdapterRegistry, SyntheticTrackingAdapter
from .temporal import CargoMeshTransactionWorkflow, connect_temporal


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run a CargoMesh Temporal worker")
    parser.add_argument(
        "--target", default=os.environ.get("CARGOMESH_TEMPORAL_TARGET", "localhost:7233")
    )
    parser.add_argument(
        "--namespace", default=os.environ.get("CARGOMESH_TEMPORAL_NAMESPACE", "default")
    )
    parser.add_argument(
        "--task-queue",
        default=os.environ.get("CARGOMESH_TEMPORAL_TASK_QUEUE", "cargomesh-transactions-v1"),
    )
    parser.add_argument(
        "--enable-synthetic-adapter",
        action="store_true",
        help="enable the offline demonstration adapter (never for carrier production use)",
    )
    parser.add_argument(
        "--enable-synthetic-browser-adapter",
        action="store_true",
        help="enable the checksum-pinned Board 3 synthetic browser adapter",
    )
    parser.add_argument(
        "--synthetic-portal-url",
        default=os.environ.get("CARGOMESH_SYNTHETIC_PORTAL_URL", "http://127.0.0.1:8765"),
        help="origin of the local synthetic portal",
    )
    parser.add_argument(
        "--browser-trace-directory",
        type=Path,
        default=None,
        help="opt in to bounded failure traces stored outside workflow history",
    )
    return parser


async def run_worker(
    *,
    target: str,
    namespace: str,
    task_queue: str,
    enable_synthetic_adapter: bool,
    enable_synthetic_browser_adapter: bool = False,
    synthetic_portal_url: str = "http://127.0.0.1:8765",
    browser_trace_directory: Path | None = None,
) -> None:
    registry = AdapterRegistry()
    if enable_synthetic_adapter:
        registry.register("synthetic.track", SyntheticTrackingAdapter())
    browser_adapter: PlaywrightBrowserAdapter | None = None
    if enable_synthetic_browser_adapter:
        artifact_sink = (
            FileArtifactSink(browser_trace_directory)
            if browser_trace_directory is not None
            else None
        )
        package = load_builtin_synthetic_package()
        browser_adapter = PlaywrightBrowserAdapter(
            package,
            BrowserAdapterConfig(
                base_url=synthetic_portal_url,
                trace_on_failure=artifact_sink is not None,
            ),
            artifact_sink=artifact_sink,
        )
        await browser_adapter.start()
        registry.register(package.manifest.name, browser_adapter)
    try:
        activities = AdapterActivities(registry)
        client = await connect_temporal(target, namespace=namespace)
        worker = Worker(
            client,
            task_queue=task_queue,
            workflows=[CargoMeshTransactionWorkflow],
            activities=[activities.execute],
        )
        await worker.run()
    finally:
        if browser_adapter is not None:
            await browser_adapter.close()


def main(argv: Sequence[str] | None = None) -> None:
    args = _parser().parse_args(argv)
    asyncio.run(
        run_worker(
            target=args.target,
            namespace=args.namespace,
            task_queue=args.task_queue,
            enable_synthetic_adapter=args.enable_synthetic_adapter,
            enable_synthetic_browser_adapter=args.enable_synthetic_browser_adapter,
            synthetic_portal_url=args.synthetic_portal_url,
            browser_trace_directory=args.browser_trace_directory,
        )
    )
