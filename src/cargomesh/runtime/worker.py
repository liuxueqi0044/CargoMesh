"""CargoMesh Temporal worker entry point."""

from __future__ import annotations

import argparse
import asyncio
import os
from collections.abc import Sequence

from temporalio.worker import Worker

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
    return parser


async def run_worker(
    *, target: str, namespace: str, task_queue: str, enable_synthetic_adapter: bool
) -> None:
    registry = AdapterRegistry()
    if enable_synthetic_adapter:
        registry.register("synthetic.track", SyntheticTrackingAdapter())
    activities = AdapterActivities(registry)
    client = await connect_temporal(target, namespace=namespace)
    worker = Worker(
        client,
        task_queue=task_queue,
        workflows=[CargoMeshTransactionWorkflow],
        activities=[activities.execute],
    )
    await worker.run()


def main(argv: Sequence[str] | None = None) -> None:
    args = _parser().parse_args(argv)
    asyncio.run(
        run_worker(
            target=args.target,
            namespace=args.namespace,
            task_queue=args.task_queue,
            enable_synthetic_adapter=args.enable_synthetic_adapter,
        )
    )
