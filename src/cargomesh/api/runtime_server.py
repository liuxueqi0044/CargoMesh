"""Opt-in runtime API server wiring for the Board 2 local demonstration."""

from __future__ import annotations

import argparse
import asyncio
import os
from collections.abc import Sequence

import uvicorn

from cargomesh.application.transactions import TransactionService
from cargomesh.runtime.idempotency import SQLiteSubmissionStore
from cargomesh.runtime.planner import synthetic_tracking_planner
from cargomesh.runtime.temporal import TemporalExecutionGateway, connect_temporal

from .main import create_app


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the CargoMesh durable runtime API")
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
        "--database",
        default=os.environ.get("CARGOMESH_SUBMISSION_DATABASE", "cargomesh-submissions.sqlite3"),
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument(
        "--enable-synthetic-adapter-binding",
        action="store_true",
        help="explicitly bind shipment.track.read to the non-carrier local demo adapter",
    )
    return parser


async def serve(args: argparse.Namespace) -> None:
    client = await connect_temporal(args.target, namespace=args.namespace)
    submissions = SQLiteSubmissionStore(args.database)
    service = TransactionService(
        planner=synthetic_tracking_planner(),
        submissions=submissions,
        gateway=TemporalExecutionGateway(client, task_queue=args.task_queue),
    )
    application = create_app(transaction_service=service)
    server = uvicorn.Server(
        uvicorn.Config(application, host=args.host, port=args.port, log_level="info")
    )
    try:
        await server.serve()
    finally:
        submissions.close()


def main(argv: Sequence[str] | None = None) -> None:
    parser = _parser()
    args = parser.parse_args(argv)
    if not args.enable_synthetic_adapter_binding:
        parser.error(
            "Board 2 ships no carrier adapter; use --enable-synthetic-adapter-binding "
            "only for the local demonstration"
        )
    asyncio.run(serve(args))
