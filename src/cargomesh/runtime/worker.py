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
from cargomesh.adapters.http_api import (
    SyntheticTrackingHttpAdapter,
    SyntheticTrackingHttpAdapterConfig,
)
from cargomesh.adapters.package import load_builtin_synthetic_package
from cargomesh.booking.adapter import BookingHttpAdapter, BookingHttpAdapterConfig
from cargomesh.booking.draft import BookingDraftAdapter
from cargomesh.booking.evidence import (
    BookingEvidenceCollector,
    BookingEvidenceCollectorConfig,
)
from cargomesh.booking.local import (
    synthetic_booking_credential_store,
    synthetic_booking_secret_provider,
)
from cargomesh.credentials import SQLiteCredentialBindingStore
from cargomesh.routing.store import SQLiteRouteOutcomeStore
from cargomesh.verification.activities import VerificationActivities
from cargomesh.verification.collectors import EvidenceCollectorRegistry
from cargomesh.verification.http_collector import (
    SyntheticLedgerHttpCollector,
    SyntheticLedgerHttpCollectorConfig,
)
from cargomesh.verification.store import SQLiteEvidenceStore

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
        "--enable-synthetic-api-adapter",
        action="store_true",
        help="enable the strict Board 5 local synthetic tracking API adapter",
    )
    parser.add_argument(
        "--synthetic-api-url",
        default=os.environ.get("CARGOMESH_SYNTHETIC_API_URL", "http://127.0.0.1:8767"),
        help="origin of the local synthetic tracking API",
    )
    parser.add_argument(
        "--enable-routing-outcomes",
        action="store_true",
        help="persist Board 5 route outcomes for health scoring and circuit breaking",
    )
    parser.add_argument(
        "--routing-database",
        type=Path,
        default=Path(
            os.environ.get("CARGOMESH_ROUTING_DATABASE", "cargomesh-routing.sqlite3")
        ),
        help="append-only SQLite route outcome database",
    )
    parser.add_argument(
        "--browser-trace-directory",
        type=Path,
        default=None,
        help="opt in to bounded failure traces stored outside workflow history",
    )
    parser.add_argument(
        "--enable-synthetic-verifier",
        action="store_true",
        help="enable the separate Board 4 synthetic ledger evidence collector",
    )
    parser.add_argument(
        "--synthetic-evidence-url",
        default=os.environ.get("CARGOMESH_SYNTHETIC_EVIDENCE_URL", "http://127.0.0.1:8766"),
        help="origin of the independent local synthetic evidence service",
    )
    parser.add_argument(
        "--evidence-database",
        type=Path,
        default=Path(
            os.environ.get("CARGOMESH_EVIDENCE_DATABASE", "cargomesh-evidence.sqlite3")
        ),
        help="append-only SQLite evidence receipt database",
    )
    parser.add_argument(
        "--enable-synthetic-booking-adapter",
        action="store_true",
        help="enable the credential-scoped local DCSA Booking demo adapter",
    )
    parser.add_argument(
        "--synthetic-booking-url",
        default=os.environ.get("CARGOMESH_SYNTHETIC_BOOKING_URL", "http://127.0.0.1:8091"),
    )
    parser.add_argument(
        "--enable-synthetic-booking-verifier",
        action="store_true",
        help="enable the separate local synthetic Booking ledger collector",
    )
    parser.add_argument(
        "--synthetic-booking-ledger-url",
        default=os.environ.get(
            "CARGOMESH_SYNTHETIC_BOOKING_LEDGER_URL", "http://127.0.0.1:8092"
        ),
    )
    parser.add_argument(
        "--synthetic-booking-tenant",
        default=os.environ.get("CARGOMESH_SYNTHETIC_BOOKING_TENANT", "tenant-a"),
    )
    parser.add_argument(
        "--synthetic-booking-environment",
        default=os.environ.get("CARGOMESH_SYNTHETIC_BOOKING_ENVIRONMENT", "local"),
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
    enable_synthetic_api_adapter: bool = False,
    synthetic_api_url: str = "http://127.0.0.1:8767",
    enable_routing_outcomes: bool = False,
    routing_database: Path | str = "cargomesh-routing.sqlite3",
    browser_trace_directory: Path | None = None,
    enable_synthetic_verifier: bool = False,
    synthetic_evidence_url: str = "http://127.0.0.1:8766",
    evidence_database: Path | str = "cargomesh-evidence.sqlite3",
    enable_synthetic_booking_adapter: bool = False,
    synthetic_booking_url: str = "http://127.0.0.1:8091",
    enable_synthetic_booking_verifier: bool = False,
    synthetic_booking_ledger_url: str = "http://127.0.0.1:8092",
    synthetic_booking_tenant: str = "tenant-a",
    synthetic_booking_environment: str = "local",
) -> None:
    registry = AdapterRegistry()
    evidence_collectors = EvidenceCollectorRegistry()
    if enable_synthetic_verifier:
        evidence_collectors.register(
            "synthetic.evidence.track",
            SyntheticLedgerHttpCollector(
                SyntheticLedgerHttpCollectorConfig(synthetic_evidence_url)
            ),
        )
    if enable_synthetic_booking_verifier:
        evidence_collectors.register(
            "synthetic.booking.ledger",
            BookingEvidenceCollector(
                BookingEvidenceCollectorConfig(synthetic_booking_ledger_url)
            ),
        )
    evidence_store = SQLiteEvidenceStore(
        evidence_database
        if enable_synthetic_verifier or enable_synthetic_booking_verifier
        else ":memory:"
    )
    outcome_store = (
        SQLiteRouteOutcomeStore(routing_database) if enable_routing_outcomes else None
    )
    browser_adapter: PlaywrightBrowserAdapter | None = None
    credential_store: SQLiteCredentialBindingStore | None = None
    try:
        if enable_synthetic_adapter:
            registry.register("synthetic.track", SyntheticTrackingAdapter())
        if enable_synthetic_api_adapter:
            registry.register(
                "synthetic.api.track",
                SyntheticTrackingHttpAdapter(
                    SyntheticTrackingHttpAdapterConfig(synthetic_api_url)
                ),
            )
        if enable_synthetic_booking_adapter:
            registry.register("synthetic.booking.draft", BookingDraftAdapter())
            registry.register_credential_aware(
                "synthetic.booking.api",
                BookingHttpAdapter(BookingHttpAdapterConfig(synthetic_booking_url)),
            )
            credential_store = synthetic_booking_credential_store(
                tenant_id=synthetic_booking_tenant,
                environment_id=synthetic_booking_environment,
            )
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
        activities = AdapterActivities(
            registry,
            outcome_store=outcome_store,
            credential_bindings=credential_store,
            secret_providers=(
                {"memory": synthetic_booking_secret_provider()}
                if enable_synthetic_booking_adapter
                else None
            ),
        )
        verification_activities = VerificationActivities(
            evidence_collectors, evidence_store
        )
        client = await connect_temporal(target, namespace=namespace)
        worker = Worker(
            client,
            task_queue=task_queue,
            workflows=[CargoMeshTransactionWorkflow],
            activities=[activities.execute, verification_activities.verify],
        )
        await worker.run()
    finally:
        if browser_adapter is not None:
            await browser_adapter.close()
        evidence_store.close()
        if outcome_store is not None:
            outcome_store.close()
        if credential_store is not None:
            credential_store.close()


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
            enable_synthetic_api_adapter=args.enable_synthetic_api_adapter,
            synthetic_api_url=args.synthetic_api_url,
            enable_routing_outcomes=args.enable_routing_outcomes,
            routing_database=args.routing_database,
            browser_trace_directory=args.browser_trace_directory,
            enable_synthetic_verifier=args.enable_synthetic_verifier,
            synthetic_evidence_url=args.synthetic_evidence_url,
            evidence_database=args.evidence_database,
            enable_synthetic_booking_adapter=args.enable_synthetic_booking_adapter,
            synthetic_booking_url=args.synthetic_booking_url,
            enable_synthetic_booking_verifier=args.enable_synthetic_booking_verifier,
            synthetic_booking_ledger_url=args.synthetic_booking_ledger_url,
            synthetic_booking_tenant=args.synthetic_booking_tenant,
            synthetic_booking_environment=args.synthetic_booking_environment,
        )
    )
