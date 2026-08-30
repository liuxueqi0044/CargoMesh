"""Opt-in runtime API server wiring for durable execution and access control."""

from __future__ import annotations

import argparse
import asyncio
import os
from collections.abc import Sequence

import uvicorn

from cargomesh.application.transactions import ExecutionPlanner, TransactionService
from cargomesh.booking.local import (
    synthetic_booking_credential_store,
    synthetic_booking_policy_provider,
)
from cargomesh.booking.planner import synthetic_booking_planner
from cargomesh.controlplane.access import AccessController
from cargomesh.controlplane.audit import SQLiteAuditStore
from cargomesh.controlplane.authentication import HttpJwksProvider, OIDCAuthenticator
from cargomesh.controlplane.authorization import MembershipAuthorizer
from cargomesh.controlplane.membership import SQLiteMembershipStore
from cargomesh.credentials import SQLiteCredentialBindingStore
from cargomesh.policy import PolicyProvider
from cargomesh.routing.store import SQLiteRouteOutcomeStore
from cargomesh.runtime.idempotency import SQLiteSubmissionStore
from cargomesh.runtime.planner import (
    synthetic_browser_tracking_planner,
    synthetic_optimized_tracking_planner,
    synthetic_tracking_planner,
    synthetic_verified_browser_tracking_planner,
)
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
    parser.add_argument(
        "--enable-synthetic-browser-binding",
        action="store_true",
        help="bind shipment.track.read to the Board 3 synthetic browser adapter",
    )
    parser.add_argument(
        "--enable-synthetic-verification-binding",
        action="store_true",
        help="attach the Board 4 independent synthetic ledger verification plan",
    )
    parser.add_argument(
        "--enable-synthetic-optimized-binding",
        action="store_true",
        help="enable Board 5 policy-ranked API execution with safe browser fallback",
    )
    parser.add_argument(
        "--routing-database",
        default=os.environ.get("CARGOMESH_ROUTING_DATABASE", "cargomesh-routing.sqlite3"),
        help="route outcome database shared with the worker",
    )
    parser.add_argument(
        "--enable-synthetic-booking-binding",
        action="store_true",
        help="bind only the approved and verified local DCSA Booking vertical slice",
    )
    parser.add_argument(
        "--synthetic-booking-tenant",
        default=os.environ.get("CARGOMESH_SYNTHETIC_BOOKING_TENANT", "tenant-a"),
    )
    parser.add_argument(
        "--synthetic-booking-environment",
        default=os.environ.get("CARGOMESH_SYNTHETIC_BOOKING_ENVIRONMENT", "local"),
    )
    parser.add_argument(
        "--enforce-access-control",
        action="store_true",
        help="require OIDC authentication, server-side membership authorization, and audit",
    )
    parser.add_argument("--oidc-issuer", default=os.environ.get("CARGOMESH_OIDC_ISSUER"))
    parser.add_argument("--oidc-audience", default=os.environ.get("CARGOMESH_OIDC_AUDIENCE"))
    parser.add_argument("--oidc-jwks-url", default=os.environ.get("CARGOMESH_OIDC_JWKS_URL"))
    parser.add_argument(
        "--environment-id", default=os.environ.get("CARGOMESH_ENVIRONMENT_ID")
    )
    parser.add_argument(
        "--membership-database",
        default=os.environ.get("CARGOMESH_MEMBERSHIP_DATABASE"),
    )
    parser.add_argument(
        "--audit-database", default=os.environ.get("CARGOMESH_AUDIT_DATABASE")
    )
    return parser


async def serve(args: argparse.Namespace) -> None:
    client = await connect_temporal(args.target, namespace=args.namespace)
    submissions = SQLiteSubmissionStore(args.database)
    routing_store: SQLiteRouteOutcomeStore | None = None
    membership_store: SQLiteMembershipStore | None = None
    audit_store: SQLiteAuditStore | None = None
    credential_store: SQLiteCredentialBindingStore | None = None
    policy_provider: PolicyProvider | None = None
    planner: ExecutionPlanner
    if args.enable_synthetic_booking_binding:
        planner = synthetic_booking_planner()
        credential_store = synthetic_booking_credential_store(
            tenant_id=args.synthetic_booking_tenant,
            environment_id=args.synthetic_booking_environment,
        )
        policy_provider = synthetic_booking_policy_provider(
            tenant_id=args.synthetic_booking_tenant,
            environment_id=args.synthetic_booking_environment,
        )
    elif args.enable_synthetic_optimized_binding:
        routing_store = SQLiteRouteOutcomeStore(args.routing_database)
        planner = synthetic_optimized_tracking_planner(routing_store)
    elif args.enable_synthetic_verification_binding:
        planner = synthetic_verified_browser_tracking_planner()
    elif args.enable_synthetic_browser_binding:
        planner = synthetic_browser_tracking_planner()
    else:
        planner = synthetic_tracking_planner()
    service = TransactionService(
        planner=planner,
        submissions=submissions,
        gateway=TemporalExecutionGateway(client, task_queue=args.task_queue),
        policy_provider=policy_provider,
        policy_environment_id=args.synthetic_booking_environment,
        credential_bindings=credential_store,
    )
    access_controller: AccessController | None = None
    if args.enforce_access_control:
        membership_store = SQLiteMembershipStore(args.membership_database)
        try:
            audit_store = SQLiteAuditStore(args.audit_database)
            access_controller = AccessController(
                authenticator=OIDCAuthenticator(
                    issuer=args.oidc_issuer,
                    audience=args.oidc_audience,
                    jwks_provider=HttpJwksProvider(args.oidc_jwks_url),
                ),
                authorizer=MembershipAuthorizer(membership_store),
                audit=audit_store,
                environment_id=args.environment_id,
            )
        except Exception:
            membership_store.close()
            raise
    application = create_app(
        transaction_service=service,
        access_controller=access_controller,
    )
    server = uvicorn.Server(
        uvicorn.Config(application, host=args.host, port=args.port, log_level="info")
    )
    try:
        await server.serve()
    finally:
        submissions.close()
        if routing_store is not None:
            routing_store.close()
        if audit_store is not None:
            audit_store.close()
        if membership_store is not None:
            membership_store.close()
        if credential_store is not None:
            credential_store.close()


def main(argv: Sequence[str] | None = None) -> None:
    parser = _parser()
    args = parser.parse_args(argv)
    binding_count = sum(
        (
            args.enable_synthetic_adapter_binding,
            args.enable_synthetic_browser_binding,
            args.enable_synthetic_optimized_binding,
            args.enable_synthetic_booking_binding,
        )
    )
    if binding_count != 1:
        parser.error(
            "choose exactly one explicit local binding: --enable-synthetic-adapter-binding, "
            "--enable-synthetic-browser-binding, or --enable-synthetic-optimized-binding"
            ", or --enable-synthetic-booking-binding"
        )
    if args.enable_synthetic_booking_binding and (
        not args.synthetic_booking_tenant
        or args.synthetic_booking_tenant != args.synthetic_booking_tenant.strip()
        or not args.synthetic_booking_environment
        or args.synthetic_booking_environment != args.synthetic_booking_environment.strip()
    ):
        parser.error("synthetic Booking tenant/environment configuration is invalid")
    if (
        args.enable_synthetic_verification_binding
        and not args.enable_synthetic_browser_binding
    ):
        parser.error(
            "--enable-synthetic-verification-binding requires "
            "--enable-synthetic-browser-binding"
        )
    access_values = {
        "--oidc-issuer": args.oidc_issuer,
        "--oidc-audience": args.oidc_audience,
        "--oidc-jwks-url": args.oidc_jwks_url,
        "--environment-id": args.environment_id,
        "--membership-database": args.membership_database,
        "--audit-database": args.audit_database,
    }
    configured_access_values = {
        flag: value
        for flag, value in access_values.items()
        if isinstance(value, str) and value.strip()
    }
    if args.enforce_access_control:
        missing = [flag for flag, value in access_values.items() if not value or not value.strip()]
        if missing:
            parser.error(
                "--enforce-access-control requires complete configuration: "
                + ", ".join(missing)
            )
        if any(value != value.strip() for value in access_values.values()):
            parser.error("access-control configuration values must not have surrounding space")
        try:
            jwks_provider = HttpJwksProvider(args.oidc_jwks_url)
            OIDCAuthenticator(
                issuer=args.oidc_issuer,
                audience=args.oidc_audience,
                jwks_provider=jwks_provider,
            )
            if not args.environment_id or args.environment_id != args.environment_id.strip():
                raise ValueError("invalid environment")
        except ValueError:
            parser.error("access-control configuration is invalid")
    elif configured_access_values:
        parser.error(
            "access-control configuration requires --enforce-access-control"
        )
    asyncio.run(serve(args))
