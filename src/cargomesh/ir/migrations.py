"""Explicit, deterministic schema migrations for persisted Transaction IR."""

from __future__ import annotations

import json
from collections import deque
from collections.abc import Callable, Mapping
from copy import deepcopy
from dataclasses import dataclass
from hashlib import sha256
from typing import Any

from pydantic import ValidationError

from .models import IR_SCHEMA_VERSION, TransactionCommand

MigrationFunction = Callable[[dict[str, Any]], dict[str, Any]]


class MigrationError(ValueError):
    """Raised when a payload cannot be safely migrated."""


@dataclass(frozen=True, slots=True)
class MigrationStep:
    source_version: str
    target_version: str
    migrate: MigrationFunction


@dataclass(frozen=True, slots=True)
class MigrationDerivation:
    """Auditable derived copy; callers persist this beside the untouched source."""

    command: TransactionCommand
    source_schema_version: str
    target_schema_version: str
    applied_steps: tuple[tuple[str, str], ...]
    original_canonical_json: str
    migrated_canonical_json: str
    original_digest: str
    migrated_digest: str


class MigrationRegistry:
    """Small directed migration graph with explicit, testable steps."""

    def __init__(self) -> None:
        self._steps: dict[tuple[str, str], MigrationStep] = {}

    def register(self, step: MigrationStep) -> None:
        key = (step.source_version, step.target_version)
        if step.source_version == step.target_version:
            raise MigrationError("migration source and target versions must differ")
        if key in self._steps:
            raise MigrationError(f"migration already registered: {key!r}")
        self._steps[key] = step

    def _find_path(self, source_version: str, target_version: str) -> list[MigrationStep]:
        queue: deque[tuple[str, list[MigrationStep]]] = deque([(source_version, [])])
        visited = {source_version}
        while queue:
            current, path = queue.popleft()
            for (edge_source, edge_target), step in self._steps.items():
                if edge_source != current or edge_target in visited:
                    continue
                next_path = [*path, step]
                if edge_target == target_version:
                    return next_path
                visited.add(edge_target)
                queue.append((edge_target, next_path))
        raise MigrationError(f"no migration path from {source_version!r} to {target_version!r}")

    def migrate(
        self,
        payload: Mapping[str, Any],
        target_version: str = IR_SCHEMA_VERSION,
    ) -> TransactionCommand:
        return self.derive(payload, target_version).command

    def derive(
        self,
        payload: Mapping[str, Any],
        target_version: str = IR_SCHEMA_VERSION,
    ) -> MigrationDerivation:
        """Create a validated derived copy and retain both document digests."""

        source_version = payload.get("schema_version")
        if not isinstance(source_version, str):
            raise MigrationError("payload must contain a string schema_version")
        original = deepcopy(dict(payload))
        working = deepcopy(original)
        applied: list[tuple[str, str]] = []
        if source_version != target_version:
            for step in self._find_path(source_version, target_version):
                working = step.migrate(working)
                if working.get("schema_version") != step.target_version:
                    raise MigrationError(
                        f"migration {step.source_version!r} -> {step.target_version!r} "
                        "did not set the target schema_version"
                    )
                applied.append((step.source_version, step.target_version))
        try:
            command = TransactionCommand.model_validate(working)
        except ValidationError as exc:
            raise MigrationError("migrated payload does not satisfy the target schema") from exc
        original_json = _canonical_document_json(original)
        migrated_json = _canonical_document_json(command.model_dump(mode="json", exclude_none=True))
        return MigrationDerivation(
            command=command,
            source_schema_version=source_version,
            target_schema_version=target_version,
            applied_steps=tuple(applied),
            original_canonical_json=original_json,
            migrated_canonical_json=migrated_json,
            original_digest=_document_digest(original_json),
            migrated_digest=_document_digest(migrated_json),
        )


def _canonical_document_json(payload: Mapping[str, Any]) -> str:
    try:
        return json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise MigrationError("migration payload must be JSON-compatible") from exc


def _document_digest(canonical_json: str) -> str:
    return f"sha256:{sha256(canonical_json.encode('utf-8')).hexdigest()}"


def _v0alpha1_to_v1(payload: dict[str, Any]) -> dict[str, Any]:
    """Migrate the documented prototype tracking-query payload into IR v1."""

    required = {
        "tenantId",
        "externalReference",
        "requestedAt",
        "referenceType",
        "referenceValue",
    }
    missing = required.difference(payload)
    if missing:
        raise MigrationError("v0alpha1 payload is missing: " + ", ".join(sorted(missing)))
    reference_field_by_type = {
        "carrierBookingReference": "carrier_booking_reference",
        "transportDocumentReference": "transport_document_reference",
        "equipmentReference": "equipment_reference",
    }
    reference_type = payload["referenceType"]
    if reference_type not in reference_field_by_type:
        raise MigrationError(f"unsupported v0alpha1 referenceType: {reference_type!r}")
    event_types = payload.get("eventTypes", [])
    return {
        "schema_version": IR_SCHEMA_VERSION,
        "transaction_id": payload.get("transactionId"),
        "tenant_id": payload["tenantId"],
        "transaction_type": "shipment.track",
        "external_reference": payload["externalReference"],
        "requested_at": payload["requestedAt"],
        "subject": {
            "kind": "shipment",
            reference_field_by_type[reference_type]: payload["referenceValue"],
        },
        "parameters": {"event_types": event_types},
        "requested_effects": ["latest_transport_events_returned"],
        "verification_requirements": {"minimum_independence_level": "L1"},
        "risk_class": "READ_ONLY",
        "required_capabilities": ["shipment.track.read"],
        "extensions": {},
    }


default_migration_registry = MigrationRegistry()
default_migration_registry.register(
    MigrationStep(
        source_version="cargomesh.transaction/v0alpha1",
        target_version=IR_SCHEMA_VERSION,
        migrate=_v0alpha1_to_v1,
    )
)
