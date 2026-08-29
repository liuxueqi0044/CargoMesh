from datetime import UTC, datetime

import pytest

from cargomesh.ir import (
    MigrationError,
    MigrationRegistry,
    default_migration_registry,
)


def test_v0alpha1_tracking_query_migrates_to_v1() -> None:
    migrated = default_migration_registry.migrate(
        {
            "schema_version": "cargomesh.transaction/v0alpha1",
            "transactionId": "txn-old",
            "tenantId": "tenant-a",
            "externalReference": "SO-1",
            "requestedAt": datetime(2026, 8, 30, tzinfo=UTC).isoformat(),
            "referenceType": "equipmentReference",
            "referenceValue": "MSCU1234567",
            "eventTypes": ["EQUIPMENT"],
        }
    )

    assert migrated.schema_version == "cargomesh.transaction/v1"
    assert migrated.subject.equipment_reference == "MSCU1234567"
    assert migrated.parameters.event_types[0].value == "EQUIPMENT"


def test_unknown_schema_version_fails_without_guessing() -> None:
    registry = MigrationRegistry()

    with pytest.raises(MigrationError, match="no migration path"):
        registry.migrate(
            {"schema_version": "vendor.unknown/v7"},
            target_version="cargomesh.transaction/v1",
        )


def test_migration_requires_schema_version() -> None:
    with pytest.raises(MigrationError, match="schema_version"):
        default_migration_registry.migrate({})


def test_migration_derivation_retains_both_payloads_and_digests() -> None:
    source = {
        "schema_version": "cargomesh.transaction/v0alpha1",
        "tenantId": "tenant-a",
        "externalReference": "SO-1",
        "requestedAt": "2026-08-30T00:00:00Z",
        "referenceType": "equipmentReference",
        "referenceValue": "MSCU1234567",
    }

    derivation = default_migration_registry.derive(source)

    assert derivation.applied_steps == (
        ("cargomesh.transaction/v0alpha1", "cargomesh.transaction/v1"),
    )
    assert derivation.original_digest.startswith("sha256:")
    assert derivation.migrated_digest.startswith("sha256:")
    assert derivation.original_digest != derivation.migrated_digest
    assert source["schema_version"] == "cargomesh.transaction/v0alpha1"
