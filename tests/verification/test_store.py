from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from cargomesh.verification.models import EvidenceChannel, EvidenceObservation
from cargomesh.verification.store import EvidenceConflict, EvidenceStoreError, SQLiteEvidenceStore


def observation(*, digest_suffix: str = "", tenant_id: str = "tenant-a") -> EvidenceObservation:
    return EvidenceObservation.issue(
        evidence_id="evidence-1",
        tenant_id=tenant_id,
        transaction_id="tx-1",
        source_record_id="record-1",
        source_system="synthetic.ledger",
        channel=EvidenceChannel.SYSTEM_RECORD,
        collector_id="collector-1",
        collection_id="collection-1",
        observed_at=datetime(2026, 1, 1, tzinfo=UTC),
        claims={"shipment.status": "IN_TRANSIT" + digest_suffix},
        synthetic=True,
    )


def test_append_read_and_same_digest_replay() -> None:
    with SQLiteEvidenceStore(":memory:") as store:
        first = observation()
        assert store.append(first).content_digest == first.content_digest
        replay = store.append(first)

        assert replay == first
        assert store.get("tenant-a", "evidence-1") == first
        assert store.get("other-tenant", "evidence-1") is None


def test_different_digest_is_conflict() -> None:
    with SQLiteEvidenceStore(":memory:") as store:
        store.append(observation())
        with pytest.raises(EvidenceConflict):
            store.append(observation(digest_suffix="-changed"))


def test_file_store_uses_wal_and_close_is_enforced(tmp_path: Path) -> None:
    path = tmp_path / "receipts.sqlite"
    store = SQLiteEvidenceStore(path)
    try:
        journal_mode = store._connection.execute("PRAGMA journal_mode").fetchone()[0]
        assert journal_mode.lower() == "wal"
    finally:
        store.close()

    with pytest.raises(EvidenceStoreError):
        store.get("tenant-a", "evidence-1")
