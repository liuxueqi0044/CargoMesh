from __future__ import annotations

import hashlib
from datetime import UTC, datetime

import pytest

from cargomesh.ir.enums import VerificationLevel
from cargomesh.platform.usage import SQLiteUsageMeter, UsageConflict, UsageError
from cargomesh.verification.models import (
    ClaimOutcome,
    ClaimResult,
    EvidenceChannel,
    EvidenceReceiptSummary,
    VerificationReport,
    VerificationVerdict,
)

NOW = datetime(2042, 1, 2, 3, 4, 5, tzinfo=UTC)


def digest(char: str) -> str:
    return "sha256:" + hashlib.sha256(char.encode()).hexdigest()


def report(
    *, verdict: VerificationVerdict = VerificationVerdict.VERIFIED, transaction_id: str = "tx-1"
) -> VerificationReport:
    claims = (
        ClaimResult(
            claim="shipment.status",
            outcome=ClaimOutcome.MATCH,
            expected="IN_TRANSIT",
            observed=("IN_TRANSIT",),
        ),
    )
    evidence = (
        EvidenceReceiptSummary(
            evidence_id="evidence-1",
            source_record_id="record-1",
            source_system="ledger",
            channel=EvidenceChannel.SYSTEM_RECORD,
            collector_id="collector",
            collection_id="collection-1",
            observed_at=NOW,
            content_digest=digest("e"),
            synthetic=False,
        ),
    )
    return VerificationReport.issue(
        transaction_id=transaction_id,
        business_digest=digest("b"),
        verdict=verdict,
        required_level=VerificationLevel.L1,
        achieved_level=VerificationLevel.L1,
        evaluated_at=NOW,
        reasons=("evidence_verified",),
        claims=claims,
        evidence=evidence,
        synthetic=False,
    )


def test_meter_requires_verified_report_and_replays_exactly(tmp_path) -> None:
    meter = SQLiteUsageMeter(tmp_path / "usage.sqlite3")
    verified = report()
    first = meter.record(
        verified,
        tenant_id="tenant-a",
        environment_id="prod",
        transaction_id="tx-1",
        capability_digest=digest("c"),
        units=3,
    )
    assert (
        meter.record(
            verified,
            tenant_id="tenant-a",
            environment_id="prod",
            transaction_id="tx-1",
            capability_digest=digest("c"),
            units=3,
        )
        == first
    )
    with pytest.raises(UsageConflict):
        meter.record(
            verified,
            tenant_id="tenant-a",
            environment_id="prod",
            transaction_id="tx-1",
            capability_digest=digest("different"),
            units=3,
        )
    assert meter.get(tenant_id="tenant-a", environment_id="prod", transaction_id="tx-1") == first
    assert meter.get(tenant_id="other", environment_id="prod", transaction_id="tx-1") is None
    meter.close()


def test_meter_rejects_non_verified_and_scope_mismatch(tmp_path) -> None:
    meter = SQLiteUsageMeter(tmp_path / "usage.sqlite3")
    with pytest.raises(UsageError) as halted:
        meter.record(
            report(verdict=VerificationVerdict.HALTED),
            tenant_id="tenant-a",
            environment_id="prod",
            transaction_id="tx-1",
            capability_digest=digest("c"),
            units=1,
        )
    assert halted.value.code == "usage_not_verified"
    with pytest.raises(UsageError) as mismatch:
        meter.record(
            report(),
            tenant_id="tenant-a",
            environment_id="prod",
            transaction_id="tx-other",
            capability_digest=digest("c"),
            units=1,
        )
    assert mismatch.value.code == "usage_scope_mismatch"


def test_meter_rejects_synthetic_and_cross_tenant_report_reuse(tmp_path) -> None:
    meter = SQLiteUsageMeter(tmp_path / "usage-safe.sqlite3")
    verified = report()
    meter.record(
        verified,
        tenant_id="tenant-a",
        environment_id="prod",
        transaction_id="tx-1",
        capability_digest=digest("c"),
        units=1,
    )
    with pytest.raises(UsageConflict):
        meter.record(
            verified,
            tenant_id="tenant-b",
            environment_id="prod",
            transaction_id="tx-1",
            capability_digest=digest("c"),
            units=1,
        )
    synthetic = report().model_copy(update={"synthetic": True})
    synthetic_values = synthetic.model_dump(exclude={"report_digest"})
    synthetic = VerificationReport.issue(**synthetic_values)
    with pytest.raises(UsageError) as rejected:
        meter.record(
            synthetic,
            tenant_id="tenant-c",
            environment_id="prod",
            transaction_id="tx-1",
            capability_digest=digest("c"),
            units=1,
        )
    assert rejected.value.code == "usage_synthetic_not_billable"


def test_meter_rejects_tampering_and_never_stores_payload(tmp_path) -> None:
    meter = SQLiteUsageMeter(tmp_path / "usage.sqlite3")
    item = meter.record(
        report(),
        tenant_id="tenant-a",
        environment_id="prod",
        transaction_id="tx-1",
        capability_digest=digest("c"),
        units=1,
    )
    meter._connection.execute(  # type: ignore[attr-defined]
        "UPDATE usage_meters SET units=? WHERE meter_digest=?", (2, item.meter_digest)
    )
    with pytest.raises(UsageError) as invalid:
        meter.get(tenant_id="tenant-a", environment_id="prod", transaction_id="tx-1")
    assert invalid.value.code == "usage_record_invalid"
    columns = {
        row[1]
        for row in meter._connection.execute("PRAGMA table_info(usage_meters)")  # type: ignore[attr-defined]
    }
    assert not columns.intersection({"claims", "input", "price", "business_payload"})
