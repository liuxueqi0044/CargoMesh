from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from cargomesh.verification.models import EvidenceChannel, EvidenceObservation, VerificationReport

NOW = datetime(2026, 2, 3, 4, 5, 6, tzinfo=UTC)


def _observation(**changes: object) -> EvidenceObservation:
    values: dict[str, object] = {
        "evidence_id": "evidence-1",
        "tenant_id": "tenant-1",
        "transaction_id": "transaction-1",
        "source_record_id": "record-1",
        "source_system": "synthetic.ledger",
        "channel": EvidenceChannel.SYSTEM_RECORD,
        "collector_id": "ledger-collector",
        "collection_id": "collection-1",
        "observed_at": NOW,
        "claims": {"shipment.status": "IN_TRANSIT"},
        "synthetic": True,
    }
    values.update(changes)
    return EvidenceObservation.issue(**values)


def test_evidence_rejects_tampered_canonical_digest() -> None:
    issued = _observation()
    payload = issued.model_dump(mode="python")
    payload["content_digest"] = "sha256:" + "0" * 64

    with pytest.raises(ValidationError, match="content digest"):
        EvidenceObservation.model_validate(payload)


def test_evidence_rejects_naive_timestamps_and_invalid_lifetime() -> None:
    with pytest.raises(ValueError, match="timezone"):
        _observation(observed_at=datetime(2026, 2, 3, 4, 5, 6))
    with pytest.raises(ValidationError, match="expiry"):
        _observation(expires_at=NOW)
    normalized = _observation(observed_at=NOW.astimezone(timezone(timedelta(hours=8))))
    assert normalized.observed_at == NOW


@pytest.mark.parametrize(
    "claims",
    [
        {"authorization": "not-allowed"},
        {"shipment.status": float("nan")},
        {"shipment.status": float("inf")},
    ],
)
def test_evidence_rejects_secret_claim_names_and_non_finite_values(
    claims: dict[str, str | float]
) -> None:
    values: dict[str, object] = {
        "schema_version": "cargomesh.evidence-observation/v1",
        "evidence_id": "evidence-invalid",
        "tenant_id": "tenant-1",
        "transaction_id": "transaction-1",
        "source_record_id": "record-invalid",
        "source_system": "synthetic.ledger",
        "channel": EvidenceChannel.SYSTEM_RECORD,
        "collector_id": "ledger-collector",
        "collection_id": "collection-invalid",
        "observed_at": NOW,
        "claims": claims,
        "content_digest": "sha256:" + "0" * 64,
    }
    with pytest.raises(ValueError):
        EvidenceObservation.model_validate(values)


def test_report_rejects_tampered_canonical_digest() -> None:
    report = VerificationReport.issue(
        transaction_id="transaction-1",
        business_digest="sha256:" + "a" * 64,
        verdict="HALTED",
        required_level="L1",
        achieved_level="L0",
        evaluated_at=NOW,
        reasons=("independence_insufficient",),
        claims=(),
        evidence=(),
    )
    payload = report.model_dump(mode="python")
    payload["report_digest"] = "sha256:" + "f" * 64

    with pytest.raises(ValidationError, match="report digest"):
        VerificationReport.model_validate(payload)
