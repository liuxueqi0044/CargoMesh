from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from cargomesh.verification.synthetic_evidence import create_synthetic_evidence_service

FIXED_CLOCK = datetime(2026, 1, 2, 3, 4, 5, 678900, tzinfo=UTC)


def test_healthy_record_has_complete_independent_evidence_shape() -> None:
    client = TestClient(create_synthetic_evidence_service(clock=lambda: FIXED_CLOCK))

    health = client.get("/healthz")
    evidence = client.get("/v1/evidence/shipments/CBR-001")

    assert health.status_code == 200
    assert health.json() == {"status": "ok", "service": "synthetic-evidence"}
    assert evidence.status_code == 200
    assert evidence.json() == {
        "schema_version": "cargomesh.synthetic-evidence/v1",
        "source_record_id": "synthetic-ledger:CBR-001",
        "source_system": "synthetic.ledger",
        "channel": "SYSTEM_RECORD",
        "subject_reference": "CBR-001",
        "observed_at": "2026-01-02T03:04:05.678900Z",
        "claims": {"shipment.reference": "CBR-001", "shipment.status": "IN_TRANSIT"},
        "synthetic": True,
    }


def test_app_freezes_clock_once_for_stable_replays() -> None:
    calls = 0

    def clock() -> datetime:
        nonlocal calls
        calls += 1
        return FIXED_CLOCK + timedelta(seconds=calls)

    client = TestClient(create_synthetic_evidence_service(clock=clock))
    first = client.get("/v1/evidence/shipments/CBR-002")
    second = client.get("/v1/evidence/shipments/CBR-002")

    assert calls == 1
    expected_timestamp = "2026-01-02T03:04:06.678900Z"
    assert first.json()["observed_at"] == expected_timestamp
    assert second.json()["observed_at"] == expected_timestamp


@pytest.mark.parametrize(
    ("variant", "expected_status", "expected_value"),
    [
        ("conflict", 200, "DELAYED"),
        ("missing", 404, None),
        ("stale", 200, "2025-01-02T03:04:05.678900Z"),
        ("server_error", 503, None),
    ],
)
def test_fault_variants(
    variant: str, expected_status: int, expected_value: str | None
) -> None:
    client = TestClient(
        create_synthetic_evidence_service(variant=variant, clock=lambda: FIXED_CLOCK)  # type: ignore[arg-type]
    )
    response = client.get("/v1/evidence/shipments/CBR-001")

    assert response.status_code == expected_status
    if variant == "conflict":
        assert response.json()["claims"]["shipment.status"] == expected_value
    elif variant == "stale":
        assert response.json()["observed_at"] == expected_value


def test_unknown_reference_is_not_reflected_and_is_not_found() -> None:
    client = TestClient(create_synthetic_evidence_service(clock=lambda: FIXED_CLOCK))
    response = client.get("/v1/evidence/shipments/%3Cscript%3Ealert(1)%3C/script%3E")

    assert response.status_code == 404
    assert "script" not in response.text.lower()


def test_variant_delay_and_clock_boundaries() -> None:
    with pytest.raises(ValueError):
        create_synthetic_evidence_service(delay_ms=-1)
    with pytest.raises(ValueError):
        create_synthetic_evidence_service(delay_ms=5001)
    with pytest.raises(ValueError):
        create_synthetic_evidence_service(delay_ms=True)
    with pytest.raises(ValueError):
        create_synthetic_evidence_service(variant="not-a-variant")  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        create_synthetic_evidence_service(clock=lambda: datetime(2026, 1, 1))

    client = TestClient(create_synthetic_evidence_service(delay_ms=1, clock=lambda: FIXED_CLOCK))
    assert client.get("/healthz").status_code == 200
    assert client.get("/v1/evidence/shipments/CBR-002").status_code == 200
