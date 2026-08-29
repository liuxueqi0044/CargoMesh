from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from cargomesh.adapters.synthetic_api import create_synthetic_tracking_api


def test_health_and_healthy_tracking_response() -> None:
    client = TestClient(create_synthetic_tracking_api())
    health = client.get("/healthz")
    response = client.get("/v1/shipments/CBR-001")

    assert health.status_code == 200
    assert health.json() == {"status": "ok", "service": "synthetic-api"}
    assert response.status_code == 200
    assert response.json() == {
        "schema_version": "cargomesh.synthetic-api/v1",
        "source_record_id": "synthetic-api:CBR-001",
        "source_system": "synthetic.api",
        "subject_reference": "CBR-001",
        "data": {
            "shipment.reference": "CBR-001",
            "shipment.status": "IN_TRANSIT",
        },
        "synthetic": True,
    }


def test_known_delivered_record_and_unknown_reference_is_not_reflected() -> None:
    client = TestClient(create_synthetic_tracking_api())
    delivered = client.get("/v1/shipments/CBR-002")
    unknown = client.get("/v1/shipments/untrusted-reference")

    assert delivered.status_code == 200
    assert delivered.json()["data"]["shipment.status"] == "DELIVERED"
    assert unknown.status_code == 404
    assert "untrusted-reference" not in unknown.text


@pytest.mark.parametrize("variant", ["server_error", "malformed", "not_found"])
def test_fault_variants(variant: str) -> None:
    client = TestClient(create_synthetic_tracking_api(variant=variant))  # type: ignore[arg-type]
    response = client.get("/v1/shipments/CBR-001")

    if variant == "server_error":
        assert response.status_code == 503
    elif variant == "malformed":
        assert response.status_code == 200
        payload = response.json()
        assert payload["schema_version"] != "cargomesh.synthetic-api/v1"
        assert "source_record_id" not in payload
        assert "shipment.status" not in payload["data"]
    else:
        assert response.status_code == 404


def test_delay_bounds_and_health_is_not_delayed() -> None:
    with pytest.raises(ValueError):
        create_synthetic_tracking_api(delay_ms=-1)
    with pytest.raises(ValueError):
        create_synthetic_tracking_api(delay_ms=5001)
    with pytest.raises(ValueError):
        create_synthetic_tracking_api(delay_ms=True)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        create_synthetic_tracking_api(variant="not-a-variant")  # type: ignore[arg-type]

    client = TestClient(create_synthetic_tracking_api(delay_ms=1))
    assert client.get("/healthz").status_code == 200
    assert client.get("/v1/shipments/CBR-001").status_code == 200
