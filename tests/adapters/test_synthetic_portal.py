from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from cargomesh.adapters.synthetic_portal import create_synthetic_portal


def test_health_and_accessible_healthy_markup() -> None:
    client = TestClient(create_synthetic_portal())

    health = client.get("/healthz")
    page = client.get("/track?bookingReference=CBR-001")

    assert health.status_code == 200
    assert health.json()["status"] == "ok"
    assert '<h1>Track shipment</h1>' in page.text
    assert 'data-testid="synthetic-notice"' in page.text
    assert "No carrier transaction" in page.text
    assert '<label for="booking-reference">Booking reference</label>' in page.text
    assert '<button type="submit">Search</button>' in page.text
    assert "<script" not in page.text.lower()
    assert '<h2 id="tracking-result-heading">Tracking result</h2>' in page.text
    assert 'data-testid="tracking-reference">CBR-001<' in page.text
    assert 'data-testid="tracking-status">IN_TRANSIT<' in page.text


def test_known_records_and_unknown_reference() -> None:
    client = TestClient(create_synthetic_portal())

    delivered = client.get("/track", params={"bookingReference": "CBR-002"})
    unknown = client.get("/track", params={"bookingReference": "NOT-KNOWN"})

    assert 'data-testid="tracking-status">DELIVERED<' in delivered.text
    assert 'data-testid="tracking-not-found"' in unknown.text
    assert 'data-testid="tracking-status"' not in unknown.text


def test_reflected_reference_is_html_escaped() -> None:
    client = TestClient(create_synthetic_portal())
    page = client.get("/track", params={"bookingReference": '<img src=x onerror="alert(1)">'})

    assert page.status_code == 200
    assert "&lt;img src=x onerror=&quot;alert(1)&quot;&gt;" in page.text
    assert '<img src=x onerror="alert(1)">' not in page.text


@pytest.mark.parametrize("variant", ["label_drift", "silent_drop", "server_error"])
def test_fault_variants(variant: str) -> None:
    client = TestClient(create_synthetic_portal(variant=variant))  # type: ignore[arg-type]
    page = client.get("/track", params={"bookingReference": "CBR-001"})

    if variant == "label_drift":
        assert page.status_code == 200
        assert '<label for="booking-reference">Shipment reference</label>' in page.text
        assert 'data-testid="tracking-status">IN_TRANSIT<' in page.text
    elif variant == "silent_drop":
        assert page.status_code == 200
        assert "No tracking result available." in page.text
        assert 'data-testid="tracking-status"' not in page.text
    else:
        assert page.status_code == 503
        assert "No carrier transaction" in page.text


def test_delay_bounds_and_health_is_not_delayed() -> None:
    with pytest.raises(ValueError):
        create_synthetic_portal(delay_ms=-1)
    with pytest.raises(ValueError):
        create_synthetic_portal(delay_ms=5001)
    with pytest.raises(ValueError):
        create_synthetic_portal(variant="not-a-variant")  # type: ignore[arg-type]

    client = TestClient(create_synthetic_portal(delay_ms=1))
    assert client.get("/healthz").status_code == 200
    assert client.get("/track", params={"bookingReference": "CBR-001"}).status_code == 200
