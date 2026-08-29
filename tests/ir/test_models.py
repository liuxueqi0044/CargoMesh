from datetime import UTC, datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from cargomesh.ir import (
    DateTimeFilter,
    EventType,
    ShipmentSubject,
    TrackFilters,
    TransactionCommand,
    business_digest,
    canonical_business_json,
)


def make_command(**overrides: object) -> TransactionCommand:
    values: dict[str, object] = {
        "transaction_id": "txn-one",
        "tenant_id": "tenant-a",
        "external_reference": "BOL-123",
        "requested_at": datetime(2026, 8, 30, 9, 0, tzinfo=UTC),
        "subject": ShipmentSubject(transport_document_reference="BOL-123"),
        "parameters": TrackFilters(event_types=(EventType.SHIPMENT,)),
        "extensions": {
            "example.com/tracking-options/v1": {"include_history": True, "priority": 2}
        },
    }
    values.update(overrides)
    return TransactionCommand.model_validate(values)


def test_subject_requires_at_least_one_identifier() -> None:
    with pytest.raises(ValidationError, match="at least one business identifier"):
        ShipmentSubject()


def test_extension_namespace_must_be_versioned_reverse_dns() -> None:
    with pytest.raises(ValidationError, match="extension keys"):
        make_command(extensions={"carrier_x/options": {"value": 1}})


def test_filter_collections_reject_duplicates() -> None:
    with pytest.raises(ValidationError, match="must not contain duplicates"):
        TrackFilters(event_types=(EventType.SHIPMENT, EventType.SHIPMENT))


def test_business_digest_excludes_runtime_identity_and_request_time() -> None:
    first = make_command()
    second = make_command(
        transaction_id="txn-two",
        requested_at=datetime(2026, 8, 31, 17, 0, tzinfo=timezone(timedelta(hours=8))),
    )

    assert business_digest(first) == business_digest(second)
    assert "transaction_id" not in canonical_business_json(first)
    assert "requested_at" not in canonical_business_json(first)


def test_business_digest_is_stable_across_mapping_key_order() -> None:
    first = make_command(
        extensions={"example.com/tracking-options/v1": {"alpha": 1, "beta": 2}}
    )
    second = make_command(
        extensions={"example.com/tracking-options/v1": {"beta": 2, "alpha": 1}}
    )

    assert canonical_business_json(first) == canonical_business_json(second)
    assert business_digest(first).startswith("sha256:")
    assert len(business_digest(first)) == len("sha256:") + 64


def test_business_change_changes_digest() -> None:
    first = make_command()
    second = make_command(external_reference="BOL-456")

    assert business_digest(first) != business_digest(second)


def test_equivalent_filter_timezone_offsets_have_the_same_digest() -> None:
    utc_command = make_command(
        parameters=TrackFilters(
            event_created_date_time=DateTimeFilter(gte="2026-08-30T00:00:00Z")
        )
    )
    offset_command = make_command(
        parameters=TrackFilters(
            event_created_date_time=DateTimeFilter(gte="2026-08-30T08:00:00+08:00")
        )
    )

    assert business_digest(utc_command) == business_digest(offset_command)


def test_requested_at_must_be_timezone_aware() -> None:
    with pytest.raises(ValidationError, match="must include a timezone"):
        make_command(requested_at=datetime(2026, 8, 30, 9, 0))
