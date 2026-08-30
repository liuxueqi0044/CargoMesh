from __future__ import annotations

from datetime import UTC, datetime

import pytest

from cargomesh.runner.artifacts import (
    ArtifactCandidate,
    ArtifactClassification,
    ArtifactPolicy,
    ArtifactRelay,
    ArtifactRelayError,
    ArtifactRule,
    ArtifactType,
    InMemoryArtifactSink,
    SQLiteArtifactReceiptStore,
)

NOW = datetime(2040, 1, 2, tzinfo=UTC)


def policy() -> ArtifactPolicy:
    return ArtifactPolicy.issue(
        policy_id="runner-artifacts",
        rules=(
            ArtifactRule(
                artifact_type=ArtifactType.SCREENSHOT,
                allowed_media_types=("image/png",),
                maximum_bytes=1024,
                maximum_classification=ArtifactClassification.CONFIDENTIAL,
            ),
            ArtifactRule(
                artifact_type=ArtifactType.EVIDENCE,
                allowed_media_types=("application/json",),
                maximum_bytes=1024,
                maximum_classification=ArtifactClassification.INTERNAL,
            ),
        ),
    )


def candidate(**changes: object) -> ArtifactCandidate:
    values: dict[str, object] = {
        "tenant_id": "tenant-a",
        "environment_id": "production",
        "task_id": "task-1",
        "artifact_type": ArtifactType.SCREENSHOT,
        "media_type": "image/png",
        "classification": ArtifactClassification.INTERNAL,
        "sanitized": True,
    }
    values.update(changes)
    return ArtifactCandidate.model_validate(values)


def test_relay_computes_digest_and_persists_metadata_only() -> None:
    sink = InMemoryArtifactSink()
    receipts = SQLiteArtifactReceiptStore()
    relay = ArtifactRelay(policy(), sink, receipts=receipts)

    receipt = relay.relay(candidate(), b"safe-image", relayed_at=NOW)
    replay = relay.relay(
        candidate(), b"safe-image", relayed_at=NOW.replace(year=2041)
    )

    assert replay == receipt
    assert receipt.content_digest.startswith("sha256:")
    assert receipt.size_bytes == 10
    assert sink.read(receipt.storage_ref) == b"safe-image"
    assert b"safe-image" not in receipt.model_dump_json().encode()


@pytest.mark.parametrize(
    ("changes", "content", "code"),
    [
        ({"media_type": "image/jpeg"}, b"x", "artifact_media_denied"),
        ({}, b"x" * 1025, "artifact_size_denied"),
        (
            {"classification": ArtifactClassification.RESTRICTED},
            b"x",
            "artifact_classification_denied",
        ),
        ({"sanitized": False}, b"x", "artifact_sanitization_required"),
        (
            {"contains_sensitive_content": True},
            b"explicit-secret-value",
            "artifact_sensitive_content",
        ),
    ],
)
def test_relay_fails_closed_without_echoing_content(
    changes: dict[str, object], content: bytes, code: str
) -> None:
    relay = ArtifactRelay(policy(), InMemoryArtifactSink())

    with pytest.raises(ArtifactRelayError) as caught:
        relay.relay(candidate(**changes), content)

    assert caught.value.code == code
    assert content not in str(caught.value).encode()


def test_evidence_does_not_require_text_redaction_but_obeys_policy() -> None:
    relay = ArtifactRelay(policy(), InMemoryArtifactSink())
    receipt = relay.relay(
        candidate(
            artifact_type=ArtifactType.EVIDENCE,
            media_type="application/json",
            sanitized=False,
        ),
        b"{}",
        relayed_at=NOW,
    )
    assert receipt.artifact_type is ArtifactType.EVIDENCE


def test_policy_digest_detects_tampering() -> None:
    value = policy().model_dump()
    value["policy_id"] = "other-policy"
    with pytest.raises(ValueError, match="digest"):
        ArtifactPolicy.model_validate(value)
