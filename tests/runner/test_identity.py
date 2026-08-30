from __future__ import annotations

import hashlib
import pickle
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest

from cargomesh.runner.identity import EnrollmentToken, RunnerHealth, RunnerIdentity
from cargomesh.runner.registry import (
    RunnerEnrollmentError,
    RunnerRegistryError,
    SQLiteRunnerRegistry,
)

NOW = datetime(2040, 1, 2, 3, 4, 5, tzinfo=UTC)
KEY_DIGEST = "sha256:" + "a" * 64


def issue(registry: SQLiteRunnerRegistry, **overrides: object):
    values: dict[str, object] = {
        "tenant_id": "tenant-a",
        "environment_id": "production",
        "runner_pool": "trusted-pool",
        "now": NOW,
    }
    values.update(overrides)
    return registry.issue_challenge(**values)


def enroll(
    registry: SQLiteRunnerRegistry,
    challenge_id: str,
    token: str | EnrollmentToken,
    **overrides: object,
) -> RunnerIdentity:
    values: dict[str, object] = {
        "tenant_id": "tenant-a",
        "environment_id": "production",
        "runner_pool": "trusted-pool",
        "public_key_digest": KEY_DIGEST,
        "capabilities": ("shipment.track.read",),
        "platform": "linux.amd64",
        "version": "1.2.3",
        "now": NOW,
    }
    values.update(overrides)
    return registry.enroll(challenge_id, token, **values)


def test_one_time_token_is_redacted_nonserializable_and_never_persisted() -> None:
    registry = SQLiteRunnerRegistry()
    delivery = issue(registry)
    token = delivery.token.take()

    assert token not in repr(delivery)
    assert token not in str(delivery.token)
    assert token not in repr(delivery.token)
    with pytest.raises(ValueError, match="no longer available"):
        delivery.token.take()
    with pytest.raises(TypeError, match="cannot be serialized"):
        pickle.dumps(EnrollmentToken("different-token"))

    identity = enroll(registry, delivery.challenge.challenge_id, token)
    rows = registry._connection.execute("SELECT token_digest FROM enrollment_challenges").fetchall()
    persisted = "".join(row["token_digest"] for row in rows)

    assert persisted == "sha256:" + hashlib.sha256(token.encode()).hexdigest()
    assert token not in persisted
    assert token not in registry._connection.serialize().decode("latin1")
    assert identity.public_key_digest == KEY_DIGEST


def test_enrollment_pins_only_public_key_metadata_and_digest_bound_identity() -> None:
    registry = SQLiteRunnerRegistry()
    delivery = issue(registry)
    identity = enroll(registry, delivery.challenge.challenge_id, delivery.token)

    assert identity.identity_digest.startswith("sha256:")
    assert identity.capabilities == ("shipment.track.read",)
    assert identity.platform == "linux.amd64"
    assert identity.version == "1.2.3"
    assert "tenant-a" not in identity.task_queue_id
    assert "production" not in identity.task_queue_id
    assert "trusted-pool" not in identity.task_queue_id
    with pytest.raises(ValueError) as caught:
        RunnerIdentity.issue(
            runner_id=identity.runner_id,
            tenant_id="tenant-a",
            environment_id="production",
            runner_pool="trusted-pool",
            task_queue_id=identity.task_queue_id,
            public_key_digest=KEY_DIGEST,
            capabilities=("shipment.track.read",),
            platform="linux.amd64",
            version="1.2.3",
            enrolled_at=NOW,
            private_key="private-key-material",
        )
    assert "private-key-material" not in str(caught.value)


def test_scope_mismatch_and_expiry_fail_closed_without_consuming_valid_challenge() -> None:
    registry = SQLiteRunnerRegistry()
    delivery = issue(registry)
    token = delivery.token.take()

    with pytest.raises(RunnerEnrollmentError) as scope_error:
        enroll(registry, delivery.challenge.challenge_id, token, environment_id="staging")
    assert scope_error.value.code == "enrollment_scope_mismatch"
    assert token not in str(scope_error.value)

    # A failed scope assertion does not turn a valid challenge into a consumed one.
    identity = enroll(registry, delivery.challenge.challenge_id, token)
    assert identity.environment_id == "production"

    expired = issue(registry, ttl_seconds=1)
    expired_token = expired.token.take()
    with pytest.raises(RunnerEnrollmentError) as expiry_error:
        enroll(
            registry,
            expired.challenge.challenge_id,
            expired_token,
            now=NOW + timedelta(seconds=1),
        )
    assert expiry_error.value.code == "enrollment_token_expired"


def test_single_challenge_has_exactly_one_concurrent_enrollment_winner() -> None:
    registry = SQLiteRunnerRegistry()
    delivery = issue(registry)
    token = delivery.token.take()

    def attempt() -> tuple[str, object]:
        try:
            return ("identity", enroll(registry, delivery.challenge.challenge_id, token))
        except RunnerEnrollmentError as exc:
            return ("error", exc.code)

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _: attempt(), range(2)))

    assert [result[0] for result in results].count("identity") == 1
    assert [result[1] for result in results if result[0] == "error"] == [
        "enrollment_token_used"
    ]


def test_get_list_health_revoke_and_scope_isolation() -> None:
    registry = SQLiteRunnerRegistry()
    delivery = issue(registry)
    identity = enroll(registry, delivery.challenge.challenge_id, delivery.token)

    assert registry.get(
        identity.runner_id,
        tenant_id="tenant-b",
        environment_id="production",
        runner_pool="trusted-pool",
    ) is None
    assert registry.list("tenant-b", "production", "trusted-pool") == ()

    online = registry.heartbeat(
        identity.runner_id,
        tenant_id="tenant-a",
        environment_id="production",
        runner_pool="trusted-pool",
        now=NOW + timedelta(seconds=1),
    )
    offline = registry.mark_offline(
        identity.runner_id,
        tenant_id="tenant-a",
        environment_id="production",
        runner_pool="trusted-pool",
        now=NOW + timedelta(seconds=2),
    )
    revoked = registry.revoke(
        identity.runner_id,
        tenant_id="tenant-a",
        environment_id="production",
        runner_pool="trusted-pool",
        now=NOW + timedelta(seconds=3),
    )

    assert online.health is RunnerHealth.ONLINE
    assert online.last_heartbeat_at == NOW + timedelta(seconds=1)
    assert offline.health is RunnerHealth.OFFLINE
    assert revoked.health is RunnerHealth.REVOKED
    assert revoked.revoked_at == NOW + timedelta(seconds=3)
    assert registry.list("tenant-a", "production", "trusted-pool") == (revoked,)
    with pytest.raises(RunnerRegistryError) as heartbeat_error:
        registry.heartbeat(
            identity.runner_id,
            tenant_id="tenant-a",
            environment_id="production",
            runner_pool="trusted-pool",
            now=NOW + timedelta(seconds=4),
        )
    assert heartbeat_error.value.code == "runner_revoked"


def test_reenrollment_creates_a_new_identity_and_previous_token_is_not_reusable() -> None:
    registry = SQLiteRunnerRegistry()
    first = issue(registry)
    first_identity = enroll(registry, first.challenge.challenge_id, first.token)
    second = issue(registry)
    second_identity = enroll(registry, second.challenge.challenge_id, second.token)

    assert second_identity.runner_id != first_identity.runner_id
    assert second_identity.task_queue_id != first_identity.task_queue_id
    with pytest.raises(RunnerEnrollmentError) as reused:
        enroll(registry, first.challenge.challenge_id, "not-the-original-token")
    assert reused.value.code == "enrollment_token_used"
