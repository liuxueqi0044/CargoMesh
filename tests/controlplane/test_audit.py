from datetime import UTC, datetime

import pytest

from cargomesh.controlplane.audit import AuditConflict, SQLiteAuditStore
from cargomesh.controlplane.models import AccessAction, AuditEvent, AuditResult, PrincipalType

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def event(event_id: str, tenant: str = "tenant-a") -> AuditEvent:
    return AuditEvent.issue(
        event_id=event_id,
        tenant_id=tenant,
        environment_id="prod",
        actor_issuer="https://issuer",
        actor_subject="subject",
        actor_type=PrincipalType.HUMAN,
        action=AccessAction.TRANSACTION_READ,
        resource_type="transaction",
        result=AuditResult.ALLOWED,
        reason_code="allowed",
        request_id=f"request-{event_id}",
        occurred_at=NOW,
    )


def test_hash_chain_is_tenant_independent_and_replay_safe() -> None:
    with SQLiteAuditStore() as store:
        first = store.append(event("one"))
        assert store.append(event("one")) == first
        second = store.append(event("two"))
        other = store.append(event("one", "tenant-b"))
        assert second.sequence == 2 and other.sequence == 1
        assert store.verify_chain("tenant-a")
        assert len(store.list("tenant-a", limit=1)) == 1
        with pytest.raises(AuditConflict):
            store.append(
                AuditEvent.issue(
                    event_id="one",
                    tenant_id="tenant-a",
                    environment_id="prod",
                    actor_issuer="https://issuer",
                    actor_subject="subject",
                    actor_type=PrincipalType.HUMAN,
                    action=AccessAction.TRANSACTION_READ,
                    resource_type="transaction",
                    result=AuditResult.ALLOWED,
                    reason_code="allowed",
                    request_id="different",
                    occurred_at=NOW,
                )
            )


def test_tampering_is_located() -> None:
    with SQLiteAuditStore() as store:
        store.append(event("one"))
        store.append(event("two"))
        store._connection.execute("DROP TRIGGER audit_records_no_update")
        store._connection.execute(
            "UPDATE audit_records SET record_digest=? WHERE tenant_id=? AND sequence=?",
            ("sha256:" + "0" * 64, "tenant-a", 2),
        )
        result = store.verify_chain("tenant-a")
        assert not result.valid and result.first_broken_sequence == 2
