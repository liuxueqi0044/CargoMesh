from datetime import UTC, datetime

import pytest

from cargomesh.controlplane.membership import MembershipConflict, SQLiteMembershipStore
from cargomesh.controlplane.models import MembershipRole, PrincipalType, TenantMembership

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def make_membership(role: MembershipRole = MembershipRole.OPERATOR) -> TenantMembership:
    return TenantMembership.issue(
        membership_id="m-1",
        issuer="https://issuer",
        subject="subject",
        principal_type=PrincipalType.HUMAN,
        tenant_id="tenant-a",
        environment_id="prod",
        role=role,
        revision=1,
        created_at=NOW,
        updated_at=NOW,
    )


def test_provision_is_idempotent_and_conflicts_require_replace() -> None:
    with SQLiteMembershipStore() as store:
        first = store.provision(make_membership())
        assert store.provision(make_membership()) == first
        changed = TenantMembership.issue(
            membership_id="m-1",
            issuer="https://issuer",
            subject="subject",
            principal_type=PrincipalType.HUMAN,
            tenant_id="tenant-a",
            environment_id="prod",
            role=MembershipRole.OPERATOR,
            status="DISABLED",
            revision=1,
            created_at=NOW,
            updated_at=NOW,
        )
        with pytest.raises(MembershipConflict):
            store.provision(changed)
        replaced = store.replace(changed)
        assert replaced.revision == 2
        assert replaced.status.value == "DISABLED"


def test_memberships_are_tenant_and_environment_scoped_and_concurrent_replay_safe(tmp_path) -> None:
    database = tmp_path / "memberships.sqlite"
    with SQLiteMembershipStore(database) as store:
        values = [store.provision(make_membership()) for _ in range(8)]
        assert all(item.membership_digest == values[0].membership_digest for item in values)
        assert store.list("other") == ()
        assert store.list("tenant-a", "dev") == ()
