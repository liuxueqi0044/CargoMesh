from datetime import UTC, datetime, timedelta

import pytest

from cargomesh.controlplane.authorization import (
    ROLE_ACTIONS,
    AuthorizationEvaluator,
    MembershipAuthorizer,
)
from cargomesh.controlplane.models import (
    AccessAction,
    AuthorizationRequest,
    MembershipRole,
    Principal,
    PrincipalType,
    TenantMembership,
)

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def principal() -> Principal:
    return Principal(
        issuer="https://issuer",
        subject="subject",
        principal_type=PrincipalType.HUMAN,
        audiences=("aud",),
        token_id_digest="sha256:" + "a" * 64,
        issued_at=NOW - timedelta(minutes=1),
        expires_at=NOW + timedelta(minutes=5),
        authenticated_at=NOW,
    )


def membership(
    role: MembershipRole, *, tenant: str = "tenant", environment: str = "prod"
) -> TenantMembership:
    return TenantMembership.issue(
        membership_id=f"{tenant}-{environment}-{role.value}",
        issuer="https://issuer",
        subject="subject",
        principal_type=PrincipalType.HUMAN,
        tenant_id=tenant,
        environment_id=environment,
        role=role,
        revision=1,
        created_at=NOW,
        updated_at=NOW,
    )


def request(action: AccessAction, *, tenant: str = "tenant") -> AuthorizationRequest:
    return AuthorizationRequest(
        principal=principal(),
        tenant_id=tenant,
        environment_id="prod",
        action=action,
        resource_type="transaction",
        evaluated_at=NOW,
    )


def test_fixed_role_matrix_and_tenant_environment_isolation() -> None:
    assert set(ROLE_ACTIONS) == set(MembershipRole)
    evaluator = AuthorizationEvaluator()
    operator = membership(MembershipRole.OPERATOR)
    assert evaluator.evaluate(request(AccessAction.TRANSACTION_CREATE), [operator]).allowed
    assert not evaluator.evaluate(request(AccessAction.TRANSACTION_APPROVE), [operator]).allowed
    assert (
        evaluator.evaluate(
            request(AccessAction.TRANSACTION_CREATE, tenant="other"), [operator]
        ).reason_code
        == "tenant_membership_missing"
    )
    assert (
        evaluator.evaluate(
            request(AccessAction.TRANSACTION_CREATE),
            [membership(MembershipRole.OPERATOR, environment="dev")],
        ).reason_code
        == "tenant_membership_missing"
    )


@pytest.mark.parametrize("role", list(MembershipRole))
@pytest.mark.parametrize("action", list(AccessAction))
def test_every_role_action_pair_matches_the_reviewed_matrix(
    role: MembershipRole, action: AccessAction
) -> None:
    decision = AuthorizationEvaluator().evaluate(request(action), [membership(role)])

    assert decision.allowed is (action in ROLE_ACTIONS[role])
    expected_reason = "allowed" if action in ROLE_ACTIONS[role] else "action_not_permitted"
    assert decision.reason_code == expected_reason


def test_disabled_and_provider_error_fail_closed_and_digest_is_deterministic() -> None:
    evaluator = AuthorizationEvaluator()
    disabled = membership(MembershipRole.TENANT_ADMIN).model_copy(update={"status": "DISABLED"})
    first = evaluator.evaluate(request(AccessAction.AUDIT_READ), [disabled])
    second = evaluator.evaluate(request(AccessAction.AUDIT_READ), [disabled])
    assert not first.allowed and first.reason_code == "tenant_membership_missing"
    assert first.decision_digest == second.decision_digest

    class Broken:
        def get_memberships(self, *_: object) -> tuple[TenantMembership, ...]:
            raise RuntimeError("backend unavailable")

    denied = MembershipAuthorizer(Broken()).authorize(request(AccessAction.TRANSACTION_READ))
    assert not denied.allowed and denied.reason_code == "membership_provider_error"
