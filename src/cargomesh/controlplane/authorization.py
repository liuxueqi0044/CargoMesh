"""Pure, fail-closed role based authorization for the control plane."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import Protocol

from .models import (
    AccessAction,
    AuthorizationDecision,
    AuthorizationRequest,
    MembershipRole,
    MembershipStatus,
    Principal,
    TenantMembership,
)


class MembershipProvider(Protocol):
    """Read-only boundary used by authorization; implementations own lookup."""

    def get_memberships(
        self, principal: Principal, tenant_id: str, environment_id: str
    ) -> Sequence[TenantMembership]: ...

    def memberships_for(
        self, principal: Principal, tenant_id: str, environment_id: str
    ) -> Sequence[TenantMembership]: ...


class AuthorizationProviderError(RuntimeError):
    """A membership provider failed and access must consequently be denied."""


# This is deliberately a small, code-reviewed policy.  Keep values tuples so the
# evaluator has no mutable or order-dependent state.
ROLE_ACTIONS: dict[MembershipRole, frozenset[AccessAction]] = {
    MembershipRole.TENANT_ADMIN: frozenset(AccessAction),
    MembershipRole.OPERATOR: frozenset(
        {
            AccessAction.TRANSACTION_CREATE,
            AccessAction.TRANSACTION_READ,
            AccessAction.TRANSACTION_CANCEL,
        }
    ),
    MembershipRole.APPROVER: frozenset(
        {AccessAction.TRANSACTION_READ, AccessAction.TRANSACTION_APPROVE}
    ),
    MembershipRole.ADAPTER_DEVELOPER: frozenset({AccessAction.TRANSACTION_READ}),
    MembershipRole.AUDITOR: frozenset(
        {AccessAction.TRANSACTION_READ, AccessAction.AUDIT_READ}
    ),
    MembershipRole.VIEWER: frozenset({AccessAction.TRANSACTION_READ}),
    MembershipRole.SERVICE_ACCOUNT: frozenset(
        {AccessAction.TRANSACTION_CREATE, AccessAction.TRANSACTION_READ}
    ),
}


class AuthorizationEvaluator:
    """Evaluate a request against caller-supplied memberships.

    The evaluator does not read a clock or a database.  A provider can be passed
    to ``evaluate`` for convenience, but all provider exceptions are converted
    to a deterministic deny decision.
    """

    def evaluate(
        self,
        request: AuthorizationRequest,
        memberships: Iterable[TenantMembership] | MembershipProvider,
    ) -> AuthorizationDecision:
        try:
            if hasattr(memberships, "get_memberships"):
                values = memberships.get_memberships(
                    request.principal, request.tenant_id, request.environment_id
                )
            elif hasattr(memberships, "memberships_for"):
                values = memberships.memberships_for(
                    request.principal, request.tenant_id, request.environment_id
                )
            elif hasattr(memberships, "list_memberships"):
                values = memberships.list_memberships(
                    request.principal, request.tenant_id, request.environment_id
                )
            else:
                values = memberships
            return self._evaluate_memberships(request, values)
        except Exception:
            return self._decision(request, False, "membership_provider_error")

    authorize = evaluate

    def _evaluate_memberships(
        self, request: AuthorizationRequest, memberships: Iterable[TenantMembership]
    ) -> AuthorizationDecision:
        action = request.action
        if not isinstance(action, AccessAction) or action not in set(AccessAction):
            return self._decision(request, False, "unknown_action")

        matched: list[TenantMembership] = []
        for membership in memberships:
            # Do not trust provider filtering: enforce the complete scope here.
            if (
                membership.issuer == request.principal.issuer
                and membership.subject == request.principal.subject
                and membership.principal_type == request.principal.principal_type
                and membership.tenant_id == request.tenant_id
                and membership.environment_id == request.environment_id
                and membership.status is MembershipStatus.ACTIVE
                and membership.role in ROLE_ACTIONS
            ):
                matched.append(membership)

        matched.sort(key=lambda item: str(item.role))
        roles = tuple(item.role for item in matched)
        revision = max((item.revision for item in matched), default=None)
        if not matched:
            return self._decision(request, False, "tenant_membership_missing")
        if not any(action in ROLE_ACTIONS[item.role] for item in matched):
            return self._decision(
                request, False, "action_not_permitted", roles=roles, revision=revision
            )
        return self._decision(request, True, "allowed", roles=roles, revision=revision)

    @staticmethod
    def _decision(
        request: AuthorizationRequest,
        allowed: bool,
        reason: str,
        *,
        roles: tuple[MembershipRole, ...] = (),
        revision: int | None = None,
    ) -> AuthorizationDecision:
        return AuthorizationDecision.issue(
            request=request,
            allowed=allowed,
            reason_code=reason,
            matched_roles=roles,
            membership_revision=revision,
        )


class MembershipAuthorizer:
    """Bind a membership provider to an evaluator for request-time use."""

    def __init__(
        self, provider: MembershipProvider, evaluator: AuthorizationEvaluator | None = None
    ) -> None:
        self.provider = provider
        self.evaluator = evaluator or AuthorizationEvaluator()

    def authorize(self, request: AuthorizationRequest) -> AuthorizationDecision:
        return self.evaluator.evaluate(request, self.provider)

    evaluate = authorize


def evaluate_authorization(
    request: AuthorizationRequest,
    memberships: Iterable[TenantMembership] | MembershipProvider,
) -> AuthorizationDecision:
    """Functional convenience wrapper around :class:`AuthorizationEvaluator`."""

    return AuthorizationEvaluator().evaluate(request, memberships)


def authorize(
    request: AuthorizationRequest,
    memberships: Iterable[TenantMembership] | MembershipProvider,
) -> AuthorizationDecision:
    return evaluate_authorization(request, memberships)


__all__ = [
    "ROLE_ACTIONS",
    "AuthorizationEvaluator",
    "AuthorizationProviderError",
    "MembershipAuthorizer",
    "MembershipProvider",
    "authorize",
    "evaluate_authorization",
]
