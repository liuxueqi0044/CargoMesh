"""Explicit local-only policy and credential wiring for the synthetic booking demo."""

from __future__ import annotations

from cargomesh.credentials import (
    CredentialBinding,
    InMemorySecretProvider,
    SecretRef,
    SQLiteCredentialBindingStore,
)
from cargomesh.ir.enums import RiskClass
from cargomesh.policy import (
    EmbeddedPolicyProvider,
    PolicyEffect,
    PolicyRule,
    PolicySet,
)

SYNTHETIC_BOOKING_ADAPTER = "synthetic.booking.api"
SYNTHETIC_BOOKING_SECRET_KEY = "synthetic-booking-demo"


def synthetic_booking_policy_provider(
    *, tenant_id: str, environment_id: str
) -> EmbeddedPolicyProvider:
    """Return a fail-closed policy restricted to the explicit demo surface."""

    common = {
        "tenant_ids": (tenant_id,),
        "environment_ids": (environment_id,),
    }
    rules = (
        PolicyRule.issue(
            rule_id="synthetic.booking.draft.allow",
            priority=10,
            capabilities=("booking.draft.prepare",),
            risk_classes=(RiskClass.READ_ONLY,),
            routes=("synthetic.booking.draft",),
            adapters=("synthetic.booking.draft",),
            effect=PolicyEffect.ALLOW,
            reason_code="synthetic.booking.draft.allowed",
            **common,
        ),
        PolicyRule.issue(
            rule_id="synthetic.booking.submit.approval",
            priority=20,
            capabilities=("booking.submit",),
            risk_classes=(RiskClass.CONSEQUENTIAL_WRITE,),
            routes=(SYNTHETIC_BOOKING_ADAPTER,),
            adapters=(SYNTHETIC_BOOKING_ADAPTER,),
            effect=PolicyEffect.REQUIRE_APPROVAL,
            approval_requirement="human.approver",
            reason_code="synthetic.booking.submit.requires-approval",
            **common,
        ),
        PolicyRule.issue(
            rule_id="synthetic.booking.cancel.allow",
            priority=30,
            capabilities=("booking.cancel",),
            risk_classes=(RiskClass.REVERSIBLE_WRITE,),
            routes=(SYNTHETIC_BOOKING_ADAPTER,),
            adapters=(SYNTHETIC_BOOKING_ADAPTER,),
            effect=PolicyEffect.ALLOW,
            reason_code="synthetic.booking.cancel.allowed",
            **common,
        ),
    )
    policy_set = PolicySet.issue(
        policy_id="synthetic.booking.local",
        version="1.0.0",
        rules=rules,
    )
    return EmbeddedPolicyProvider(policy_set)


def synthetic_booking_credential_store(
    *, tenant_id: str, environment_id: str
) -> SQLiteCredentialBindingStore:
    """Create metadata-only bindings for submit and cancellation."""

    store = SQLiteCredentialBindingStore()
    reference = SecretRef(provider="memory", key=SYNTHETIC_BOOKING_SECRET_KEY)
    for capability in ("booking.submit", "booking.cancel"):
        store.provision(
            CredentialBinding.issue(
                tenant_id=tenant_id,
                environment_id=environment_id,
                adapter=SYNTHETIC_BOOKING_ADAPTER,
                capability=capability,
                secrets={"api_key": reference},
                revision=1,
            )
        )
    return store


def synthetic_booking_secret_provider() -> InMemorySecretProvider:
    """Return a clearly non-production secret provider for the local carrier."""

    return InMemorySecretProvider(
        {SYNTHETIC_BOOKING_SECRET_KEY: "synthetic-only-not-a-real-credential"}
    )


__all__ = [
    "SYNTHETIC_BOOKING_ADAPTER",
    "SYNTHETIC_BOOKING_SECRET_KEY",
    "synthetic_booking_credential_store",
    "synthetic_booking_policy_provider",
    "synthetic_booking_secret_provider",
]
