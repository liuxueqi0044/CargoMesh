"""Freeze authorization and credential metadata before durable execution starts."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime

from cargomesh.credentials import CredentialBindingStore
from cargomesh.ir.enums import RiskClass
from cargomesh.policy import PolicyDecision, PolicyEffect, PolicyInput, PolicyProvider
from cargomesh.routing.models import ExecutionChannel

from .models import ExecutionPlan, ExecutionStep, RouteFallbackSpec

_PROVIDER_FAILURE_REASONS = frozenset(
    {
        "policy_provider_error",
        "opa_timeout",
        "opa_transport_error",
        "opa_http_error",
        "opa_redirect_rejected",
        "opa_content_type_invalid",
        "opa_content_length_invalid",
        "opa_response_too_large",
        "opa_response_invalid",
    }
)


class PolicyPlanningError(RuntimeError):
    """A bounded planning failure safe to expose through the application layer."""

    def __init__(self, code: str, message: str, *, status_code: int) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code


async def apply_execution_policy(
    plan: ExecutionPlan,
    provider: PolicyProvider,
    *,
    environment_id: str,
    principal_ref: str,
    credential_bindings: CredentialBindingStore | None = None,
    default_approval_timeout_seconds: int = 86_400,
    clock: Callable[[], datetime] | None = None,
) -> ExecutionPlan:
    """Evaluate every possible attempt and freeze decisions plus secret-reference digests.

    The function runs before a Workflow starts. It never resolves secret material and
    never passes business payloads to the policy provider.
    """

    if not 1 <= default_approval_timeout_seconds <= 604_800:
        raise ValueError("default approval timeout is out of bounds")
    evaluated_at = (clock or (lambda: datetime.now(UTC)))()
    if evaluated_at.tzinfo is None or evaluated_at.utcoffset() is None:
        raise ValueError("policy clock must return a timezone-aware value")
    evaluated_at = evaluated_at.astimezone(UTC)

    primary_decisions: list[PolicyDecision] = []
    fallback_decisions: list[PolicyDecision] = []
    compensation_decisions: list[PolicyDecision] = []
    updated_steps: list[ExecutionStep] = []
    for step in plan.steps:
        binding_digest = _binding_digest(
            credential_bindings,
            tenant_id=plan.tenant_id,
            environment_id=environment_id,
            adapter=step.adapter,
            capability=step.capability,
        )
        primary = await _evaluate_attempt(
            provider,
            plan=plan,
            capability=step.capability,
            risk_class=step.risk_class,
            environment_id=environment_id,
            principal_ref=principal_ref,
            route=step.route_candidate_id or step.adapter,
            adapter=step.adapter,
            channel=step.execution_channel,
            evaluated_at=evaluated_at,
        )
        primary_decisions.append(primary)

        updated_fallbacks: list[RouteFallbackSpec] = []
        approval_required = primary.effect is PolicyEffect.REQUIRE_APPROVAL
        for fallback in step.route_fallbacks:
            fallback_digest = _binding_digest(
                credential_bindings,
                tenant_id=plan.tenant_id,
                environment_id=environment_id,
                adapter=fallback.adapter,
                capability=step.capability,
            )
            decision = await _evaluate_attempt(
                provider,
                plan=plan,
                capability=step.capability,
                risk_class=step.risk_class,
                environment_id=environment_id,
                principal_ref=principal_ref,
                route=fallback.candidate_id,
                adapter=fallback.adapter,
                channel=fallback.execution_channel,
                evaluated_at=evaluated_at,
            )
            fallback_decisions.append(decision)
            approval_required = (
                approval_required or decision.effect is PolicyEffect.REQUIRE_APPROVAL
            )
            updated_fallbacks.append(
                fallback.model_copy(
                    update={"credential_binding_digest": fallback_digest}
                )
            )

        updated_compensation = step.compensation
        if updated_compensation is not None and updated_compensation.capability is not None:
            compensation_digest = _binding_digest(
                credential_bindings,
                tenant_id=plan.tenant_id,
                environment_id=environment_id,
                adapter=updated_compensation.adapter,
                capability=updated_compensation.capability,
            )
            compensation_decision = await _evaluate_attempt(
                provider,
                plan=plan,
                capability=updated_compensation.capability,
                risk_class=updated_compensation.risk_class,
                environment_id=environment_id,
                principal_ref=principal_ref,
                route=updated_compensation.adapter,
                adapter=updated_compensation.adapter,
                channel=updated_compensation.execution_channel,
                evaluated_at=evaluated_at,
            )
            if compensation_decision.effect is PolicyEffect.REQUIRE_APPROVAL:
                raise PolicyPlanningError(
                    "compensation_approval_unsupported",
                    "Compensation policy must allow direct bounded recovery",
                    status_code=403,
                )
            compensation_decisions.append(compensation_decision)
            updated_compensation = updated_compensation.model_copy(
                update={"credential_binding_digest": compensation_digest}
            )

        updates: dict[str, object] = {
            "credential_binding_digest": binding_digest,
            "route_fallbacks": tuple(updated_fallbacks),
            "compensation": updated_compensation,
        }
        if approval_required:
            updates.update(
                requires_approval=True,
                approval_timeout_seconds=(
                    step.approval_timeout_seconds or default_approval_timeout_seconds
                ),
            )
        updated_steps.append(step.model_copy(update=updates))

    payload = plan.model_dump(mode="python")
    payload.update(
        environment_id=environment_id,
        steps=tuple(updated_steps),
        policy_decisions=tuple(
            (*primary_decisions, *fallback_decisions, *compensation_decisions)
        ),
    )
    try:
        return ExecutionPlan.model_validate(payload)
    except Exception as exc:
        raise PolicyPlanningError(
            "policy_plan_invalid",
            "Policy result could not be frozen into a valid execution plan",
            status_code=503,
        ) from exc


async def _evaluate_attempt(
    provider: PolicyProvider,
    *,
    plan: ExecutionPlan,
    capability: str,
    risk_class: RiskClass,
    environment_id: str,
    principal_ref: str,
    route: str,
    adapter: str,
    channel: ExecutionChannel,
    evaluated_at: datetime,
) -> PolicyDecision:
    try:
        policy_input = PolicyInput.issue(
            tenant_id=plan.tenant_id,
            environment_id=environment_id,
            principal_ref=principal_ref,
            capability=capability,
            risk_class=risk_class,
            data_classification=plan.data_classification,
            requested_verification_level=plan.verification_level,
            route=route,
            channel=channel,
            adapter=adapter,
            evaluated_at=evaluated_at,
        )
        decision = await provider.evaluate(policy_input)
    except Exception as exc:
        raise PolicyPlanningError(
            "policy_unavailable",
            "Execution policy is temporarily unavailable",
            status_code=503,
        ) from exc
    if not isinstance(decision, PolicyDecision) or decision.input != policy_input:
        raise PolicyPlanningError(
            "policy_unavailable",
            "Execution policy returned an invalid decision",
            status_code=503,
        )
    if decision.effect is PolicyEffect.DENY:
        unavailable = decision.reason_code in _PROVIDER_FAILURE_REASONS or (
            decision.reason_code.startswith("opa_")
            or decision.reason_code.startswith("policy_provider_")
        )
        raise PolicyPlanningError(
            "policy_unavailable" if unavailable else "policy_denied",
            (
                "Execution policy is temporarily unavailable"
                if unavailable
                else "Execution policy denied this transaction"
            ),
            status_code=503 if unavailable else 403,
        )
    return decision


def _binding_digest(
    store: CredentialBindingStore | None,
    *,
    tenant_id: str,
    environment_id: str,
    adapter: str,
    capability: str,
) -> str | None:
    if store is None:
        return None
    try:
        binding = store.get(tenant_id, environment_id, adapter, capability)
    except Exception as exc:
        raise PolicyPlanningError(
            "credential_directory_unavailable",
            "Credential metadata is temporarily unavailable",
            status_code=503,
        ) from exc
    return None if binding is None else binding.binding_digest
