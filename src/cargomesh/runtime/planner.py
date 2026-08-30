"""Deterministic compilation from Transaction IR to an execution plan."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from typing import Protocol, cast

from pydantic import BaseModel, ConfigDict, JsonValue

from cargomesh.ir import ShipmentSubject, TransactionCommand
from cargomesh.ir.enums import RiskClass, VerificationLevel
from cargomesh.routing.engine import select_route
from cargomesh.routing.models import (
    DataClassification,
    ExecutionChannel,
    RouteCandidate,
    RouteHealthSnapshot,
    RoutingPolicy,
    RoutingRequest,
)
from cargomesh.verification.models import (
    EvidenceCollectionSpec,
    VerificationClaimRule,
    VerificationPlan,
)

from .models import (
    ExecutionPlan,
    ExecutionStep,
    RetryPolicySpec,
    RouteFallbackSpec,
    RuntimeName,
)


class CapabilityBinding(BaseModel):
    """Operator-configured binding; dynamic route optimization is deliberately absent."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    adapter: RuntimeName
    operation: RuntimeName
    requires_approval: bool = False
    approval_timeout_seconds: int | None = None
    timeout_seconds: int = 60
    retry: RetryPolicySpec = RetryPolicySpec()
    execution_channel: ExecutionChannel = ExecutionChannel.API


class MissingCapabilityBinding(ValueError):
    def __init__(self, capability: str) -> None:
        super().__init__(f"no execution binding is configured for capability {capability}")
        self.capability = capability


class StaticExecutionPlanner:
    """Build a stable, ordered plan from explicit capability bindings."""

    def __init__(
        self,
        bindings: Mapping[str, CapabilityBinding],
        *,
        verification_factory: Callable[[TransactionCommand], VerificationPlan | None]
        | None = None,
    ) -> None:
        self._bindings = dict(bindings)
        self._verification_factory = verification_factory

    def build(
        self,
        command: TransactionCommand,
        *,
        transaction_id: str,
        business_digest: str,
    ) -> ExecutionPlan:
        command_payload = cast(
            dict[str, JsonValue],
            command.model_dump(mode="json", exclude={"transaction_id", "requested_at"}),
        )
        steps: list[ExecutionStep] = []
        previous_step_id: str | None = None
        for index, capability_value in enumerate(command.required_capabilities, start=1):
            capability = capability_value.value
            try:
                binding = self._bindings[capability]
            except KeyError as exc:
                raise MissingCapabilityBinding(capability) from exc
            step_id = f"execute-{index}-{capability.replace('.', '-')}"
            steps.append(
                ExecutionStep(
                    step_id=step_id,
                    capability=capability,
                    adapter=binding.adapter,
                    operation=binding.operation,
                    risk_class=command.risk_class,
                    input={"transaction": command_payload},
                    depends_on=(previous_step_id,) if previous_step_id is not None else (),
                    timeout_seconds=binding.timeout_seconds,
                    retry=binding.retry,
                    requires_approval=binding.requires_approval,
                    approval_timeout_seconds=binding.approval_timeout_seconds,
                    execution_channel=binding.execution_channel,
                )
            )
            previous_step_id = step_id
        return ExecutionPlan(
            transaction_id=transaction_id,
            tenant_id=command.tenant_id,
            business_digest=business_digest,
            risk_class=command.risk_class,
            verification_level=command.verification_requirements.minimum_independence_level,
            steps=tuple(steps),
            verification=(
                self._verification_factory(command)
                if self._verification_factory is not None
                else None
            ),
        )


class RouteHealthProvider(Protocol):
    def health_snapshot(
        self,
        tenant_id: str,
        candidate: RouteCandidate,
        policy: RoutingPolicy,
        evaluated_at: datetime,
    ) -> RouteHealthSnapshot: ...


class RoutingPolicyProvider(Protocol):
    def policy_for(self, command: TransactionCommand) -> RoutingPolicy: ...


class StaticRoutingPolicyProvider:
    def __init__(self, policy: RoutingPolicy) -> None:
        self._policy = policy

    def policy_for(self, command: TransactionCommand) -> RoutingPolicy:
        del command
        return self._policy


class OptimizingExecutionPlanner:
    """Freeze policy, observed health, ranking, and fallbacks before Workflow start."""

    def __init__(
        self,
        candidates: tuple[RouteCandidate, ...],
        policy_provider: RoutingPolicyProvider,
        health_provider: RouteHealthProvider,
        *,
        clock: Callable[[], datetime] | None = None,
        data_classification: DataClassification = DataClassification.INTERNAL,
        verification_factory: Callable[[TransactionCommand], VerificationPlan | None]
        | None = None,
    ) -> None:
        self._candidates = candidates
        self._policy_provider = policy_provider
        self._health_provider = health_provider
        self._clock = clock or (lambda: datetime.now(UTC))
        self._data_classification = data_classification
        self._verification_factory = verification_factory

    def build(
        self,
        command: TransactionCommand,
        *,
        transaction_id: str,
        business_digest: str,
    ) -> ExecutionPlan:
        command_payload = cast(
            dict[str, JsonValue],
            command.model_dump(mode="json", exclude={"transaction_id", "requested_at"}),
        )
        steps: list[ExecutionStep] = []
        decisions = []
        previous_step_id: str | None = None
        policy = self._policy_provider.policy_for(command)
        for index, capability_value in enumerate(command.required_capabilities, start=1):
            capability = capability_value.value
            candidates = tuple(
                candidate
                for candidate in self._candidates
                if candidate.capability == capability
            )
            request = RoutingRequest(
                tenant_id=command.tenant_id,
                capability=capability,
                risk_class=command.risk_class,
                data_classification=self._data_classification,
                required_verification_level=(
                    command.verification_requirements.minimum_independence_level
                ),
                evaluated_at=self._clock(),
            )
            health = tuple(
                self._health_provider.health_snapshot(
                    command.tenant_id,
                    candidate,
                    policy,
                    request.evaluated_at,
                )
                for candidate in candidates
            )
            decision = select_route(request, candidates, health, policy)
            candidate_by_id = {
                candidate.candidate_id: candidate for candidate in candidates
            }
            selected = candidate_by_id[decision.selected_candidate_id]
            fallbacks = tuple(
                _runtime_fallback(candidate_by_id[candidate_id])
                for candidate_id in decision.fallback_candidate_ids
            )
            step_id = f"execute-{index}-{capability.replace('.', '-')}"
            steps.append(
                ExecutionStep(
                    step_id=step_id,
                    capability=capability,
                    adapter=selected.adapter,
                    operation=selected.operation,
                    risk_class=command.risk_class,
                    input={"transaction": command_payload},
                    depends_on=(previous_step_id,) if previous_step_id else (),
                    timeout_seconds=selected.timeout_seconds,
                    retry=_runtime_retry(selected),
                    requires_approval=selected.requires_approval,
                    approval_timeout_seconds=selected.approval_timeout_seconds,
                    route_candidate_id=selected.candidate_id,
                    fallback_on_error_codes=selected.fallback_on_error_codes,
                    route_fallbacks=fallbacks,
                    execution_channel=selected.channel,
                )
            )
            decisions.append(decision)
            previous_step_id = step_id
        return ExecutionPlan(
            transaction_id=transaction_id,
            tenant_id=command.tenant_id,
            business_digest=business_digest,
            risk_class=command.risk_class,
            verification_level=(
                command.verification_requirements.minimum_independence_level
            ),
            data_classification=self._data_classification,
            steps=tuple(steps),
            verification=(
                self._verification_factory(command)
                if self._verification_factory is not None
                else None
            ),
            routing_decisions=tuple(decisions),
        )


def _runtime_retry(candidate: RouteCandidate) -> RetryPolicySpec:
    return RetryPolicySpec.model_validate(candidate.retry.model_dump())


def _runtime_fallback(candidate: RouteCandidate) -> RouteFallbackSpec:
    return RouteFallbackSpec(
        candidate_id=candidate.candidate_id,
        adapter=candidate.adapter,
        operation=candidate.operation,
        timeout_seconds=candidate.timeout_seconds,
        retry=_runtime_retry(candidate),
        fallback_on_error_codes=candidate.fallback_on_error_codes,
        execution_channel=candidate.channel,
    )


def synthetic_tracking_planner() -> StaticExecutionPlanner:
    """Return an explicitly synthetic local-demo binding, never a carrier adapter."""

    return StaticExecutionPlanner(
        {
            "shipment.track.read": CapabilityBinding(
                adapter="synthetic.track", operation="fetch"
            )
        }
    )


def synthetic_browser_tracking_planner() -> StaticExecutionPlanner:
    """Bind tracking to Board 3's certified synthetic browser adapter."""

    return StaticExecutionPlanner(
        {
            "shipment.track.read": CapabilityBinding(
                adapter="synthetic.browser.track",
                operation="fetch",
                execution_channel=ExecutionChannel.BROWSER,
            )
        }
    )


def synthetic_verified_browser_tracking_planner() -> StaticExecutionPlanner:
    """Bind Board 3 execution to Board 4's separate synthetic ledger verifier."""

    return StaticExecutionPlanner(
        {
            "shipment.track.read": CapabilityBinding(
                adapter="synthetic.browser.track",
                operation="fetch",
                execution_channel=ExecutionChannel.BROWSER,
            )
        },
        verification_factory=_synthetic_tracking_verification,
    )


def synthetic_optimized_tracking_planner(
    health_provider: RouteHealthProvider,
    *,
    clock: Callable[[], datetime] | None = None,
) -> OptimizingExecutionPlanner:
    """Prefer the local synthetic API and fall back to the certified browser path."""

    api = RouteCandidate.issue(
        candidate_id="synthetic.api.track",
        capability="shipment.track.read",
        adapter="synthetic.api.track",
        operation="fetch",
        channel=ExecutionChannel.API,
        baseline_success_bps=9950,
        baseline_sample_weight=20,
        expected_latency_ms=50,
        cost_micros=10,
        static_priority=10,
        maximum_risk_class=RiskClass.READ_ONLY,
        maximum_data_classification=DataClassification.INTERNAL,
        maximum_verification_level=VerificationLevel.L3,
        timeout_seconds=10,
        fallback_on_error_codes=(
            "api_not_found",
            "api_response_invalid",
            "api_server_error",
            "api_timeout",
            "api_transport_error",
        ),
    )
    browser = RouteCandidate.issue(
        candidate_id="synthetic.browser.track",
        capability="shipment.track.read",
        adapter="synthetic.browser.track",
        operation="fetch",
        channel=ExecutionChannel.BROWSER,
        baseline_success_bps=9700,
        baseline_sample_weight=20,
        expected_latency_ms=1000,
        cost_micros=500,
        static_priority=20,
        maximum_risk_class=RiskClass.READ_ONLY,
        maximum_data_classification=DataClassification.INTERNAL,
        maximum_verification_level=VerificationLevel.L3,
        timeout_seconds=60,
    )
    policy = RoutingPolicy.issue(
        policy_id="synthetic.local.optimized",
        version="1.0.0",
        allowed_channels=(ExecutionChannel.API, ExecutionChannel.BROWSER),
        maximum_risk_class=RiskClass.READ_ONLY,
        maximum_data_classification=DataClassification.INTERNAL,
        minimum_verification_level=VerificationLevel.L0,
        maximum_latency_ms=10_000,
        maximum_cost_micros=1_000_000,
        maximum_fallbacks=1,
    )
    return OptimizingExecutionPlanner(
        (api, browser),
        StaticRoutingPolicyProvider(policy),
        health_provider,
        clock=clock,
        verification_factory=_synthetic_tracking_verification,
    )


def _synthetic_tracking_verification(command: TransactionCommand) -> VerificationPlan | None:
    if (
        command.verification_requirements.minimum_independence_level
        is VerificationLevel.L0
    ):
        return None
    if not isinstance(command.subject, ShipmentSubject):
        raise MissingCapabilityBinding("verification.shipment.subject")
    reference = command.subject.carrier_booking_reference
    if reference is None:
        raise MissingCapabilityBinding("verification.shipment.carrier_booking_reference")
    return VerificationPlan(
        required_level=command.verification_requirements.minimum_independence_level,
        collectors=(
            EvidenceCollectionSpec(
                step_id="collect-synthetic-ledger",
                collector_id="synthetic.evidence.track",
                operation="fetch",
                input={"carrier_booking_reference": reference},
            ),
        ),
        claim_rules=(
            VerificationClaimRule(
                claim="shipment.reference",
                expected_pointer="/transaction/subject/carrier_booking_reference",
            ),
            VerificationClaimRule(
                claim="shipment.status",
                expected_pointer="/outputs/0/output/data/shipment.status",
            ),
        ),
    )
