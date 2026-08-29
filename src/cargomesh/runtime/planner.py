"""Deterministic compilation from Transaction IR to an execution plan."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import cast

from pydantic import BaseModel, ConfigDict, JsonValue

from cargomesh.ir import TransactionCommand
from cargomesh.ir.enums import VerificationLevel
from cargomesh.verification.models import (
    EvidenceCollectionSpec,
    VerificationClaimRule,
    VerificationPlan,
)

from .models import ExecutionPlan, ExecutionStep, RetryPolicySpec, RuntimeName


class CapabilityBinding(BaseModel):
    """Operator-configured binding; dynamic route optimization is deliberately absent."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    adapter: RuntimeName
    operation: RuntimeName
    requires_approval: bool = False
    approval_timeout_seconds: int | None = None
    timeout_seconds: int = 60
    retry: RetryPolicySpec = RetryPolicySpec()


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
                adapter="synthetic.browser.track", operation="fetch"
            )
        }
    )


def synthetic_verified_browser_tracking_planner() -> StaticExecutionPlanner:
    """Bind Board 3 execution to Board 4's separate synthetic ledger verifier."""

    return StaticExecutionPlanner(
        {
            "shipment.track.read": CapabilityBinding(
                adapter="synthetic.browser.track", operation="fetch"
            )
        },
        verification_factory=_synthetic_tracking_verification,
    )


def _synthetic_tracking_verification(command: TransactionCommand) -> VerificationPlan | None:
    if (
        command.verification_requirements.minimum_independence_level
        is VerificationLevel.L0
    ):
        return None
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
