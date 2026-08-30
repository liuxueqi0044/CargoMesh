from __future__ import annotations

import pytest

from cargomesh.channels.planner import ChannelPlanCompiler, ChannelStepSpec
from cargomesh.ir.enums import RiskClass, VerificationLevel
from cargomesh.routing.models import ExecutionChannel
from cargomesh.runtime.models import RetryPolicySpec
from cargomesh.verification.models import (
    EvidenceCollectionSpec,
    VerificationClaimRule,
    VerificationPlan,
)

BUSINESS_DIGEST = "sha256:" + "a" * 64
ARTIFACT_DIGEST = "sha256:" + "b" * 64


def _verification() -> VerificationPlan:
    return VerificationPlan(
        required_level=VerificationLevel.L2,
        collectors=(
            EvidenceCollectionSpec(
                step_id="verify",
                collector_id="ledger",
                operation="fetch",
            ),
        ),
        claim_rules=(
            VerificationClaimRule(
                claim="booking.status",
                expected_pointer="/booking/status",
            ),
        ),
    )


def test_compiles_edi_and_human_steps_in_dependency_order() -> None:
    steps = (
        ChannelStepSpec(
            step_id="prepare-edi",
            capability="edi.prepare",
            adapter="edi-gateway",
            operation="prepare",
            channel=ExecutionChannel.EDI,
            input={"document_digest": ARTIFACT_DIGEST},
            artifact_digest_reference=ARTIFACT_DIGEST,
        ),
        ChannelStepSpec(
            step_id="attend-review",
            capability="human.review",
            adapter="human-review",
            operation="approve",
            channel=ExecutionChannel.HUMAN,
            risk_class=RiskClass.REVERSIBLE_WRITE,
            requires_approval=True,
            retry=RetryPolicySpec(maximum_attempts=1),
            depends_on=("prepare-edi",),
        ),
    )
    plan = ChannelPlanCompiler().compile(
        transaction_id="txn-1",
        tenant_id="tenant-1",
        business_digest=BUSINESS_DIGEST,
        verification_level=VerificationLevel.L2,
        verification=_verification(),
        steps=steps,
    )
    assert [step.step_id for step in plan.steps] == ["prepare-edi", "attend-review"]
    assert plan.risk_class is RiskClass.REVERSIBLE_WRITE
    assert plan.steps[1].requires_approval is True
    assert plan.steps[0].input["artifact_digest_reference"] == ARTIFACT_DIGEST
    assert plan.verification is not None
    assert plan.verification.required_level is VerificationLevel.L2
    assert plan.steps[0].execution_channel is ExecutionChannel.EDI


@pytest.mark.parametrize(
    "kwargs",
    [
        {"channel": ExecutionChannel.API},
        {"channel": ExecutionChannel.EDI, "input": {"authorization": "SUPERSECRET"}},
        {"channel": ExecutionChannel.EDI, "input": {"body": "UNB+SUPERSECRET'"}},
        {"channel": ExecutionChannel.EDI, "artifact_digest_reference": "not-a-digest"},
    ],
)
def test_rejects_unsupported_channels_secrets_and_raw_documents(
    kwargs: dict[str, object],
) -> None:
    values: dict[str, object] = {
        "step_id": "send-edi",
        "capability": "edi.send",
        "adapter": "edi-gateway",
        "operation": "send",
    }
    values.update(kwargs)
    with pytest.raises(ValueError) as raised:
        ChannelStepSpec.model_validate(values)
    assert "SUPERSECRET" not in str(raised.value)


def test_effectful_steps_require_approval_and_one_attempt() -> None:
    with pytest.raises(ValueError):
        ChannelStepSpec(
            step_id="send-edi",
            capability="edi.send",
            adapter="edi-gateway",
            operation="send",
            channel=ExecutionChannel.EDI,
            risk_class=RiskClass.CONSEQUENTIAL_WRITE,
        )
    with pytest.raises(ValueError):
        ChannelStepSpec(
            step_id="send-edi",
            capability="edi.send",
            adapter="edi-gateway",
            operation="send",
            channel=ExecutionChannel.EDI,
            risk_class=RiskClass.CONSEQUENTIAL_WRITE,
            requires_approval=True,
        )


def test_plan_rejects_forward_dependencies_and_verification_identity_mismatch() -> None:
    step = ChannelStepSpec(
        step_id="send-edi",
        capability="edi.send",
        adapter="edi-gateway",
        operation="send",
        channel=ExecutionChannel.EDI,
    )
    compiler = ChannelPlanCompiler()
    with pytest.raises(ValueError):
        compiler.compile(
            transaction_id="txn-1",
            tenant_id="tenant-1",
            business_digest=BUSINESS_DIGEST,
            verification_level=VerificationLevel.L2,
            verification=None,
            steps=(
                step.model_copy(update={"depends_on": ("later",)}),
                step.model_copy(update={"step_id": "later"}),
            ),
        )
    with pytest.raises(ValueError):
        compiler.compile(
            transaction_id="txn-1",
            tenant_id="tenant-1",
            business_digest=BUSINESS_DIGEST,
            verification_level=VerificationLevel.L1,
            verification=_verification(),
            steps=(step,),
        )
