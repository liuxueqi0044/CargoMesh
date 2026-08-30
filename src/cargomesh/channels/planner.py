"""Deterministic compilation of attended EDI/HUMAN channel steps.

The compiler only translates channel metadata into the existing runtime
``ExecutionPlan``.  It does not parse or transport documents and never
claims that a plan has been verified.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence

from pydantic import ConfigDict, Field, JsonValue, field_validator, model_validator

from cargomesh.ir.enums import RiskClass, VerificationLevel
from cargomesh.routing.models import DataClassification, ExecutionChannel
from cargomesh.runtime.models import ExecutionPlan, ExecutionStep, RetryPolicySpec, RuntimeModel
from cargomesh.verification.models import VerificationPlan

CHANNEL_PLAN_MAX_INPUT_BYTES = 65_536
CHANNEL_PLAN_MAX_INPUT_DEPTH = 8
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_SECRET_KEY_RE = re.compile(
    r"(?:^|[._-])(?:authorization|cookie|credential|password|secret|token|api[_-]?key)"
    r"(?:$|[._-])",
    re.IGNORECASE,
)
_DOCUMENT_KEY_RE = re.compile(
    r"(?:^|[._-])(?:body|content|document|edi|mime|pdf|payload|raw|source)"
    r"(?:$|[._-])",
    re.IGNORECASE,
)


class ChannelStepSpec(RuntimeModel):
    """Immutable metadata for one EDI or attended-human execution step."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        populate_by_name=True,
        str_strip_whitespace=True,
    )

    step_id: str = Field(
        min_length=1, max_length=128, pattern=r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$"
    )
    capability: str = Field(
        min_length=1, max_length=128, pattern=r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$"
    )
    adapter: str = Field(
        min_length=1, max_length=128, pattern=r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$"
    )
    operation: str = Field(
        min_length=1, max_length=128, pattern=r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$"
    )
    execution_channel: ExecutionChannel = Field(alias="channel")
    risk_class: RiskClass = RiskClass.READ_ONLY
    input: dict[str, JsonValue] = Field(default_factory=dict, max_length=32)
    artifact_digest_reference: str | None = None
    requires_approval: bool = False
    approval_timeout_seconds: int | None = Field(default=None, ge=1, le=604_800)
    timeout_seconds: int = Field(default=60, ge=1, le=86_400)
    retry: RetryPolicySpec = Field(default_factory=RetryPolicySpec)
    depends_on: tuple[str, ...] = ()

    @field_validator("artifact_digest_reference")
    @classmethod
    def validate_artifact_digest(cls, value: str | None) -> str | None:
        if value is not None and _DIGEST_RE.fullmatch(value) is None:
            raise ValueError("artifact digest reference must be a lowercase sha256 digest")
        return value

    @model_validator(mode="after")
    def validate_step(self) -> ChannelStepSpec:
        if self.execution_channel not in {ExecutionChannel.EDI, ExecutionChannel.HUMAN}:
            raise ValueError("channel step must use EDI or HUMAN")
        if len(self.depends_on) != len(set(self.depends_on)):
            raise ValueError("channel step dependencies must be unique")
        if self.step_id in self.depends_on:
            raise ValueError("channel step cannot depend on itself")
        if self.risk_class is not RiskClass.READ_ONLY:
            if not self.requires_approval:
                raise ValueError("effectful channel steps require approval")
            if self.retry.maximum_attempts != 1:
                raise ValueError("effectful channel steps allow one attempt")
        elif self.approval_timeout_seconds is not None and not self.requires_approval:
            raise ValueError("approval timeout requires approval")
        _validate_metadata(self.input)
        return self

    @property
    def channel(self) -> ExecutionChannel:
        return self.execution_channel


class ChannelPlanCompiler:
    """Compile channel specs into the existing deterministic execution plan."""

    @staticmethod
    def compile(
        *,
        transaction_id: str,
        tenant_id: str,
        business_digest: str,
        verification_level: VerificationLevel,
        verification: VerificationPlan | None,
        steps: Sequence[ChannelStepSpec],
        environment_id: str = "local",
        data_classification: DataClassification = DataClassification.INTERNAL,
        risk_class: RiskClass | None = None,
    ) -> ExecutionPlan:
        if _DIGEST_RE.fullmatch(business_digest) is None:
            raise ValueError("business digest must be a lowercase sha256 digest")
        if not steps:
            raise ValueError("channel plan requires at least one step")
        frozen_steps = tuple(steps)
        step_ids = [step.step_id for step in frozen_steps]
        if len(step_ids) != len(set(step_ids)):
            raise ValueError("channel plan step ids must be unique")
        available: set[str] = set()
        for step in frozen_steps:
            if set(step.depends_on) - available:
                raise ValueError("channel plan dependencies must be topologically ordered")
            available.add(step.step_id)
        calculated_risk = max(
            (step.risk_class for step in frozen_steps),
            key=_risk_rank,
        )
        if risk_class is not None and risk_class is not calculated_risk:
            raise ValueError("channel plan risk summary is inaccurate")
        runtime_steps = tuple(
            ExecutionStep(
                step_id=step.step_id,
                capability=step.capability,
                adapter=step.adapter,
                operation=step.operation,
                risk_class=step.risk_class,
                input=_plan_input(step),
                depends_on=step.depends_on,
                timeout_seconds=step.timeout_seconds,
                retry=step.retry,
                requires_approval=step.requires_approval,
                approval_timeout_seconds=step.approval_timeout_seconds,
                execution_channel=step.execution_channel,
            )
            for step in frozen_steps
        )
        if verification is not None and verification.required_level is not verification_level:
            raise ValueError("verification level does not match the execution plan")
        return ExecutionPlan(
            transaction_id=transaction_id,
            tenant_id=tenant_id,
            environment_id=environment_id,
            business_digest=business_digest,
            risk_class=calculated_risk,
            verification_level=verification_level,
            data_classification=data_classification,
            steps=runtime_steps,
            verification=verification,
        )


def _plan_input(step: ChannelStepSpec) -> dict[str, JsonValue]:
    values = dict(step.input)
    if step.artifact_digest_reference is not None:
        if "artifact_digest_reference" in values:
            raise ValueError("artifact digest reference must be declared once")
        values["artifact_digest_reference"] = step.artifact_digest_reference
    _validate_metadata(values)
    return values


def _risk_rank(value: RiskClass) -> int:
    return {
        RiskClass.READ_ONLY: 0,
        RiskClass.REVERSIBLE_WRITE: 1,
        RiskClass.CONSEQUENTIAL_WRITE: 2,
    }[value]


def _validate_metadata(value: object, depth: int = 0, *, key: str = "input") -> None:
    if depth > CHANNEL_PLAN_MAX_INPUT_DEPTH:
        raise ValueError("channel input exceeds maximum nesting depth")
    if isinstance(value, Mapping):
        for item_key, item in value.items():
            key_text = str(item_key)
            if _SECRET_KEY_RE.search(key_text):
                raise ValueError("channel input contains a secret-like key")
            if _DOCUMENT_KEY_RE.search(key_text) and not key_text.lower().endswith(
                ("digest", "_digest", "reference", "_reference")
            ):
                raise ValueError("channel input contains raw document content")
            _validate_metadata(item, depth + 1, key=key_text)
    elif isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        for item in value:
            _validate_metadata(item, depth + 1, key=key)
    elif isinstance(value, bytes | bytearray):
        raise ValueError("channel input must be JSON metadata")
    elif isinstance(value, str) and ("UNB+" in value or "UNH+" in value):
        raise ValueError("channel input contains raw EDI content")
    try:
        encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("channel input must be bounded JSON metadata") from exc
    if len(encoded) > CHANNEL_PLAN_MAX_INPUT_BYTES:
        raise ValueError("channel input exceeds size limit")


__all__ = [
    "CHANNEL_PLAN_MAX_INPUT_BYTES",
    "CHANNEL_PLAN_MAX_INPUT_DEPTH",
    "ChannelPlanCompiler",
    "ChannelStepSpec",
]
