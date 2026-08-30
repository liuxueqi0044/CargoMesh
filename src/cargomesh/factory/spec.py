"""Reviewed SOP and deterministic adapter-binding factory contracts."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from .capture import (
    CaptureAction,
    CaptureModel,
    CaptureName,
    DemonstrationCapture,
    FillAction,
    SelectAction,
    SemanticLocator,
)

FactoryName = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=128,
        pattern=r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$",
    ),
]
FactoryText = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=512)]
Sha256Digest = Annotated[str, StringConstraints(pattern=r"^sha256:[0-9a-f]{64}$")]
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class FactorySpecError(ValueError):
    """Bounded deterministic factory error."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class ReviewedSOP(CaptureModel):
    """Human-reviewed structured actions; no free-text instructions."""

    sop_id: FactoryName
    supported_parameters: tuple[CaptureName, ...] = Field(min_length=1, max_length=64)
    steps: tuple[CaptureAction, ...] = Field(min_length=1, max_length=100, alias="actions")
    sop_digest: Sha256Digest

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        populate_by_name=True,
        str_strip_whitespace=True,
    )

    @model_validator(mode="after")
    def validate_sop(self) -> ReviewedSOP:
        if len(self.supported_parameters) != len(set(self.supported_parameters)):
            raise ValueError("SOP parameters must be unique")
        action_parameters = {
            action.parameter
            for action in self.steps
            if isinstance(action, (FillAction, SelectAction))
        }
        if action_parameters != set(self.supported_parameters):
            raise ValueError("SOP parameters must exactly match its bindable actions")
        if self.sop_digest != _digest(self.model_dump(mode="python", exclude={"sop_digest"})):
            raise ValueError("SOP digest does not match structured metadata")
        return self

    @classmethod
    def issue(
        cls,
        *,
        sop_id: str,
        supported_parameters: Sequence[str],
        steps: Sequence[CaptureAction],
    ) -> ReviewedSOP:
        values: dict[str, object] = {
            "sop_id": sop_id,
            "supported_parameters": tuple(supported_parameters),
            "steps": tuple(steps),
        }
        values["sop_digest"] = _digest(values)
        return cls.model_validate(values)

    @property
    def digest(self) -> str:
        return self.sop_digest


class ParameterEvidence(CaptureModel):
    parameter: CaptureName
    evidence_ids: tuple[FactoryText, ...] = Field(min_length=1, max_length=16)
    value_digest: Sha256Digest

    @model_validator(mode="after")
    def validate_evidence(self) -> ParameterEvidence:
        if len(self.evidence_ids) != len(set(self.evidence_ids)):
            raise ValueError("parameter evidence references must be unique")
        return self


class Ambiguity(CaptureModel):
    ambiguity_id: FactoryName
    parameter: CaptureName
    reason: FactoryText
    candidate_indexes: tuple[int, ...] = Field(min_length=1, max_length=16)
    evidence_ids: tuple[FactoryText, ...] = Field(default=(), max_length=16)
    resolvable: bool = False


class Resolution(CaptureModel):
    ambiguity_id: FactoryName
    selected_index: int = Field(ge=0, le=100)
    reviewer: FactoryText


class ParameterBinding(CaptureModel):
    parameter: CaptureName
    action: Literal["fill", "select"]
    locator: SemanticLocator
    evidence_ids: tuple[FactoryText, ...] = Field(min_length=1, max_length=16)

    @model_validator(mode="after")
    def validate_evidence_ids(self) -> ParameterBinding:
        if len(self.evidence_ids) != len(set(self.evidence_ids)):
            raise ValueError("binding evidence references must be unique")
        return self


class BindingSpecification(CaptureModel):
    schema_name: FactoryName
    source_capture_digest: Sha256Digest
    source_sop_digest: Sha256Digest
    parameters: tuple[ParameterBinding, ...] = Field(default=(), max_length=64)
    ambiguities: tuple[Ambiguity, ...] = Field(default=(), max_length=64)
    resolutions: tuple[Resolution, ...] = Field(default=(), max_length=64)
    status: Literal["AMBIGUOUS", "READY", "CERTIFIED"] = "AMBIGUOUS"
    certified_by: FactoryText | None = None
    checksum: Sha256Digest

    @model_validator(mode="after")
    def validate_binding(self) -> BindingSpecification:
        if self.status in {"READY", "CERTIFIED"}:
            if not self.parameters:
                raise ValueError("ready binding requires executable parameters")
            if not _resolved(self.ambiguities, self.resolutions):
                raise ValueError("unresolved ambiguities cannot produce a ready binding")
        parameter_names = [item.parameter for item in self.parameters]
        if len(parameter_names) != len(set(parameter_names)):
            raise ValueError("binding parameters must be unique")
        ambiguity_ids = {item.ambiguity_id for item in self.ambiguities}
        resolution_ids = [item.ambiguity_id for item in self.resolutions]
        if (
            len(resolution_ids) != len(set(resolution_ids))
            or not set(resolution_ids) <= ambiguity_ids
        ):
            raise ValueError("binding resolutions must reference each ambiguity once")
        by_id = {item.ambiguity_id: item for item in self.ambiguities}
        for resolution in self.resolutions:
            ambiguity = by_id[resolution.ambiguity_id]
            if not ambiguity.resolvable:
                raise ValueError("evidence blockers cannot be resolved by choosing an action")
            if resolution.selected_index not in ambiguity.candidate_indexes:
                raise ValueError("binding resolution selects an unknown candidate")
        if self.status == "CERTIFIED" and self.certified_by is None:
            raise ValueError("certified binding requires a reviewer")
        if self.status != "CERTIFIED" and self.certified_by is not None:
            raise ValueError("only certified bindings may name a certifier")
        if self.checksum != _digest(self.model_dump(mode="python", exclude={"checksum"})):
            raise ValueError("binding checksum does not match metadata")
        return self

    @property
    def ready(self) -> bool:
        return self.status in {"READY", "CERTIFIED"}

    @property
    def certified(self) -> bool:
        return self.status == "CERTIFIED"


class AdapterFactoryCompiler:
    @staticmethod
    def compile(
        capture: DemonstrationCapture,
        sop: ReviewedSOP,
        *,
        parameter_evidence: Sequence[ParameterEvidence] = (),
        resolutions: Sequence[Resolution] = (),
        schema_name: str = "adapter.binding",
    ) -> BindingSpecification:
        evidence_by_parameter: dict[str, list[ParameterEvidence]] = {}
        for evidence in parameter_evidence:
            evidence_by_parameter.setdefault(evidence.parameter, []).append(evidence)
        capture_parameters = {
            action.parameter
            for action in capture.actions
            if isinstance(action, (FillAction, SelectAction))
        }
        if set(evidence_by_parameter) - capture_parameters:
            raise FactorySpecError(
                "factory_evidence_unused",
                "parameter evidence must reference a captured parameter",
            )
        resolution_by_id = {item.ambiguity_id: item for item in resolutions}
        if len(resolution_by_id) != len(tuple(resolutions)):
            raise FactorySpecError(
                "factory_resolution_duplicate",
                "ambiguity resolutions must be unique",
            )
        ambiguities: list[Ambiguity] = []
        bindings: list[ParameterBinding] = []
        sop_steps = sop.steps
        processed_parameters: set[str] = set()
        for index, action in enumerate(capture.actions):
            if not isinstance(action, (FillAction, SelectAction)):
                continue
            parameter = action.parameter
            if parameter in processed_parameters:
                ambiguities.append(
                    Ambiguity(
                        ambiguity_id=f"a-{index + 1}",
                        parameter=parameter,
                        reason="capture contains duplicate parameter actions",
                        candidate_indexes=(index,),
                        resolvable=False,
                    )
                )
                continue
            processed_parameters.add(parameter)
            candidate_indexes = tuple(
                candidate_index
                for candidate_index, candidate in enumerate(sop_steps)
                if isinstance(candidate, (FillAction, SelectAction))
                and candidate.parameter == parameter
            )
            reason: str | None = None
            evidence_items = evidence_by_parameter.get(parameter, [])
            digests = {item.value_digest for item in evidence_items}
            evidence_ids = tuple(
                sorted(
                    {
                        evidence_id
                        for item in evidence_items
                        for evidence_id in item.evidence_ids
                    }
                )
            )
            if parameter not in sop.supported_parameters:
                reason = "parameter is not supported by reviewed SOP"
            elif not candidate_indexes:
                reason = "capture parameter has no reviewed SOP action"
            elif not evidence_items:
                reason = "parameter has no independent evidence reference"
            elif len(digests) > 1:
                reason = "parameter evidence contains conflicting digests"
            if reason is not None:
                ambiguities.append(
                    Ambiguity(
                        ambiguity_id=f"a-{index + 1}",
                        parameter=parameter,
                        reason=reason,
                        candidate_indexes=candidate_indexes or (index,),
                        evidence_ids=evidence_ids,
                        resolvable=False,
                    )
                )
                continue
            requires_resolution = len(candidate_indexes) != 1 or (
                candidate_indexes
                and (
                    sop_steps[candidate_indexes[0]].kind != action.kind
                    or sop_steps[candidate_indexes[0]].locator != action.locator
                )
            )
            selected_index = candidate_indexes[0]
            if requires_resolution:
                ambiguity_id = f"a-{index + 1}"
                ambiguity = Ambiguity(
                    ambiguity_id=ambiguity_id,
                    parameter=parameter,
                    reason="reviewed SOP action requires an explicit human selection",
                    candidate_indexes=candidate_indexes,
                    evidence_ids=evidence_ids,
                    resolvable=True,
                )
                ambiguities.append(ambiguity)
                resolution = resolution_by_id.get(ambiguity_id)
                if resolution is None or resolution.selected_index not in candidate_indexes:
                    continue
                selected_index = resolution.selected_index
            candidate = sop_steps[selected_index]
            if not isinstance(candidate, (FillAction, SelectAction)):
                raise FactorySpecError(
                    "factory_mapping_invalid", "reviewed SOP action is not bindable"
                )
            bindings.append(
                ParameterBinding(
                    parameter=parameter,
                    action=candidate.kind,
                    locator=candidate.locator,
                    evidence_ids=evidence_ids,
                )
            )
        resolution_values = tuple(resolutions)
        unresolved = not bindings or not _resolved(tuple(ambiguities), resolution_values)
        status: Literal["AMBIGUOUS", "READY"] = "AMBIGUOUS" if unresolved else "READY"
        values: dict[str, object] = {
            "schema_name": schema_name,
            "source_capture_digest": capture.capture_digest,
            "source_sop_digest": sop.sop_digest,
            "parameters": tuple(bindings),
            "ambiguities": tuple(ambiguities),
            "resolutions": resolution_values,
            "status": status,
            "certified_by": None,
        }
        values["checksum"] = _digest(values)
        return BindingSpecification.model_validate(values)

    @staticmethod
    def certify(specification: BindingSpecification, *, reviewer: str) -> BindingSpecification:
        if not specification.ready:
            raise FactorySpecError("factory_not_ready", "binding specification is not ready")
        values = specification.model_dump(mode="python", exclude={"checksum"})
        values["status"] = "CERTIFIED"
        values["certified_by"] = reviewer
        values["checksum"] = _digest(values)
        return BindingSpecification.model_validate(values)


def _resolved(ambiguities: tuple[Ambiguity, ...], resolutions: Sequence[Resolution]) -> bool:
    if any(not item.resolvable for item in ambiguities):
        return False
    ids = {item.ambiguity_id for item in ambiguities}
    selected = {item.ambiguity_id for item in resolutions}
    return ids.issubset(selected)


def _canonical(value: object) -> object:
    if isinstance(value, BaseModel):
        return _canonical(value.model_dump(mode="python"))
    if isinstance(value, Mapping):
        return {str(key): _canonical(item) for key, item in value.items()}
    if isinstance(value, tuple | list):
        return [_canonical(item) for item in value]
    return value


def _digest(value: object) -> str:
    encoded = json.dumps(
        _canonical(value), ensure_ascii=False, separators=(",", ":"), sort_keys=True, default=str
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


__all__ = [
    "AdapterFactoryCompiler",
    "Ambiguity",
    "BindingSpecification",
    "FactorySpecError",
    "ParameterBinding",
    "ParameterEvidence",
    "Resolution",
    "ReviewedSOP",
]
