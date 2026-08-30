"""Deterministic Adapter TCK scoring and drift-report contracts."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from enum import Enum, StrEnum
from typing import Annotated, Literal, Protocol, cast

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

TCK_SUITE_SCHEMA_VERSION: Literal["cargomesh.adapter-tck-suite/v1"] = (
    "cargomesh.adapter-tck-suite/v1"
)
TCK_REPORT_SCHEMA_VERSION: Literal["cargomesh.adapter-tck-report/v1"] = (
    "cargomesh.adapter-tck-report/v1"
)
DRIFT_REPORT_SCHEMA_VERSION: Literal["cargomesh.adapter-drift-report/v1"] = (
    "cargomesh.adapter-drift-report/v1"
)

TCKName = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=128,
        pattern=r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$",
    ),
]
Sha256Digest = Annotated[str, StringConstraints(pattern=r"^sha256:[0-9a-f]{64}$")]
_SAFE_CODE = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")


class TCKModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class TCKOutcome(StrEnum):
    PASS = "PASS"
    EXPECTED_HALT = "EXPECTED_HALT"
    DRIFT_DETECTED = "DRIFT_DETECTED"
    FAIL = "FAIL"


class TCKCase(TCKModel):
    case_id: TCKName
    portal_variant: TCKName
    expected_outcome: TCKOutcome
    security_critical: bool = False


class TCKSuite(TCKModel):
    schema_version: Literal["cargomesh.adapter-tck-suite/v1"] = TCK_SUITE_SCHEMA_VERSION
    suite_id: TCKName
    version: str = Field(pattern=r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$")
    cases: tuple[TCKCase, ...] = Field(min_length=1, max_length=128)
    suite_digest: Sha256Digest

    @model_validator(mode="after")
    def validate_suite(self) -> TCKSuite:
        case_ids = [case.case_id for case in self.cases]
        if len(case_ids) != len(set(case_ids)):
            raise ValueError("TCK case ids must be unique")
        if self.suite_digest != _model_digest(self, {"suite_digest"}):
            raise ValueError("TCK suite digest does not match")
        return self

    @classmethod
    def issue(cls, **values: object) -> TCKSuite:
        return cast(TCKSuite, _issue(cls, values, "suite_digest"))


class TCKObservation(TCKModel):
    case_id: TCKName
    outcome: TCKOutcome
    duration_ms: int = Field(ge=0, le=3_600_000)
    failure_code: TCKName | None = None
    artifact_digest: Sha256Digest | None = None

    @model_validator(mode="after")
    def validate_observation(self) -> TCKObservation:
        if self.outcome is TCKOutcome.FAIL and self.failure_code is None:
            raise ValueError("failed TCK observation requires a bounded code")
        if self.failure_code is not None and _SAFE_CODE.fullmatch(self.failure_code) is None:
            raise ValueError("TCK failure code is invalid")
        return self


class TCKCaseResult(TCKModel):
    case_id: TCKName
    expected_outcome: TCKOutcome
    actual_outcome: TCKOutcome
    passed: bool
    security_critical: bool
    failure_code: TCKName | None = None


class TCKReport(TCKModel):
    schema_version: Literal["cargomesh.adapter-tck-report/v1"] = TCK_REPORT_SCHEMA_VERSION
    suite_digest: Sha256Digest
    adapter_package_digest: Sha256Digest
    compatible: bool
    reliability_ppm: int = Field(ge=0, le=1_000_000)
    results: tuple[TCKCaseResult, ...] = Field(min_length=1, max_length=128)
    evaluated_at: datetime
    report_digest: Sha256Digest

    @model_validator(mode="after")
    def validate_report(self) -> TCKReport:
        if self.evaluated_at.tzinfo is None or self.evaluated_at.utcoffset() is None:
            raise ValueError("TCK evaluation time must include a timezone")
        passed_count = sum(result.passed for result in self.results)
        expected_reliability = passed_count * 1_000_000 // len(self.results)
        if self.reliability_ppm != expected_reliability:
            raise ValueError("TCK reliability does not match results")
        case_ids = [result.case_id for result in self.results]
        if len(case_ids) != len(set(case_ids)):
            raise ValueError("TCK result case ids must be unique")
        expected_compatibility = all(result.passed for result in self.results)
        if self.compatible != expected_compatibility:
            raise ValueError("TCK compatibility does not match results")
        if self.report_digest != _model_digest(self, {"report_digest"}):
            raise ValueError("TCK report digest does not match")
        return self

    @classmethod
    def issue(cls, **values: object) -> TCKReport:
        return cast(TCKReport, _issue(cls, values, "report_digest"))


class DriftReport(TCKModel):
    schema_version: Literal["cargomesh.adapter-drift-report/v1"] = (
        DRIFT_REPORT_SCHEMA_VERSION
    )
    adapter_package_digest: Sha256Digest
    baseline_signature_digest: Sha256Digest
    observed_signature_digest: Sha256Digest
    changed_semantics: tuple[TCKName, ...] = Field(min_length=1, max_length=64)
    detected_at: datetime
    report_digest: Sha256Digest

    @model_validator(mode="after")
    def validate_drift(self) -> DriftReport:
        if self.baseline_signature_digest == self.observed_signature_digest:
            raise ValueError("drift report requires different signatures")
        if len(self.changed_semantics) != len(set(self.changed_semantics)):
            raise ValueError("changed semantics must be unique")
        if self.detected_at.tzinfo is None or self.detected_at.utcoffset() is None:
            raise ValueError("drift detection time must include a timezone")
        if self.report_digest != _model_digest(self, {"report_digest"}):
            raise ValueError("drift report digest does not match")
        return self

    @classmethod
    def issue(cls, **values: object) -> DriftReport:
        return cast(DriftReport, _issue(cls, values, "report_digest"))


class TCKExecutor(Protocol):
    async def run(self, case: TCKCase) -> TCKObservation: ...


async def run_tck(
    suite: TCKSuite,
    adapter_package_digest: str,
    executor: TCKExecutor,
    *,
    evaluated_at: datetime | None = None,
) -> TCKReport:
    """Run every frozen case once, sequentially, and reject identity mismatches."""

    observations: list[TCKObservation] = []
    for case in suite.cases:
        observation = await executor.run(case)
        if observation.case_id != case.case_id:
            raise ValueError("TCK executor returned an observation for another case")
        observations.append(observation)
    return evaluate_tck(
        suite,
        adapter_package_digest,
        tuple(observations),
        evaluated_at=evaluated_at or datetime.now(UTC),
    )


def evaluate_tck(
    suite: TCKSuite,
    adapter_package_digest: str,
    observations: Sequence[TCKObservation],
    *,
    evaluated_at: datetime,
) -> TCKReport:
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", adapter_package_digest):
        raise ValueError("adapter package digest is invalid")
    by_case: dict[str, TCKObservation] = {}
    for observation in observations:
        if observation.case_id in by_case:
            raise ValueError("TCK observations must be unique")
        by_case[observation.case_id] = observation
    if set(by_case) != {case.case_id for case in suite.cases}:
        raise ValueError("TCK observations must cover the suite exactly")
    results = tuple(
        TCKCaseResult(
            case_id=case.case_id,
            expected_outcome=case.expected_outcome,
            actual_outcome=by_case[case.case_id].outcome,
            passed=by_case[case.case_id].outcome is case.expected_outcome,
            security_critical=case.security_critical,
            failure_code=by_case[case.case_id].failure_code,
        )
        for case in suite.cases
    )
    passed_count = sum(result.passed for result in results)
    return TCKReport.issue(
        suite_digest=suite.suite_digest,
        adapter_package_digest=adapter_package_digest,
        compatible=passed_count == len(results),
        reliability_ppm=passed_count * 1_000_000 // len(results),
        results=results,
        evaluated_at=evaluated_at,
    )


def synthetic_browser_tck_suite() -> TCKSuite:
    return TCKSuite.issue(
        suite_id="synthetic.browser.tck",
        version="1.0.0",
        cases=(
            TCKCase(
                case_id="healthy.read",
                portal_variant="healthy",
                expected_outcome=TCKOutcome.PASS,
            ),
            TCKCase(
                case_id="label.drift",
                portal_variant="label-drift",
                expected_outcome=TCKOutcome.DRIFT_DETECTED,
                security_critical=True,
            ),
            TCKCase(
                case_id="silent.drop",
                portal_variant="silent-drop",
                expected_outcome=TCKOutcome.EXPECTED_HALT,
                security_critical=True,
            ),
            TCKCase(
                case_id="server.error",
                portal_variant="server-error",
                expected_outcome=TCKOutcome.EXPECTED_HALT,
            ),
        ),
    )


def _issue(
    model_type: type[TCKSuite] | type[TCKReport] | type[DriftReport],
    values: Mapping[str, object],
    digest_field: str,
) -> TCKSuite | TCKReport | DriftReport:
    payload = dict(values)
    unsigned = model_type.model_construct(_fields_set=set(payload), **payload)
    payload[digest_field] = _model_digest(unsigned, {digest_field})
    return model_type.model_validate(payload)


def _model_digest(model: BaseModel, exclude: set[str]) -> str:
    return _digest(model.model_dump(mode="python", exclude=exclude, warnings=False))


def _digest(value: object) -> str:
    encoded = json.dumps(
        _canonical(value),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _canonical(value: object) -> object:
    if isinstance(value, BaseModel):
        return _canonical(value.model_dump(mode="python"))
    if isinstance(value, datetime):
        return value.astimezone(UTC).isoformat(timespec="microseconds")
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Mapping):
        return {str(key): _canonical(item) for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        return [_canonical(item) for item in value]
    return value


__all__ = [
    "DriftReport",
    "TCKCase",
    "TCKCaseResult",
    "TCKExecutor",
    "TCKObservation",
    "TCKOutcome",
    "TCKReport",
    "TCKSuite",
    "evaluate_tck",
    "run_tck",
    "synthetic_browser_tck_suite",
]
