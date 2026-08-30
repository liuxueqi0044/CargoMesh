"""In-memory, protocol-injected isolated candidate validation for AI repair."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Protocol

from .budget import BudgetReservation, RepairBudgetError, SQLiteRepairBudgetLedger
from .models import (
    RepairBudget,
    RepairCandidate,
    RepairProposal,
    RepairRequest,
    RepairUsage,
    SafeCode,
    ValidationReport,
    _digest,
)

_MAX_REPLACEMENT_BYTES = 1_048_576


class RepairSandboxError(RuntimeError):
    """Bounded failure which never contains model output or candidate content."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class ModelRepairResponse:
    """Ephemeral model output; do not persist this object or its replacement bytes."""

    base_package_digest: str
    replacements: Mapping[str, bytes]
    usage: RepairUsage


@dataclass(frozen=True)
class GateResult:
    passed: bool
    codes: tuple[str, ...]
    report_digest: str
    violation_codes: tuple[str, ...] = ()
    duration_seconds: int = 0


class RepairModelGateway(Protocol):
    def propose(
        self,
        request: RepairRequest,
        diagnostic_codes: tuple[str, ...],
    ) -> ModelRepairResponse: ...


class BasePackageProvider(Protocol):
    def read_package(self, package_digest: str) -> Mapping[str, bytes]: ...


class CandidatePackageLoader(Protocol):
    def load(self, files: Mapping[str, bytes]) -> str: ...


class CandidateTCKGate(Protocol):
    def validate(self, package_digest: str, *, timeout_seconds: int) -> GateResult: ...


class CandidateSecurityGate(Protocol):
    def validate(self, package_digest: str, *, timeout_seconds: int) -> GateResult: ...


@dataclass(frozen=True)
class SandboxOutcome:
    candidate: RepairCandidate
    validation: ValidationReport
    proposal: RepairProposal | None


class IsolatedRepairSandbox:
    """Creates a proposal only after isolated loader, TCK, and security gates pass."""

    def __init__(
        self,
        *,
        model_gateway: RepairModelGateway,
        base_packages: BasePackageProvider,
        package_loader: CandidatePackageLoader,
        tck_gate: CandidateTCKGate,
        security_gate: CandidateSecurityGate,
        budget_ledger: SQLiteRepairBudgetLedger,
    ) -> None:
        self._model_gateway = model_gateway
        self._base_packages = base_packages
        self._package_loader = package_loader
        self._tck_gate = tck_gate
        self._security_gate = security_gate
        self._budget_ledger = budget_ledger

    def generate_and_validate(
        self,
        request: RepairRequest,
        budget: RepairBudget,
        reserved_usage: RepairUsage,
        *,
        attempt_id: str,
        diagnostic_codes: Sequence[str] = (),
    ) -> SandboxOutcome:
        """Run the optional model path. Healthy executions never invoke this method."""

        _validate_codes(diagnostic_codes)
        try:
            base_files = _safe_base_files(
                self._base_packages.read_package(request.base_package_digest),
                request,
            )
            base_digest = self._package_loader.load(base_files)
        except RepairSandboxError:
            raise
        except Exception as exc:
            raise RepairSandboxError(
                "base_package_invalid", "Base package is not valid"
            ) from exc
        if base_digest != request.base_package_digest:
            raise RepairSandboxError("base_digest_mismatch", "Base package does not match")
        reservation = self._reserve(request, budget, reserved_usage, attempt_id)
        response: ModelRepairResponse | None = None
        try:
            response = self._model_gateway.propose(request, tuple(diagnostic_codes))
            _validate_model_usage(response, reserved_usage)
            candidate_files, changed_paths = _apply_replacements(request, base_files, response)
            candidate_package_digest = self._package_loader.load(candidate_files)
            _validate_digest(candidate_package_digest, "candidate_package_invalid")
            tck = self._tck_gate.validate(
                candidate_package_digest,
                timeout_seconds=budget.max_validation_seconds,
            )
            security = self._security_gate.validate(
                candidate_package_digest,
                timeout_seconds=budget.max_validation_seconds,
            )
            actual_usage = _actual_usage(response, changed_paths, tck, security)
            candidate = RepairCandidate.issue(
                job_id=request.job_id,
                request_digest=request.request_digest,
                base_package_digest=request.base_package_digest,
                candidate_package_digest=candidate_package_digest,
                changed_paths=changed_paths,
                usage=actual_usage,
                result_code=(
                    "candidate_validated"
                    if tck.passed and security.passed
                    else "candidate_rejected"
                ),
            )
            validation = _validation_report(candidate, tck, security)
            proposal = (
                RepairProposal.issue(
                    request_digest=request.request_digest,
                    candidate_digest=candidate.candidate_digest,
                    validation_report_digest=validation.report_digest,
                    result_code="proposal_ready",
                )
                if validation.passed
                else None
            )
            self._finalize(reservation, actual_usage)
            return SandboxOutcome(candidate=candidate, validation=validation, proposal=proposal)
        except RepairSandboxError:
            self._finalize_conservatively(reservation, response)
            raise
        except RepairBudgetError as exc:
            self._finalize_conservatively(reservation, response)
            raise RepairSandboxError(
                "repair_budget_failed", "Repair budget reservation failed"
            ) from exc
        except Exception as exc:
            self._finalize_conservatively(reservation, response)
            raise RepairSandboxError(
                "repair_sandbox_failed", "Isolated candidate validation failed"
            ) from exc

    def _reserve(
        self,
        request: RepairRequest,
        budget: RepairBudget,
        usage: RepairUsage,
        attempt_id: str,
    ) -> BudgetReservation:
        try:
            if self._budget_ledger.get(
                attempt_id,
                tenant_id=request.tenant_id,
                environment_id=request.environment_id,
                job_id=request.job_id,
            ) is not None:
                raise RepairSandboxError(
                    "repair_attempt_replayed", "Repair attempt was already reserved"
                )
            return self._budget_ledger.reserve_before_use(
                request,
                budget,
                usage,
                reservation_id=attempt_id,
            )
        except RepairBudgetError as exc:
            raise RepairSandboxError(
                "repair_budget_failed", "Repair budget reservation failed"
            ) from exc

    def _finalize(self, reservation: BudgetReservation, usage: RepairUsage) -> None:
        try:
            self._budget_ledger.finalize(reservation, usage)
        except RepairBudgetError as exc:
            raise RepairSandboxError(
                "repair_budget_failed", "Repair budget finalization failed"
            ) from exc

    def _finalize_conservatively(
        self,
        reservation: BudgetReservation,
        response: ModelRepairResponse | None,
    ) -> None:
        del response
        try:
            self._budget_ledger.finalize(reservation, reservation.reserved)
        except (RepairBudgetError, ValueError):
            return


def _safe_base_files(files: Mapping[str, bytes], request: RepairRequest) -> dict[str, bytes]:
    result: dict[str, bytes] = {}
    for path, content in files.items():
        _validate_path(path)
        if not isinstance(content, bytes) or len(content) > _MAX_REPLACEMENT_BYTES:
            raise RepairSandboxError("base_package_invalid", "Base package is not valid")
        _validate_json_bytes(content)
        result[path] = content
    if not result or not set(request.allowed_paths).issubset(result):
        raise RepairSandboxError("base_package_invalid", "Base package is not valid")
    return result


def _apply_replacements(
    request: RepairRequest,
    base_files: Mapping[str, bytes],
    response: ModelRepairResponse,
) -> tuple[dict[str, bytes], tuple[str, ...]]:
    if response.base_package_digest != request.base_package_digest:
        raise RepairSandboxError("base_digest_mismatch", "Candidate base package does not match")
    if not response.replacements:
        raise RepairSandboxError("candidate_empty", "Candidate contains no replacements")
    changed_paths = tuple(sorted(response.replacements))
    if not set(changed_paths).issubset(request.allowed_paths):
        raise RepairSandboxError("candidate_path_forbidden", "Candidate changes a forbidden path")
    candidate_files = dict(base_files)
    for path, content in response.replacements.items():
        _validate_path(path)
        if path not in base_files:
            raise RepairSandboxError(
                "candidate_path_forbidden", "Candidate changes a forbidden path"
            )
        if not isinstance(content, bytes) or len(content) > _MAX_REPLACEMENT_BYTES:
            raise RepairSandboxError(
                "candidate_content_invalid", "Candidate JSON replacement is invalid"
            )
        _validate_json_bytes(content)
        candidate_files[path] = content
    if _files_digest(candidate_files) == _files_digest(base_files):
        raise RepairSandboxError(
            "candidate_unchanged", "Candidate does not change the base package"
        )
    return candidate_files, changed_paths


def _actual_usage(
    response: ModelRepairResponse,
    changed_paths: tuple[str, ...],
    tck: GateResult,
    security: GateResult,
) -> RepairUsage:
    candidate_bytes = sum(len(value) for value in response.replacements.values())
    if (
        response.usage.files != len(changed_paths)
        or response.usage.candidate_bytes != candidate_bytes
    ):
        raise RepairSandboxError("model_usage_invalid", "Model usage metadata is invalid")
    return RepairUsage(
        model_calls=response.usage.model_calls,
        input_tokens=response.usage.input_tokens,
        output_tokens=response.usage.output_tokens,
        cost_units=response.usage.cost_units,
        files=len(changed_paths),
        candidate_bytes=candidate_bytes,
        validation_seconds=tck.duration_seconds + security.duration_seconds,
    )


def _validate_model_usage(
    response: ModelRepairResponse,
    reserved_usage: RepairUsage,
) -> None:
    usage = response.usage
    if usage.model_calls < 1:
        raise RepairSandboxError("model_usage_invalid", "Model usage metadata is invalid")
    if (
        usage.model_calls > reserved_usage.model_calls
        or usage.input_tokens > reserved_usage.input_tokens
        or usage.output_tokens > reserved_usage.output_tokens
        or usage.cost_units > reserved_usage.cost_units
        or usage.files > reserved_usage.files
        or usage.candidate_bytes > reserved_usage.candidate_bytes
        or usage.validation_seconds > reserved_usage.validation_seconds
    ):
        raise RepairSandboxError("model_usage_invalid", "Model usage metadata is invalid")
    if (
        usage.files != len(response.replacements)
        or usage.candidate_bytes != sum(len(value) for value in response.replacements.values())
    ):
        raise RepairSandboxError("model_usage_invalid", "Model usage metadata is invalid")


def _validation_report(
    candidate: RepairCandidate,
    tck: GateResult,
    security: GateResult,
) -> ValidationReport:
    check_codes = _safe_codes((*tck.codes, *security.codes))
    violations = _safe_codes((*tck.violation_codes, *security.violation_codes))
    return ValidationReport.issue(
        candidate_digest=candidate.candidate_digest,
        tck_report_digest=tck.report_digest,
        security_report_digest=security.report_digest,
        passed=tck.passed and security.passed and not violations,
        check_codes=check_codes or ("validation_completed",),
        violation_codes=violations,
        duration_seconds=tck.duration_seconds + security.duration_seconds,
    )


def _validate_path(path: str) -> None:
    if (
        not isinstance(path, str)
        or not path.endswith(".json")
        or path.startswith(("/", "."))
        or "\\" in path
        or "//" in path
        or any(part in {"", ".", ".."} for part in path.split("/"))
        or path.endswith((".py", ".js", ".ts"))
    ):
        raise RepairSandboxError("candidate_path_forbidden", "Candidate path is not allowed")


def _validate_json_bytes(content: bytes) -> None:
    try:
        text = content.decode("utf-8", errors="strict")
        json.loads(text, object_pairs_hook=_unique_json_object)
    except (TypeError, ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RepairSandboxError(
            "candidate_content_invalid", "Candidate JSON replacement is invalid"
        ) from exc


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _validate_codes(codes: Sequence[str]) -> None:
    _safe_codes(codes)


def _safe_codes(codes: Sequence[str]) -> tuple[str, ...]:
    values = tuple(codes)
    if len(values) > 128 or any(not isinstance(value, str) or not value for value in values):
        raise RepairSandboxError("diagnostic_invalid", "Repair diagnostics are invalid")
    try:
        return tuple(SafeCode(value) for value in values)
    except ValueError as exc:
        raise RepairSandboxError("diagnostic_invalid", "Repair diagnostics are invalid") from exc


def _validate_digest(value: str, code: str) -> None:
    if not isinstance(value, str) or len(value) != 71 or not value.startswith("sha256:"):
        raise RepairSandboxError(code, "Candidate package identity is invalid")
    try:
        int(value[7:], 16)
    except ValueError as exc:
        raise RepairSandboxError(code, "Candidate package identity is invalid") from exc


def _files_digest(files: Mapping[str, bytes]) -> str:
    return _digest(
        {
            path: "sha256:" + hashlib.sha256(content).hexdigest()
            for path, content in sorted(files.items())
        }
    )


__all__ = [
    "BasePackageProvider",
    "CandidatePackageLoader",
    "CandidateSecurityGate",
    "CandidateTCKGate",
    "GateResult",
    "IsolatedRepairSandbox",
    "ModelRepairResponse",
    "RepairModelGateway",
    "RepairSandboxError",
    "SandboxOutcome",
]
