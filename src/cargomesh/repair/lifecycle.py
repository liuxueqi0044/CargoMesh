"""Append-only, digest-linked repair proposal, canary, promotion, and rollback lifecycle."""

from __future__ import annotations

import sqlite3
import threading
from collections.abc import Mapping
from contextlib import suppress
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Literal, Protocol, cast

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from .models import (
    CanaryResult,
    ReleaseResult,
    RepairApproval,
    RepairCandidate,
    RepairProposal,
    RepairRequest,
    RepairTransition,
    Sha256Digest,
    ValidationReport,
    _digest,
)

CANARY_EVIDENCE_SCHEMA_VERSION: Literal["cargomesh.repair-canary-evidence/v1"] = (
    "cargomesh.repair-canary-evidence/v1"
)
CANARY_THRESHOLDS_SCHEMA_VERSION: Literal["cargomesh.repair-canary-thresholds/v1"] = (
    "cargomesh.repair-canary-thresholds/v1"
)

_STATE_NONE = "none"


class RepairLifecycleState(StrEnum):
    GENERATED = "generated"
    VALIDATED = "validated"
    PROPOSED = "proposed"
    APPROVED = "approved"
    CANARY = "canary"
    PROMOTED = "promoted"
    ROLLED_BACK = "rolled_back"
    REJECTED = "rejected"
    FAILED = "failed"


class LifecycleModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class RepairLifecycleError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class CanaryThresholds(LifecycleModel):
    schema_version: Literal["cargomesh.repair-canary-thresholds/v1"] = (
        CANARY_THRESHOLDS_SCHEMA_VERSION
    )
    minimum_observations: int = Field(ge=1, le=1_000_000)
    minimum_success_ppm: int = Field(ge=0, le=1_000_000)
    thresholds_digest: Sha256Digest

    @model_validator(mode="after")
    def validate_thresholds(self) -> CanaryThresholds:
        if self.thresholds_digest != _digest(
            self.model_dump(mode="python", exclude={"thresholds_digest"})
        ):
            raise ValueError("canary thresholds digest does not match")
        return self

    @classmethod
    def issue(cls, **values: object) -> CanaryThresholds:
        return cast(CanaryThresholds, _issue(cls, values, "thresholds_digest"))


class VerifiedCanaryEvidence(LifecycleModel):
    """Independent evidence; lifecycle computes health from integer counters only."""

    schema_version: Literal["cargomesh.repair-canary-evidence/v1"] = (
        CANARY_EVIDENCE_SCHEMA_VERSION
    )
    proposal_digest: Sha256Digest
    evidence_source: Annotated[
        str,
        StringConstraints(
            strip_whitespace=True,
            min_length=1,
            max_length=128,
            pattern=r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$",
        ),
    ]
    source_record_digest: Sha256Digest
    observation_count: int = Field(ge=0, le=1_000_000)
    success_count: int = Field(ge=0, le=1_000_000)
    invariant_violation_count: int = Field(ge=0, le=1_000_000)
    verified: bool
    evidence_digest: Sha256Digest

    @model_validator(mode="after")
    def validate_evidence(self) -> VerifiedCanaryEvidence:
        if self.success_count > self.observation_count:
            raise ValueError("canary successes cannot exceed observations")
        if self.evidence_digest != _digest(
            self.model_dump(mode="python", exclude={"evidence_digest"})
        ):
            raise ValueError("canary evidence digest does not match")
        return self

    @classmethod
    def issue(cls, **values: object) -> VerifiedCanaryEvidence:
        return cast(VerifiedCanaryEvidence, _issue(cls, values, "evidence_digest"))


class CanaryDecision(LifecycleModel):
    proposal_digest: Sha256Digest
    evidence_digest: Sha256Digest
    thresholds_digest: Sha256Digest
    passed: bool
    decision_digest: Sha256Digest

    @model_validator(mode="after")
    def validate_decision(self) -> CanaryDecision:
        if self.decision_digest != _digest(
            self.model_dump(mode="python", exclude={"decision_digest"})
        ):
            raise ValueError("canary decision digest does not match")
        return self

    @classmethod
    def issue(cls, **values: object) -> CanaryDecision:
        return cast(CanaryDecision, _issue(cls, values, "decision_digest"))


class ApprovalVerifier(Protocol):
    def verify(
        self,
        approval: RepairApproval,
        proposal: RepairProposal,
        request: RepairRequest,
    ) -> bool: ...


class CanaryExecutor(Protocol):
    def run(self, proposal: RepairProposal) -> CanaryResult: ...


class CanaryEvidenceVerifier(Protocol):
    def verify(
        self,
        canary: CanaryResult,
        proposal: RepairProposal,
        request: RepairRequest,
    ) -> VerifiedCanaryEvidence: ...


class DeploymentBoundary(Protocol):
    def promote(self, candidate_package_digest: str, previous_package_digest: str) -> bool: ...

    def rollback(self, previous_package_digest: str) -> None: ...


class SQLiteRepairLifecycle:
    """Atomic append-only transition chain. It stores metadata only."""

    def __init__(self, database: str | Path = ":memory:") -> None:
        self._closed = False
        self._lock = threading.RLock()
        try:
            self._connection = sqlite3.connect(
                str(database),
                isolation_level=None,
                check_same_thread=False,
                timeout=10,
            )
            self._connection.row_factory = sqlite3.Row
            if str(database) != ":memory:":
                self._connection.execute("PRAGMA journal_mode=WAL")
            self._connection.execute("PRAGMA busy_timeout=10000")
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS repair_transitions (
                    transition_digest TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    environment_id TEXT NOT NULL,
                    job_id TEXT NOT NULL,
                    request_digest TEXT NOT NULL,
                    transition_json TEXT NOT NULL
                )
                """
            )
        except sqlite3.Error as exc:
            raise RepairLifecycleError(
                "repair_lifecycle_unavailable", "Repair lifecycle store is unavailable"
            ) from exc

    def append(
        self,
        request: RepairRequest,
        subject_digest: str,
        to_state: RepairLifecycleState,
        event_code: str,
        *,
        occurred_at: datetime | None = None,
    ) -> RepairTransition:
        with self._lock:
            self._ensure_open()
            connection = self._connection
            try:
                connection.execute("BEGIN IMMEDIATE")
                latest = self._latest(connection, request)
                from_state = _STATE_NONE if latest is None else latest.to_state
                if to_state.value not in _ALLOWED_TRANSITIONS.get(from_state, frozenset()):
                    raise RepairLifecycleError(
                        "repair_transition_invalid", "Repair lifecycle transition is invalid"
                    )
                transition = RepairTransition.issue(
                    tenant_id=request.tenant_id,
                    environment_id=request.environment_id,
                    job_id=request.job_id,
                    request_digest=request.request_digest,
                    subject_digest=subject_digest,
                    from_state=from_state,
                    to_state=to_state.value,
                    event_code=event_code,
                    previous_transition_digest=(
                        None if latest is None else latest.transition_digest
                    ),
                    occurred_at=occurred_at or datetime.now(UTC),
                )
                connection.execute(
                    """
                    INSERT INTO repair_transitions (
                        transition_digest, tenant_id, environment_id, job_id,
                        request_digest, transition_json
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        transition.transition_digest,
                        transition.tenant_id,
                        transition.environment_id,
                        transition.job_id,
                        transition.request_digest,
                        transition.model_dump_json(),
                    ),
                )
                connection.commit()
                return transition
            except RepairLifecycleError:
                _rollback(connection)
                raise
            except sqlite3.Error as exc:
                _rollback(connection)
                raise RepairLifecycleError(
                    "repair_lifecycle_unavailable", "Repair lifecycle store is unavailable"
                ) from exc

    def transitions(self, request: RepairRequest) -> tuple[RepairTransition, ...]:
        with self._lock:
            self._ensure_open()
            try:
                return self._load_chain(self._connection, request)
            except sqlite3.Error as exc:
                raise RepairLifecycleError(
                    "repair_lifecycle_unavailable", "Repair lifecycle store is unavailable"
                ) from exc

    def state(self, request: RepairRequest) -> RepairLifecycleState | None:
        chain = self.transitions(request)
        return None if not chain else RepairLifecycleState(chain[-1].to_state)

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._connection.close()
                self._closed = True

    def _latest(
        self, connection: sqlite3.Connection, request: RepairRequest
    ) -> RepairTransition | None:
        chain = self._load_chain(connection, request)
        return None if not chain else chain[-1]

    def _load_chain(
        self, connection: sqlite3.Connection, request: RepairRequest
    ) -> tuple[RepairTransition, ...]:
        rows = connection.execute(
            """
            SELECT transition_json FROM repair_transitions
            WHERE tenant_id = ? AND environment_id = ?
            AND job_id = ? AND request_digest = ?
            ORDER BY rowid
            """,
            (
                request.tenant_id,
                request.environment_id,
                request.job_id,
                request.request_digest,
            ),
        ).fetchall()
        chain = tuple(_decode_transition(_row_text(row)) for row in rows)
        previous: RepairTransition | None = None
        for transition in chain:
            expected_digest = None if previous is None else previous.transition_digest
            expected_state = _STATE_NONE if previous is None else previous.to_state
            if (
                transition.previous_transition_digest != expected_digest
                or transition.from_state != expected_state
            ):
                raise RepairLifecycleError(
                    "repair_lifecycle_invalid", "Repair lifecycle transition chain is invalid"
                )
            previous = transition
        return chain

    def _ensure_open(self) -> None:
        if self._closed:
            raise RepairLifecycleError(
                "repair_lifecycle_unavailable", "Repair lifecycle store is unavailable"
            )


class RepairLifecycle:
    """Coordinates injected approval, evidence, canary, and deployment boundaries."""

    def __init__(
        self,
        *,
        transitions: SQLiteRepairLifecycle,
        approval_verifier: ApprovalVerifier,
        canary_executor: CanaryExecutor,
        evidence_verifier: CanaryEvidenceVerifier,
        deployment: DeploymentBoundary,
        thresholds: CanaryThresholds,
    ) -> None:
        self._transitions = transitions
        self._approval_verifier = approval_verifier
        self._canary_executor = canary_executor
        self._evidence_verifier = evidence_verifier
        self._deployment = deployment
        self._thresholds = thresholds

    def record_candidate(
        self, request: RepairRequest, candidate: RepairCandidate
    ) -> RepairTransition:
        if (
            candidate.request_digest != request.request_digest
            or candidate.job_id != request.job_id
            or candidate.base_package_digest != request.base_package_digest
        ):
            raise RepairLifecycleError(
                "repair_candidate_mismatch", "Repair candidate does not match request"
            )
        return self._transitions.append(
            request,
            candidate.candidate_digest,
            RepairLifecycleState.GENERATED,
            "candidate_generated",
        )

    def record_validation(
        self,
        request: RepairRequest,
        candidate: RepairCandidate,
        report: ValidationReport,
    ) -> RepairTransition:
        if (
            candidate.request_digest != request.request_digest
            or report.candidate_digest != candidate.candidate_digest
        ):
            raise RepairLifecycleError(
                "repair_validation_mismatch", "Validation does not match repair candidate"
            )
        state = (
            RepairLifecycleState.VALIDATED
            if report.passed
            else RepairLifecycleState.REJECTED
        )
        return self._transitions.append(
            request,
            report.report_digest,
            state,
            "validation_passed" if report.passed else "validation_failed",
        )

    def record_proposal(
        self,
        request: RepairRequest,
        candidate: RepairCandidate,
        report: ValidationReport,
        proposal: RepairProposal,
    ) -> RepairTransition:
        if (
            not report.passed
            or candidate.request_digest != request.request_digest
            or candidate.job_id != request.job_id
            or candidate.base_package_digest != request.base_package_digest
            or proposal.request_digest != request.request_digest
            or proposal.candidate_digest != candidate.candidate_digest
            or proposal.validation_report_digest != report.report_digest
        ):
            raise RepairLifecycleError(
                "repair_proposal_invalid", "Repair proposal is not validated"
            )
        return self._transitions.append(
            request,
            proposal.proposal_digest,
            RepairLifecycleState.PROPOSED,
            "proposal_created",
        )

    def approve(
        self,
        request: RepairRequest,
        proposal: RepairProposal,
        approval: RepairApproval,
        *,
        now: datetime | None = None,
    ) -> RepairTransition:
        if (
            proposal.request_digest != request.request_digest
            or approval.proposal_digest != proposal.proposal_digest
        ):
            raise RepairLifecycleError(
                "repair_approval_mismatch", "Repair approval does not match proposal"
            )
        timestamp = datetime.now(UTC) if now is None else now
        if timestamp.tzinfo is None or timestamp.utcoffset() is None:
            raise RepairLifecycleError("repair_time_invalid", "Repair time is invalid")
        if proposal.expires_at <= timestamp:
            raise RepairLifecycleError("repair_proposal_expired", "Repair proposal has expired")
        try:
            approved = self._approval_verifier.verify(approval, proposal, request)
        except Exception as exc:
            raise RepairLifecycleError(
                "repair_approval_unverified", "Repair approval could not be verified"
            ) from exc
        if not approval.approved or approved is not True:
            raise RepairLifecycleError(
                "repair_approval_unverified", "Repair approval could not be verified"
            )
        return self._transitions.append(
            request,
            approval.approval_digest,
            RepairLifecycleState.APPROVED,
            "proposal_approved",
        )

    def canary(
        self,
        request: RepairRequest,
        candidate: RepairCandidate,
        proposal: RepairProposal,
        *,
        now: datetime | None = None,
    ) -> tuple[CanaryDecision, ReleaseResult | None]:
        _require_artifact_scope(request, candidate, proposal)
        timestamp = datetime.now(UTC) if now is None else now
        if timestamp.tzinfo is None or timestamp.utcoffset() is None:
            raise RepairLifecycleError("repair_time_invalid", "Repair time is invalid")
        if proposal.expires_at <= timestamp:
            raise RepairLifecycleError("repair_proposal_expired", "Repair proposal has expired")
        self._transitions.append(
            request,
            proposal.proposal_digest,
            RepairLifecycleState.CANARY,
            "canary_started",
        )
        try:
            result = self._canary_executor.run(proposal)
            if result.proposal_digest != proposal.proposal_digest:
                raise RepairLifecycleError(
                    "repair_canary_mismatch", "Canary result does not match proposal"
                )
            evidence = self._evidence_verifier.verify(result, proposal, request)
            decision = _evaluate_canary(proposal, evidence, self._thresholds)
        except Exception as exc:
            return self._rollback(request, candidate, proposal, "canary_unavailable", exc)
        if not decision.passed:
            return decision, self._rollback_release(request, candidate, "canary_failed")
        return decision, None

    def promote(
        self,
        request: RepairRequest,
        candidate: RepairCandidate,
        proposal: RepairProposal,
        decision: CanaryDecision,
    ) -> ReleaseResult:
        _require_artifact_scope(request, candidate, proposal)
        if (
            decision.proposal_digest != proposal.proposal_digest
            or decision.thresholds_digest != self._thresholds.thresholds_digest
        ):
            raise RepairLifecycleError(
                "repair_canary_mismatch", "Canary decision does not match proposal"
            )
        if self._transitions.state(request) is not RepairLifecycleState.CANARY:
            raise RepairLifecycleError(
                "repair_transition_invalid", "Repair lifecycle transition is invalid"
            )
        if not decision.passed:
            return self._rollback_release(request, candidate, "canary_failed")
        try:
            promoted = self._deployment.promote(
                candidate.candidate_package_digest,
                candidate.base_package_digest,
            )
        except Exception:
            promoted = False
        if promoted is not True:
            return self._rollback_release(request, candidate, "promotion_failed")
        self._transitions.append(
            request,
            decision.decision_digest,
            RepairLifecycleState.PROMOTED,
            "promoted",
        )
        return ReleaseResult.issue(
            previous_package_digest=candidate.base_package_digest,
            candidate_package_digest=candidate.candidate_package_digest,
            released=True,
            result_code="promoted",
        )

    def _rollback(
        self,
        request: RepairRequest,
        candidate: RepairCandidate,
        proposal: RepairProposal,
        code: str,
        cause: Exception,
    ) -> tuple[CanaryDecision, ReleaseResult]:
        decision = CanaryDecision.issue(
            proposal_digest=proposal.proposal_digest,
            evidence_digest=_empty_digest(),
            thresholds_digest=self._thresholds.thresholds_digest,
            passed=False,
        )
        del cause
        return decision, self._rollback_release(request, candidate, code)

    def _rollback_release(
        self, request: RepairRequest, candidate: RepairCandidate, code: str
    ) -> ReleaseResult:
        state = RepairLifecycleState.ROLLED_BACK
        try:
            self._deployment.rollback(candidate.base_package_digest)
        except Exception:
            code = "rollback_failed"
            state = RepairLifecycleState.FAILED
        self._transitions.append(
            request,
            candidate.base_package_digest,
            state,
            code,
        )
        return ReleaseResult.issue(
            previous_package_digest=candidate.base_package_digest,
            candidate_package_digest=candidate.candidate_package_digest,
            released=False,
            result_code=code,
        )


_ALLOWED_TRANSITIONS: dict[str, frozenset[str]] = {
    _STATE_NONE: frozenset({RepairLifecycleState.GENERATED.value}),
    RepairLifecycleState.GENERATED.value: frozenset(
        {RepairLifecycleState.VALIDATED.value, RepairLifecycleState.REJECTED.value}
    ),
    RepairLifecycleState.VALIDATED.value: frozenset({RepairLifecycleState.PROPOSED.value}),
    RepairLifecycleState.PROPOSED.value: frozenset({RepairLifecycleState.APPROVED.value}),
    RepairLifecycleState.APPROVED.value: frozenset({RepairLifecycleState.CANARY.value}),
    RepairLifecycleState.CANARY.value: frozenset(
        {
            RepairLifecycleState.PROMOTED.value,
            RepairLifecycleState.ROLLED_BACK.value,
            RepairLifecycleState.FAILED.value,
        }
    ),
}


def _require_artifact_scope(
    request: RepairRequest,
    candidate: RepairCandidate,
    proposal: RepairProposal,
) -> None:
    if (
        candidate.job_id != request.job_id
        or candidate.request_digest != request.request_digest
        or candidate.base_package_digest != request.base_package_digest
        or proposal.request_digest != request.request_digest
        or proposal.candidate_digest != candidate.candidate_digest
    ):
        raise RepairLifecycleError(
            "repair_artifact_mismatch", "Repair artifacts do not match request"
        )


def _evaluate_canary(
    proposal: RepairProposal,
    evidence: VerifiedCanaryEvidence,
    thresholds: CanaryThresholds,
) -> CanaryDecision:
    if evidence.proposal_digest != proposal.proposal_digest:
        raise RepairLifecycleError(
            "repair_canary_mismatch", "Canary evidence does not match proposal"
        )
    success_ppm = (
        0
        if evidence.observation_count == 0
        else evidence.success_count * 1_000_000 // evidence.observation_count
    )
    passed = (
        evidence.verified
        and evidence.observation_count >= thresholds.minimum_observations
        and success_ppm >= thresholds.minimum_success_ppm
        and evidence.invariant_violation_count == 0
    )
    return CanaryDecision.issue(
        proposal_digest=proposal.proposal_digest,
        evidence_digest=evidence.evidence_digest,
        thresholds_digest=thresholds.thresholds_digest,
        passed=passed,
    )


def _issue(
    model_type: type[CanaryThresholds]
    | type[VerifiedCanaryEvidence]
    | type[CanaryDecision],
    values: Mapping[str, object],
    digest_field: str,
) -> CanaryThresholds | VerifiedCanaryEvidence | CanaryDecision:
    payload = dict(values)
    unsigned = model_type.model_construct(_fields_set=set(payload), **payload)
    payload[digest_field] = _digest(unsigned.model_dump())
    return model_type.model_validate(payload)


def _row_text(row: sqlite3.Row) -> str:
    value = row["transition_json"]
    if not isinstance(value, str):
        raise RepairLifecycleError(
            "repair_lifecycle_invalid", "Repair lifecycle transition is invalid"
        )
    return value


def _decode_transition(value: str) -> RepairTransition:
    try:
        return RepairTransition.model_validate_json(value)
    except Exception as exc:
        raise RepairLifecycleError(
            "repair_lifecycle_invalid", "Repair lifecycle transition is invalid"
        ) from exc


def _empty_digest() -> str:
    return "sha256:" + "0" * 64


def _rollback(connection: sqlite3.Connection) -> None:
    with suppress(sqlite3.Error):
        connection.rollback()


__all__ = [
    "CANARY_EVIDENCE_SCHEMA_VERSION",
    "CANARY_THRESHOLDS_SCHEMA_VERSION",
    "ApprovalVerifier",
    "CanaryDecision",
    "CanaryEvidenceVerifier",
    "CanaryExecutor",
    "CanaryThresholds",
    "DeploymentBoundary",
    "RepairLifecycle",
    "RepairLifecycleError",
    "RepairLifecycleState",
    "SQLiteRepairLifecycle",
    "VerifiedCanaryEvidence",
]
