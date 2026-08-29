"""Independent evidence collection and deterministic verification."""

from .engine import evaluate_verification
from .models import (
    ClaimOutcome,
    EvidenceChannel,
    EvidenceObservation,
    ExecutionSource,
    VerificationPlan,
    VerificationReport,
    VerificationVerdict,
)

__all__ = [
    "ClaimOutcome",
    "EvidenceChannel",
    "EvidenceObservation",
    "ExecutionSource",
    "VerificationPlan",
    "VerificationReport",
    "VerificationVerdict",
    "evaluate_verification",
]
