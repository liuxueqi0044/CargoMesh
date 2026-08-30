from __future__ import annotations

import asyncio
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from cargomesh.factory.tck import (
    DriftReport,
    TCKObservation,
    TCKOutcome,
    evaluate_tck,
    run_tck,
    synthetic_browser_tck_suite,
)

NOW = datetime(2040, 1, 2, 3, 4, 5, tzinfo=UTC)
PACKAGE_DIGEST = "sha256:" + "a" * 64


def observations(*, label_outcome: TCKOutcome = TCKOutcome.DRIFT_DETECTED):
    return (
        TCKObservation(case_id="healthy.read", outcome=TCKOutcome.PASS, duration_ms=10),
        TCKObservation(case_id="label.drift", outcome=label_outcome, duration_ms=5),
        TCKObservation(
            case_id="silent.drop", outcome=TCKOutcome.EXPECTED_HALT, duration_ms=4
        ),
        TCKObservation(
            case_id="server.error", outcome=TCKOutcome.EXPECTED_HALT, duration_ms=3
        ),
    )


def test_complete_expected_suite_is_compatible_and_digest_bound() -> None:
    suite = synthetic_browser_tck_suite()
    report = evaluate_tck(
        suite, PACKAGE_DIGEST, observations(), evaluated_at=NOW
    )

    assert report.compatible is True
    assert report.reliability_ppm == 1_000_000
    assert report.report_digest.startswith("sha256:")


def test_unexpected_drift_behavior_fails_compatibility() -> None:
    report = evaluate_tck(
        synthetic_browser_tck_suite(),
        PACKAGE_DIGEST,
        observations(label_outcome=TCKOutcome.PASS),
        evaluated_at=NOW,
    )

    assert report.compatible is False
    assert report.reliability_ppm == 750_000
    assert report.results[1].security_critical is True


def test_suite_requires_exactly_one_observation_per_case() -> None:
    suite = synthetic_browser_tck_suite()
    with pytest.raises(ValueError, match="cover the suite exactly"):
        evaluate_tck(suite, PACKAGE_DIGEST, observations()[:-1], evaluated_at=NOW)
    with pytest.raises(ValueError, match="unique"):
        evaluate_tck(
            suite,
            PACKAGE_DIGEST,
            (*observations(), observations()[0]),
            evaluated_at=NOW,
        )


def test_executor_case_identity_mismatch_is_rejected() -> None:
    class BrokenExecutor:
        async def run(self, case):
            del case
            return TCKObservation(
                case_id="another.case", outcome=TCKOutcome.PASS, duration_ms=1
            )

    with pytest.raises(ValueError, match="another case"):
        asyncio.run(
            run_tck(
                synthetic_browser_tck_suite(),
                PACKAGE_DIGEST,
                BrokenExecutor(),
                evaluated_at=NOW,
            )
        )


def test_drift_report_requires_distinct_signatures_and_no_payload() -> None:
    report = DriftReport.issue(
        adapter_package_digest=PACKAGE_DIGEST,
        baseline_signature_digest="sha256:" + "b" * 64,
        observed_signature_digest="sha256:" + "c" * 64,
        changed_semantics=("booking.reference.label",),
        detected_at=NOW,
    )
    assert report.report_digest.startswith("sha256:")
    with pytest.raises(ValidationError, match="different signatures"):
        DriftReport.issue(
            adapter_package_digest=PACKAGE_DIGEST,
            baseline_signature_digest="sha256:" + "b" * 64,
            observed_signature_digest="sha256:" + "b" * 64,
            changed_semantics=("booking.reference.label",),
            detected_at=NOW,
        )
