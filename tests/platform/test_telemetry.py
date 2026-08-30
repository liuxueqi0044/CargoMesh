from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from cargomesh.platform.telemetry import (
    AlertReason,
    MetricName,
    SLOWindow,
    SpanName,
    TelemetryEmitter,
    TelemetryError,
    TelemetryRecord,
    TelemetrySignal,
    calculate_slo,
    evaluate_slo_alert,
)

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def test_telemetry_is_allowlisted_payload_free_and_digest_bound() -> None:
    record = TelemetryRecord.issue(
        signal=TelemetrySignal.METRIC,
        name=MetricName.TRANSACTION_TOTAL,
        resource_attributes={"service.name": "cargomesh", "service.version": "0.13.0"},
        attributes={"tenant.id": "tenant-a", "environment.id": "prod"},
        value=1,
        occurred_at=NOW,
    )
    assert record.record_digest.startswith("sha256:")
    with pytest.raises(ValidationError):
        TelemetryRecord.issue(
            signal=TelemetrySignal.METRIC,
            name=MetricName.TRANSACTION_TOTAL,
            attributes={"payload": "business-input"},
            occurred_at=NOW,
        )
    with pytest.raises(ValidationError):
        TelemetryRecord.issue(
            signal=TelemetrySignal.SPAN,
            name=SpanName.ADAPTER_CALL,
            attributes={"tenant.id": "https://secret.example"},
            occurred_at=NOW,
        )


def test_exporter_is_injected_and_failure_has_no_exception_text() -> None:
    exported: list[TelemetryRecord] = []

    class Exporter:
        def export(self, record: TelemetryRecord) -> None:
            exported.append(record)

    record = TelemetryEmitter(Exporter()).emit(
        signal=TelemetrySignal.METRIC,
        name=MetricName.TRANSACTION_TOTAL,
        attributes={"tenant.id": "tenant-a"},
        value=1,
        occurred_at=NOW,
    )
    assert exported == [record]

    class Broken:
        def export(self, record: TelemetryRecord) -> None:
            del record
            raise RuntimeError("token=do-not-leak")

    with pytest.raises(TelemetryError) as caught:
        TelemetryEmitter(Broken()).emit(
            signal=TelemetrySignal.METRIC,
            name=MetricName.TRANSACTION_TOTAL,
            occurred_at=NOW,
        )
    assert caught.value.code == "telemetry_export_failed"
    assert "do-not-leak" not in str(caught.value)


def test_slo_rates_treat_missing_as_failure_and_alert_is_deterministic() -> None:
    window = SLOWindow(
        window_id="short",
        event_count=10,
        success_count=8,
        verified_count=7,
        latency_compliant_count=6,
        latency_sample_count=8,
        latency_total_ms=1000,
        window_seconds=60,
    )
    report = calculate_slo(window)
    assert report.availability_ppm == 800_000
    assert report.verified_rate_ppm == 700_000
    assert report.latency_compliance_ppm == 600_000
    decision = evaluate_slo_alert(
        slo_name="transaction", short_window=report, long_window=report
    )
    assert decision.alert and decision.reason_code is AlertReason.BURN_RATE_EXCEEDED
    assert decision.decision_digest == evaluate_slo_alert(
        slo_name="transaction", short_window=report, long_window=report
    ).decision_digest


def test_slo_rejects_inconsistent_counts_and_empty_window_is_not_success() -> None:
    with pytest.raises(ValidationError):
        SLOWindow(
            window_id="bad",
            event_count=1,
            success_count=2,
            verified_count=0,
            latency_compliant_count=0,
            latency_sample_count=0,
            latency_total_ms=0,
            window_seconds=1,
        )
    empty = calculate_slo(
        SLOWindow(
            window_id="empty",
            event_count=0,
            success_count=0,
            verified_count=0,
            latency_compliant_count=0,
            latency_sample_count=0,
            latency_total_ms=0,
            window_seconds=60,
        )
    )
    decision = evaluate_slo_alert(
        slo_name="transaction",
        short_window=empty,
        long_window=empty,
        minimum_events=1,
    )
    assert decision.alert and decision.reason_code is AlertReason.INSUFFICIENT_SAMPLES


def test_slo_reports_cannot_forge_rates_or_suppress_invalid_windows() -> None:
    report = calculate_slo(
        SLOWindow(
            window_id="real",
            event_count=10,
            success_count=9,
            verified_count=9,
            latency_compliant_count=9,
            latency_sample_count=9,
            latency_total_ms=10,
            window_seconds=60,
        )
    )
    with pytest.raises(ValidationError, match="does not match"):
        report.model_copy(update={"availability_ppm": 1_000_000}).model_validate(
            report.model_copy(update={"availability_ppm": 1_000_000}).model_dump()
        )
    decision = evaluate_slo_alert(
        slo_name="not valid!",
        short_window=report,
        long_window=report,
    )
    assert decision.alert and decision.reason_code is AlertReason.INVALID_WINDOW
