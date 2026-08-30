"""Payload-free OpenTelemetry-shaped signals and deterministic SLO math.

The module intentionally does not import an OpenTelemetry SDK or perform any
I/O.  Applications inject an exporter implementing :class:`TelemetryExporter`.
Only the allowlisted semantic attributes can cross this boundary.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Final, Literal, Protocol

from pydantic import (
    AliasChoices,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

SCHEMA_VERSION: Final[Literal["cargomesh.telemetry/v1"]] = "cargomesh.telemetry/v1"
SLO_SCHEMA_VERSION: Final[Literal["cargomesh.slo/v1"]] = "cargomesh.slo/v1"
ALERT_SCHEMA_VERSION: Final[Literal["cargomesh.slo-alert/v1"]] = (
    "cargomesh.slo-alert/v1"
)
Sha256Digest = Annotated[str, StringConstraints(pattern=r"^sha256:[0-9a-f]{64}$")]
Identifier = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=128,
        pattern=r"^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$",
    ),
]


class TelemetrySignal(StrEnum):
    SPAN = "span"
    METRIC = "metric"
    LOG = "log"


class MetricName(StrEnum):
    TRANSACTION_TOTAL = "cargomesh.transaction.total"
    TRANSACTION_SUCCESS = "cargomesh.transaction.success"
    TRANSACTION_VERIFIED = "cargomesh.transaction.verified"
    TRANSACTION_LATENCY_MS = "cargomesh.transaction.latency_ms"
    ADAPTER_OUTCOME_TOTAL = "cargomesh.adapter.outcome.total"
    ADAPTER_OUTCOME_FAILURE = "cargomesh.adapter.outcome.failure"


class SpanName(StrEnum):
    TRANSACTION_COMPILE = "cargomesh.transaction.compile"
    TRANSACTION_EXECUTE = "cargomesh.transaction.execute"
    VERIFICATION = "cargomesh.verification"
    ADAPTER_CALL = "cargomesh.adapter.call"


class LogName(StrEnum):
    SECURITY_EVENT = "cargomesh.security.event"
    LIFECYCLE_EVENT = "cargomesh.lifecycle.event"


# Names follow OTel's dot-separated semantic convention style.  Resource and
# signal attributes have separate sets so a caller cannot smuggle dimensions
# into a less restricted signal type.
RESOURCE_ATTRIBUTE_ALLOWLIST = frozenset(
    {
        "service.name",
        "service.version",
        "deployment.environment.name",
        "telemetry.sdk.name",
        "telemetry.sdk.version",
    }
)
SPAN_ATTRIBUTE_ALLOWLIST = frozenset(
    {
        "tenant.id",
        "environment.id",
        "transaction.id",
        "operation.name",
        "transaction.state",
        "verification.status",
        "adapter.id",
        "adapter.version",
        "route.candidate.id",
        "result",
        "error.code",
    }
)
METRIC_ATTRIBUTE_ALLOWLIST = frozenset(
    {
        "tenant.id",
        "environment.id",
        "operation.name",
        "adapter.id",
        "adapter.version",
        "route.candidate.id",
        "result",
        "verification.status",
        "slo.name",
        "window.id",
    }
)
ATTRIBUTE_ALLOWLIST = frozenset(
    RESOURCE_ATTRIBUTE_ALLOWLIST | SPAN_ATTRIBUTE_ALLOWLIST | METRIC_ATTRIBUTE_ALLOWLIST
)
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_SAFE_KEY_RE = re.compile(
    r"(?:authorization|cookie|credential|password|secret|token|api[_-]?key|payload|body|"
    r"claim|evidence|exception|url|path)",
    re.IGNORECASE,
)
_SECRET_VALUE_RE = re.compile(
    r"(?:\bbearer\s+|\b(?:password|secret|token|cookie|api[_-]?key)\s*[=:])",
    re.IGNORECASE,
)


class TelemetryError(RuntimeError):
    """Bounded telemetry failure that never exposes exporter details."""

    def __init__(self, code: str, message: str = "Telemetry operation failed") -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class TelemetryExportError(TelemetryError):
    def __init__(self) -> None:
        super().__init__("telemetry_export_failed", "Telemetry export failed")


class TelemetryExporter(Protocol):
    """Injected export boundary; implementations may persist or export data."""

    def export(self, record: TelemetryRecord) -> None: ...


TelemetryScalar = str | int | bool


class FrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class TelemetryRecord(FrozenModel):
    schema_version: Literal["cargomesh.telemetry/v1"] = SCHEMA_VERSION
    signal: TelemetrySignal
    name: Identifier
    resource_attributes: dict[Identifier, TelemetryScalar] = Field(
        default_factory=dict, max_length=16
    )
    attributes: dict[Identifier, TelemetryScalar] = Field(default_factory=dict, max_length=16)
    value: int | bool | None = None
    occurred_at: datetime
    record_digest: Sha256Digest

    @field_validator("occurred_at")
    @classmethod
    def require_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("telemetry timestamp must include a timezone")
        return value.astimezone(UTC)

    @field_validator("attributes")
    @classmethod
    def validate_attributes(
        cls, value: dict[str, TelemetryScalar]
    ) -> dict[str, TelemetryScalar]:
        for key, item in value.items():
            if key not in ATTRIBUTE_ALLOWLIST or _SAFE_KEY_RE.search(key):
                raise ValueError("telemetry attribute is not allowlisted")
            if isinstance(item, str) and (
                not _valid_scalar_string(item) or _SECRET_VALUE_RE.search(item)
            ):
                raise ValueError("telemetry attribute value is not bounded")
            if not isinstance(item, (str, int, bool)):
                raise ValueError("telemetry attribute value type is not allowed")
            if isinstance(item, int) and not isinstance(item, bool) and not _bounded_int(item):
                raise ValueError("telemetry attribute integer is not bounded")
        return value

    @field_validator("resource_attributes")
    @classmethod
    def validate_resource_attributes(
        cls, value: dict[str, TelemetryScalar]
    ) -> dict[str, TelemetryScalar]:
        return _validate_attribute_values(value, RESOURCE_ATTRIBUTE_ALLOWLIST)

    @model_validator(mode="after")
    def validate_signal_attributes(self) -> TelemetryRecord:
        allowed = {
            TelemetrySignal.SPAN: SPAN_ATTRIBUTE_ALLOWLIST,
            TelemetrySignal.METRIC: METRIC_ATTRIBUTE_ALLOWLIST,
            TelemetrySignal.LOG: SPAN_ATTRIBUTE_ALLOWLIST,
        }[self.signal]
        if any(key not in allowed for key in self.attributes):
            raise ValueError("telemetry attribute is not valid for signal")
        return self

    @model_validator(mode="after")
    def validate_signal_name(self) -> TelemetryRecord:
        if self.signal is TelemetrySignal.METRIC and self.name not in set(MetricName):
            raise ValueError("metric name is not allowlisted")
        if self.signal is TelemetrySignal.SPAN and self.name not in set(SpanName):
            raise ValueError("span name is not allowlisted")
        if self.signal is TelemetrySignal.LOG and self.name not in set(LogName):
            raise ValueError("log name is not allowlisted")
        if (
            isinstance(self.value, int)
            and not isinstance(self.value, bool)
            and not _bounded_int(self.value)
        ):
            raise ValueError("telemetry value integer is not bounded")
        return self

    @model_validator(mode="after")
    def validate_digest(self) -> TelemetryRecord:
        if self.record_digest != _model_digest(self, exclude={"record_digest"}):
            raise ValueError("telemetry record digest does not match")
        return self

    @classmethod
    def issue(cls, **values: object) -> TelemetryRecord:
        payload = dict(values)
        payload.setdefault("schema_version", SCHEMA_VERSION)
        unsigned = cls.model_construct(_fields_set=set(payload), **payload)
        payload["record_digest"] = _model_digest(unsigned, exclude={"record_digest"})
        return cls.model_validate(payload)


class TelemetryEmitter:
    """Validate and send bounded records to an injected exporter."""

    def __init__(self, exporter: TelemetryExporter) -> None:
        self.exporter = exporter

    def emit(
        self,
        *,
        signal: TelemetrySignal,
        name: str,
        attributes: Mapping[str, TelemetryScalar] | None = None,
        resource_attributes: Mapping[str, TelemetryScalar] | None = None,
        value: int | bool | None = None,
        occurred_at: datetime,
    ) -> TelemetryRecord:
        try:
            record = TelemetryRecord.issue(
                signal=signal,
                name=name,
                resource_attributes=dict(resource_attributes or {}),
                attributes=dict(attributes or {}),
                value=value,
                occurred_at=occurred_at,
            )
        except Exception as exc:
            del exc
            raise TelemetryError("invalid_telemetry", "Telemetry record is invalid") from None
        try:
            self.exporter.export(record)
        except Exception as exc:
            del exc
            raise TelemetryExportError() from None
        return record


class SLOWindow(FrozenModel):
    """Integer observations for one deterministic SLO measurement window.

    Counts are expected observations, not just observed successes.  Therefore
    absent/unknown outcomes remain in ``event_count`` and never inflate a rate.
    """

    schema_version: Literal["cargomesh.slo/v1"] = SLO_SCHEMA_VERSION
    window_id: Identifier
    event_count: int = Field(
        ge=0, le=2**63 - 1, validation_alias=AliasChoices("event_count", "total_events")
    )
    success_count: int = Field(
        ge=0,
        le=2**63 - 1,
        validation_alias=AliasChoices("success_count", "successful_events"),
    )
    verified_count: int = Field(
        ge=0, le=2**63 - 1, validation_alias=AliasChoices("verified_count", "verified_events")
    )
    latency_compliant_count: int = Field(
        ge=0,
        le=2**63 - 1,
        validation_alias=AliasChoices("latency_compliant_count", "latency_compliant_events"),
    )
    latency_sample_count: int = Field(
        ge=0,
        le=2**63 - 1,
        validation_alias=AliasChoices("latency_sample_count", "latency_events"),
    )
    latency_total_ms: int = Field(ge=0, le=2**63 - 1)
    window_seconds: int = Field(gt=0, le=2**63 - 1)

    @property
    def total_events(self) -> int:
        return self.event_count

    @property
    def successful_events(self) -> int:
        return self.success_count

    @property
    def verified_events(self) -> int:
        return self.verified_count

    @property
    def latency_compliant_events(self) -> int:
        return self.latency_compliant_count

    @model_validator(mode="after")
    def validate_counts(self) -> SLOWindow:
        if self.success_count > self.event_count:
            raise ValueError("success count exceeds event count")
        if self.verified_count > self.event_count:
            raise ValueError("verified count exceeds event count")
        if self.latency_compliant_count > self.event_count:
            raise ValueError("latency count exceeds event count")
        if self.latency_sample_count > self.event_count:
            raise ValueError("latency sample count exceeds event count")
        if self.latency_compliant_count > self.latency_sample_count:
            raise ValueError("compliant count exceeds latency samples")
        return self


class SLOReport(FrozenModel):
    schema_version: Literal["cargomesh.slo/v1"] = SLO_SCHEMA_VERSION
    window: SLOWindow
    availability_ppm: int = Field(ge=0, le=1_000_000)
    verified_rate_ppm: int = Field(ge=0, le=1_000_000)
    latency_compliance_ppm: int = Field(ge=0, le=1_000_000)
    availability_burn_rate_ppm: int = Field(ge=0, le=2**63 - 1)
    verified_rate_burn_rate_ppm: int = Field(ge=0, le=2**63 - 1)
    latency_burn_rate_ppm: int = Field(ge=0, le=2**63 - 1)
    target_availability_ppm: int = Field(ge=0, le=1_000_000)
    target_verified_rate_ppm: int = Field(ge=0, le=1_000_000)
    target_latency_compliance_ppm: int = Field(ge=0, le=1_000_000)

    @model_validator(mode="after")
    def validate_computed_values(self) -> SLOReport:
        denominator = self.window.event_count
        expected = (
            _rate(self.window.success_count, denominator),
            _rate(self.window.verified_count, denominator),
            _rate(self.window.latency_compliant_count, denominator),
        )
        actual = (
            self.availability_ppm,
            self.verified_rate_ppm,
            self.latency_compliance_ppm,
        )
        burns = (
            _burn(expected[0], self.target_availability_ppm),
            _burn(expected[1], self.target_verified_rate_ppm),
            _burn(expected[2], self.target_latency_compliance_ppm),
        )
        if actual != expected or burns != (
            self.availability_burn_rate_ppm,
            self.verified_rate_burn_rate_ppm,
            self.latency_burn_rate_ppm,
        ):
            raise ValueError("SLO report does not match its window and targets")
        return self


class AlertReason(StrEnum):
    WITHIN_BUDGET = "within_budget"
    BURN_RATE_EXCEEDED = "burn_rate_exceeded"
    INSUFFICIENT_SAMPLES = "insufficient_samples"
    INVALID_WINDOW = "invalid_window"


class SLOAlertDecision(FrozenModel):
    schema_version: Literal["cargomesh.slo-alert/v1"] = ALERT_SCHEMA_VERSION
    slo_name: Identifier
    alert: bool
    reason_code: AlertReason
    short_window_id: Identifier
    long_window_id: Identifier
    burn_rate_ppm: int = Field(ge=0, le=2**63 - 1)
    threshold_ppm: int = Field(ge=0, le=2**63 - 1)
    decision_digest: Sha256Digest

    @model_validator(mode="after")
    def validate_digest(self) -> SLOAlertDecision:
        if self.reason_code in {
            AlertReason.BURN_RATE_EXCEEDED,
            AlertReason.INSUFFICIENT_SAMPLES,
            AlertReason.INVALID_WINDOW,
        } and not self.alert:
            raise ValueError("unsafe SLO decisions must alert")
        if self.reason_code is AlertReason.WITHIN_BUDGET and self.alert:
            raise ValueError("within-budget SLO decision cannot alert")
        if (
            self.reason_code is AlertReason.BURN_RATE_EXCEEDED
            and self.burn_rate_ppm < self.threshold_ppm
        ):
            raise ValueError("burn-rate alert is below its threshold")
        if self.decision_digest != _model_digest(self, exclude={"decision_digest"}):
            raise ValueError("SLO alert decision digest does not match")
        return self

    @classmethod
    def issue(cls, **values: object) -> SLOAlertDecision:
        payload = dict(values)
        payload.setdefault("schema_version", ALERT_SCHEMA_VERSION)
        unsigned = cls.model_construct(_fields_set=set(payload), **payload)
        payload["decision_digest"] = _model_digest(unsigned, exclude={"decision_digest"})
        return cls.model_validate(payload)


def calculate_slo(
    window: SLOWindow,
    *,
    target_availability_ppm: int = 999_000,
    target_verified_rate_ppm: int = 999_000,
    target_latency_compliance_ppm: int = 950_000,
) -> SLOReport:
    """Calculate rates and error-budget burn rates using integer arithmetic."""

    _validate_target(target_availability_ppm)
    _validate_target(target_verified_rate_ppm)
    _validate_target(target_latency_compliance_ppm)
    denominator = window.event_count
    availability = _rate(window.success_count, denominator)
    verified = _rate(window.verified_count, denominator)
    latency = _rate(window.latency_compliant_count, denominator)
    return SLOReport(
        window=window,
        availability_ppm=availability,
        verified_rate_ppm=verified,
        latency_compliance_ppm=latency,
        availability_burn_rate_ppm=_burn(availability, target_availability_ppm),
        verified_rate_burn_rate_ppm=_burn(verified, target_verified_rate_ppm),
        latency_burn_rate_ppm=_burn(latency, target_latency_compliance_ppm),
        target_availability_ppm=target_availability_ppm,
        target_verified_rate_ppm=target_verified_rate_ppm,
        target_latency_compliance_ppm=target_latency_compliance_ppm,
    )


def evaluate_slo_alert(
    *,
    slo_name: str,
    short_window: SLOReport,
    long_window: SLOReport,
    threshold_ppm: int = 2_000_000,
    minimum_events: int = 1,
) -> SLOAlertDecision:
    """Require both explicit windows to breach the integer burn threshold."""

    safe_threshold = (
        threshold_ppm
        if isinstance(threshold_ppm, int) and not isinstance(threshold_ppm, bool)
        else 0
    )
    safe_threshold = min(2**63 - 1, max(0, safe_threshold))
    try:
        if (
            not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}", slo_name)
            or not isinstance(threshold_ppm, int)
            or isinstance(threshold_ppm, bool)
            or not 0 <= threshold_ppm <= 2**63 - 1
            or not isinstance(minimum_events, int)
            or isinstance(minimum_events, bool)
            or not 0 <= minimum_events <= 2**63 - 1
        ):
            raise ValueError
        slo = slo_name
    except Exception as exc:
        del exc
        return SLOAlertDecision.issue(
            slo_name="invalid",
            alert=True,
            reason_code=AlertReason.INVALID_WINDOW,
            short_window_id=short_window.window.window_id,
            long_window_id=long_window.window.window_id,
            burn_rate_ppm=2**63 - 1,
            threshold_ppm=safe_threshold,
        )
    if (
        short_window.window.event_count < minimum_events
        or long_window.window.event_count < minimum_events
    ):
        return SLOAlertDecision.issue(
            slo_name=slo,
            alert=True,
            reason_code=AlertReason.INSUFFICIENT_SAMPLES,
            short_window_id=short_window.window.window_id,
            long_window_id=long_window.window.window_id,
            burn_rate_ppm=calculate_multi_window_burn_rate(short_window, long_window),
            threshold_ppm=threshold_ppm,
        )
    short_burn = max(
        short_window.availability_burn_rate_ppm,
        short_window.verified_rate_burn_rate_ppm,
        short_window.latency_burn_rate_ppm,
    )
    long_burn = max(
        long_window.availability_burn_rate_ppm,
        long_window.verified_rate_burn_rate_ppm,
        long_window.latency_burn_rate_ppm,
    )
    burn = min(short_burn, long_burn)
    alert = short_burn >= threshold_ppm and long_burn >= threshold_ppm
    return SLOAlertDecision.issue(
        slo_name=slo,
        alert=alert,
        reason_code=AlertReason.BURN_RATE_EXCEEDED if alert else AlertReason.WITHIN_BUDGET,
        short_window_id=short_window.window.window_id,
        long_window_id=long_window.window.window_id,
        burn_rate_ppm=burn,
        threshold_ppm=threshold_ppm,
    )


def calculate_multi_window_burn_rate(
    short_window: SLOReport, long_window: SLOReport
) -> int:
    """Return the conservative (lower) burn rate required by both windows."""

    short = max(
        short_window.availability_burn_rate_ppm,
        short_window.verified_rate_burn_rate_ppm,
        short_window.latency_burn_rate_ppm,
    )
    long = max(
        long_window.availability_burn_rate_ppm,
        long_window.verified_rate_burn_rate_ppm,
        long_window.latency_burn_rate_ppm,
    )
    return min(short, long)


def _rate(numerator: int, denominator: int) -> int:
    return 0 if denominator == 0 else numerator * 1_000_000 // denominator


def _burn(observed_ppm: int, target_ppm: int) -> int:
    budget = 1_000_000 - target_ppm
    if budget <= 0:
        return 0 if observed_ppm >= target_ppm else 2**63 - 1
    error = 1_000_000 - observed_ppm
    return max(0, error) * 1_000_000 // budget


def _validate_target(value: int) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 1_000_000:
        raise ValueError("SLO target must be an integer ppm")


def _valid_scalar_string(value: str) -> bool:
    return bool(
        _DIGEST_RE.fullmatch(value)
        or re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}", value)
    )


def _validate_attribute_values(
    value: dict[str, TelemetryScalar], allowed: frozenset[str]
) -> dict[str, TelemetryScalar]:
    for key, item in value.items():
        if key not in allowed or _SAFE_KEY_RE.search(key):
            raise ValueError("telemetry attribute is not allowlisted")
        if isinstance(item, str) and (
            not _valid_scalar_string(item) or _SECRET_VALUE_RE.search(item)
        ):
            raise ValueError("telemetry attribute value is not bounded")
        if not isinstance(item, (str, int, bool)):
            raise ValueError("telemetry attribute value type is not allowed")
        if isinstance(item, int) and not isinstance(item, bool) and not _bounded_int(item):
            raise ValueError("telemetry attribute integer is not bounded")
    return value


def _bounded_int(value: int) -> bool:
    return -(2**63) <= value <= 2**63 - 1


def _model_digest(model: BaseModel, *, exclude: set[str]) -> str:
    value = model.model_dump(mode="python", exclude=exclude, warnings=False)
    canonical = json.dumps(
        _canonical(value), ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode()
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def _canonical(value: object) -> object:
    if isinstance(value, BaseModel):
        return _canonical(value.model_dump(mode="python"))
    if isinstance(value, datetime):
        return value.astimezone(UTC).isoformat(timespec="microseconds")
    if isinstance(value, StrEnum):
        return value.value
    if isinstance(value, Mapping):
        return {str(key): _canonical(item) for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        return [_canonical(item) for item in value]
    return value


__all__ = [
    "ALLOWED_METRIC_ATTRIBUTES",
    "ALLOWED_RESOURCE_ATTRIBUTES",
    "ALLOWED_SPAN_ATTRIBUTES",
    "ATTRIBUTE_ALLOWLIST",
    "METRIC_ATTRIBUTE_ALLOWLIST",
    "OTEL_METRIC_ATTRIBUTES",
    "OTEL_RESOURCE_ATTRIBUTES",
    "OTEL_SPAN_ATTRIBUTES",
    "RESOURCE_ATTRIBUTE_ALLOWLIST",
    "SPAN_ATTRIBUTE_ALLOWLIST",
    "AlertReason",
    "LogName",
    "MetricName",
    "SLOAlert",
    "SLOAlertDecision",
    "SLOMeasurement",
    "SLOReport",
    "SLOWindow",
    "SpanName",
    "TelemetryEmitter",
    "TelemetryError",
    "TelemetryExportError",
    "TelemetryExporter",
    "TelemetryRecord",
    "TelemetryScalar",
    "TelemetrySignal",
    "calculate_multi_window_burn_rate",
    "calculate_slo",
    "evaluate_slo_alert",
]

# Readable aliases used by callers that prefer the OTel terminology.
ALLOWED_RESOURCE_ATTRIBUTES = RESOURCE_ATTRIBUTE_ALLOWLIST
ALLOWED_SPAN_ATTRIBUTES = SPAN_ATTRIBUTE_ALLOWLIST
ALLOWED_METRIC_ATTRIBUTES = METRIC_ATTRIBUTE_ALLOWLIST
OTEL_RESOURCE_ATTRIBUTES = RESOURCE_ATTRIBUTE_ALLOWLIST
OTEL_SPAN_ATTRIBUTES = SPAN_ATTRIBUTE_ALLOWLIST
OTEL_METRIC_ATTRIBUTES = METRIC_ATTRIBUTE_ALLOWLIST

# Compatibility spellings for callers that describe the input as a
# measurement or the output as an alert rather than using the concrete model
# names above.
SLOMeasurement = SLOWindow
SLOAlert = SLOAlertDecision
