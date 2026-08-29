"""Pydantic models for CargoMesh Transaction IR v1."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, JsonValue, StringConstraints, model_validator

from .enums import (
    Capability,
    EventType,
    RequestedEffect,
    RiskClass,
    TransactionType,
    VerificationLevel,
)

IR_SCHEMA_VERSION = "cargomesh.transaction/v1"

Identifier = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=256)]
ShortCode = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=64)]

_EXTENSION_NAMESPACE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+"
    r"[a-z]{2,63}/[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?/v[1-9][0-9]*$"
)


class IRModel(BaseModel):
    """Strict and immutable base model for IR values."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class ShipmentSubject(IRModel):
    """Identifiers that select a shipment or transport object."""

    kind: Literal["shipment"] = "shipment"
    carrier_booking_reference: Identifier | None = None
    booking_reference: Identifier | None = None
    transport_document_id: Identifier | None = None
    transport_document_reference: Identifier | None = None
    equipment_reference: Identifier | None = None
    schedule_id: Identifier | None = None
    transport_call_id: Identifier | None = None

    @model_validator(mode="after")
    def require_business_identifier(self) -> ShipmentSubject:
        identifiers = (
            self.carrier_booking_reference,
            self.booking_reference,
            self.transport_document_id,
            self.transport_document_reference,
            self.equipment_reference,
            self.schedule_id,
            self.transport_call_id,
        )
        if not any(identifiers):
            raise ValueError("shipment subject requires at least one business identifier")
        return self


class DateTimeFilter(IRModel):
    """A lossless representation of DCSA's date-time query operators."""

    eq: datetime | None = None
    gt: datetime | None = None
    gte: datetime | None = None
    lt: datetime | None = None
    lte: datetime | None = None

    @model_validator(mode="after")
    def validate_predicate(self) -> DateTimeFilter:
        values = (self.eq, self.gt, self.gte, self.lt, self.lte)
        if not any(values):
            raise ValueError("date-time filter requires at least one predicate")
        for value in values:
            if value is not None and (value.tzinfo is None or value.utcoffset() is None):
                raise ValueError("date-time filter values must include a timezone")
        if self.eq is not None and any((self.gt, self.gte, self.lt, self.lte)):
            raise ValueError("eq cannot be combined with range predicates")
        if self.gt is not None and self.gte is not None:
            raise ValueError("gt and gte are mutually exclusive")
        if self.lt is not None and self.lte is not None:
            raise ValueError("lt and lte are mutually exclusive")
        lower = self.gt or self.gte
        upper = self.lt or self.lte
        if lower is not None and upper is not None and lower > upper:
            raise ValueError("date-time lower bound must not be after upper bound")
        return self


class TrackFilters(IRModel):
    """Typed filters supported by the DCSA TNT 2.3 mapping."""

    event_types: tuple[EventType, ...] = ()
    shipment_event_type_codes: tuple[ShortCode, ...] = ()
    document_type_codes: tuple[ShortCode, ...] = ()
    transport_event_type_codes: tuple[ShortCode, ...] = ()
    equipment_event_type_codes: tuple[ShortCode, ...] = ()
    vessel_imo_number: ShortCode | None = None
    carrier_voyage_number: ShortCode | None = None
    export_voyage_number: ShortCode | None = None
    carrier_service_code: ShortCode | None = None
    un_location_code: ShortCode | None = None
    event_created_date_time: DateTimeFilter | None = None
    limit: int | None = Field(default=None, ge=1, le=1000)
    cursor: Identifier | None = None
    sort: Identifier | None = None

    @model_validator(mode="after")
    def reject_duplicate_filters(self) -> TrackFilters:
        collection_fields = (
            "event_types",
            "shipment_event_type_codes",
            "document_type_codes",
            "transport_event_type_codes",
            "equipment_event_type_codes",
        )
        for field_name in collection_fields:
            values = getattr(self, field_name)
            if len(values) != len(set(values)):
                raise ValueError(f"{field_name} must not contain duplicates")
        return self


class VerificationRequirements(IRModel):
    minimum_independence_level: VerificationLevel = VerificationLevel.L1


class TransactionCommand(IRModel):
    """Versioned business command, independent from a concrete execution backend."""

    schema_version: Literal["cargomesh.transaction/v1"] = "cargomesh.transaction/v1"
    transaction_id: Identifier | None = None
    tenant_id: Identifier
    transaction_type: Literal[TransactionType.SHIPMENT_TRACK] = TransactionType.SHIPMENT_TRACK
    external_reference: Identifier
    requested_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    subject: ShipmentSubject
    parameters: TrackFilters = Field(default_factory=TrackFilters)
    requested_effects: tuple[RequestedEffect, ...] = (
        RequestedEffect.LATEST_TRANSPORT_EVENTS_RETURNED,
    )
    verification_requirements: VerificationRequirements = Field(
        default_factory=VerificationRequirements
    )
    risk_class: Literal[RiskClass.READ_ONLY] = RiskClass.READ_ONLY
    required_capabilities: tuple[Capability, ...] = (Capability.SHIPMENT_TRACK_READ,)
    extensions: dict[str, JsonValue] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_command_invariants(self) -> TransactionCommand:
        if not self.requested_effects:
            raise ValueError("requested_effects must not be empty")
        if len(self.requested_effects) != len(set(self.requested_effects)):
            raise ValueError("requested_effects must not contain duplicates")
        if len(self.required_capabilities) != len(set(self.required_capabilities)):
            raise ValueError("required_capabilities must not contain duplicates")
        invalid_namespaces = [
            namespace
            for namespace in self.extensions
            if _EXTENSION_NAMESPACE.fullmatch(namespace) is None
        ]
        if invalid_namespaces:
            raise ValueError(
                "extension keys must use '<dns-name>/<schema-name>/vN' namespaces: "
                + ", ".join(sorted(invalid_namespaces))
            )
        if self.requested_at.tzinfo is None or self.requested_at.utcoffset() is None:
            raise ValueError("requested_at must include a timezone")
        return self
