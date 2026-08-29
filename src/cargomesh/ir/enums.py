"""Stable vocabulary used by the CargoMesh transaction IR."""

from enum import StrEnum


class TransactionType(StrEnum):
    SHIPMENT_TRACK = "shipment.track"


class Capability(StrEnum):
    SHIPMENT_TRACK_READ = "shipment.track.read"


class RequestedEffect(StrEnum):
    LATEST_TRANSPORT_EVENTS_RETURNED = "latest_transport_events_returned"


class RiskClass(StrEnum):
    READ_ONLY = "READ_ONLY"
    REVERSIBLE_WRITE = "REVERSIBLE_WRITE"
    CONSEQUENTIAL_WRITE = "CONSEQUENTIAL_WRITE"


class VerificationLevel(StrEnum):
    L0 = "L0"
    L1 = "L1"
    L2 = "L2"
    L3 = "L3"


class EventType(StrEnum):
    SHIPMENT = "SHIPMENT"
    TRANSPORT = "TRANSPORT"
    EQUIPMENT = "EQUIPMENT"


class SortDirection(StrEnum):
    ASC = "ASC"
    DESC = "DESC"
