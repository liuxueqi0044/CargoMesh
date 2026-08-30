"""DCSA Track & Trace 2.3 query mapping to CargoMesh Transaction IR v1."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Literal, cast, get_args

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from cargomesh.ir import (
    IR_SCHEMA_VERSION,
    DateTimeFilter,
    EventType,
    ShipmentSubject,
    TrackFilters,
    TransactionCommand,
)

from .models import MappingDiagnostic, MappingError, MappingFidelity, MappingResult

DCSA_TNT_QUERY_VERSION = "dcsa.tnt.query/v2.3"

ShipmentEventTypeCode = Literal[
    "RECE",
    "DRFT",
    "PENA",
    "PENU",
    "PENC",
    "CONF",
    "REJE",
    "APPR",
    "ISSU",
    "SURR",
    "SUBM",
    "VOID",
    "REQS",
    "CMPL",
    "HOLD",
    "RELS",
    "CANC",
]
DocumentTypeCode = Literal[
    "CBR", "BKG", "SHI", "SRM", "TRD", "ARN", "VGM", "CAS", "CUS", "DGD", "OOG"
]
TransportEventTypeCode = Literal["ARRI", "DEPA"]
EquipmentEventTypeCode = Literal[
    "LOAD", "DISC", "GTIN", "GTOT", "STUF", "STRP", "PICK", "DROP", "INSP", "RSEA", "RMVD"
]

SHIPMENT_EVENT_TYPE_CODES = frozenset(
    cast(tuple[str, ...], get_args(ShipmentEventTypeCode))
)
DOCUMENT_TYPE_CODES = frozenset(cast(tuple[str, ...], get_args(DocumentTypeCode)))
TRANSPORT_EVENT_TYPE_CODES = frozenset(cast(tuple[str, ...], get_args(TransportEventTypeCode)))
EQUIPMENT_EVENT_TYPE_CODES = frozenset(
    cast(tuple[str, ...], get_args(EquipmentEventTypeCode))
)

QueryValue = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=256)]
QueryCode = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=64)]


class DCSATNTQueryV2(BaseModel):
    """Supported subset of GET /v2/events parameters in DCSA TNT 2.3."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=True,
        str_strip_whitespace=True,
    )

    event_type: tuple[EventType, ...] = Field(default=(), alias="eventType")
    shipment_event_type_code: tuple[ShipmentEventTypeCode, ...] = Field(
        default=(), alias="shipmentEventTypeCode"
    )
    document_type_code: tuple[DocumentTypeCode, ...] = Field(default=(), alias="documentTypeCode")
    carrier_booking_reference: QueryValue | None = Field(
        default=None, alias="carrierBookingReference"
    )
    booking_reference: QueryValue | None = Field(default=None, alias="bookingReference")
    transport_document_id: QueryValue | None = Field(default=None, alias="transportDocumentID")
    transport_document_reference: QueryValue | None = Field(
        default=None, alias="transportDocumentReference"
    )
    transport_event_type_code: tuple[TransportEventTypeCode, ...] = Field(
        default=(), alias="transportEventTypeCode"
    )
    schedule_id: QueryValue | None = Field(default=None, alias="scheduleID")
    transport_call_id: QueryValue | None = Field(default=None, alias="transportCallID")
    vessel_imo_number: QueryCode | None = Field(default=None, alias="vesselIMONumber")
    carrier_voyage_number: QueryCode | None = Field(default=None, alias="carrierVoyageNumber")
    export_voyage_number: QueryCode | None = Field(default=None, alias="exportVoyageNumber")
    carrier_service_code: QueryCode | None = Field(default=None, alias="carrierServiceCode")
    un_location_code: QueryCode | None = Field(default=None, alias="UNLocationCode")
    equipment_event_type_code: tuple[EquipmentEventTypeCode, ...] = Field(
        default=(), alias="equipmentEventTypeCode"
    )
    equipment_reference: QueryValue | None = Field(default=None, alias="equipmentReference")
    event_created_date_time: datetime | None = Field(default=None, alias="eventCreatedDateTime")
    event_created_date_time_eq: datetime | None = Field(
        default=None, alias="eventCreatedDateTime:eq"
    )
    event_created_date_time_gt: datetime | None = Field(
        default=None, alias="eventCreatedDateTime:gt"
    )
    event_created_date_time_gte: datetime | None = Field(
        default=None, alias="eventCreatedDateTime:gte"
    )
    event_created_date_time_lt: datetime | None = Field(
        default=None, alias="eventCreatedDateTime:lt"
    )
    event_created_date_time_lte: datetime | None = Field(
        default=None, alias="eventCreatedDateTime:lte"
    )
    limit: int | None = Field(default=None, ge=1, le=1000)
    cursor: QueryValue | None = None
    sort: QueryValue | None = None

    @field_validator(
        "event_type",
        "shipment_event_type_code",
        "document_type_code",
        "transport_event_type_code",
        "equipment_event_type_code",
        mode="before",
    )
    @classmethod
    def accept_comma_separated_values(cls, value: object) -> object:
        if isinstance(value, str):
            return tuple(part.strip() for part in value.split(",") if part.strip())
        return value

    @model_validator(mode="after")
    def require_subject_reference(self) -> DCSATNTQueryV2:
        references = (
            self.carrier_booking_reference,
            self.booking_reference,
            self.transport_document_id,
            self.transport_document_reference,
            self.equipment_reference,
            self.schedule_id,
            self.transport_call_id,
        )
        if not any(references):
            raise ValueError(
                "DCSA TNT compilation requires at least one shipment, equipment, "
                "schedule, or transport-call reference"
            )
        return self

    @model_validator(mode="after")
    def validate_date_time_predicates(self) -> DCSATNTQueryV2:
        predicate = self.to_date_time_filter()
        if predicate is not None:
            DateTimeFilter.model_validate(predicate)
        return self

    def to_date_time_filter(self) -> DateTimeFilter | None:
        values = {
            "eq": self.event_created_date_time or self.event_created_date_time_eq,
            "gt": self.event_created_date_time_gt,
            "gte": self.event_created_date_time_gte,
            "lt": self.event_created_date_time_lt,
            "lte": self.event_created_date_time_lte,
        }
        if not any(values.values()):
            return None
        if self.event_created_date_time is not None and self.event_created_date_time_eq is not None:
            raise ValueError("eventCreatedDateTime and eventCreatedDateTime:eq are equivalent")
        return DateTimeFilter.model_validate(values)


class MappingContext(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    tenant_id: QueryValue
    external_reference: QueryValue | None = None
    transaction_id: QueryValue | None = None
    requested_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @model_validator(mode="after")
    def require_aware_time(self) -> MappingContext:
        if self.requested_at.tzinfo is None or self.requested_at.utcoffset() is None:
            raise ValueError("requested_at must include a timezone")
        return self


class DCSATNTV2Mapper:
    """Loss-aware bidirectional mapper for the supported TNT 2.3 query surface."""

    @staticmethod
    def _default_external_reference(query: DCSATNTQueryV2) -> str:
        candidates = (
            query.carrier_booking_reference,
            query.transport_document_reference,
            query.equipment_reference,
            query.booking_reference,
            query.transport_call_id,
            query.transport_document_id,
            query.schedule_id,
        )
        selected = next((candidate for candidate in candidates if candidate), None)
        if selected is None:
            raise ValueError("query does not contain a usable external reference")
        return selected

    def to_ir(
        self,
        query: DCSATNTQueryV2,
        context: MappingContext,
    ) -> MappingResult[TransactionCommand]:
        diagnostics = self._exact_mapping_diagnostics(query)
        external_reference = context.external_reference
        if external_reference is None:
            external_reference = self._default_external_reference(query)
            diagnostics.append(
                MappingDiagnostic(
                    source_path="query",
                    target_path="external_reference",
                    fidelity=MappingFidelity.DEFAULTED,
                    code="EXTERNAL_REFERENCE_SELECTED",
                    message="external_reference was deterministically selected from the query",
                )
            )

        command = TransactionCommand(
            transaction_id=context.transaction_id,
            tenant_id=context.tenant_id,
            external_reference=external_reference,
            requested_at=context.requested_at,
            subject=ShipmentSubject(
                carrier_booking_reference=query.carrier_booking_reference,
                booking_reference=query.booking_reference,
                transport_document_id=query.transport_document_id,
                transport_document_reference=query.transport_document_reference,
                equipment_reference=query.equipment_reference,
                schedule_id=query.schedule_id,
                transport_call_id=query.transport_call_id,
            ),
            parameters=TrackFilters(
                event_types=query.event_type,
                shipment_event_type_codes=query.shipment_event_type_code,
                document_type_codes=query.document_type_code,
                transport_event_type_codes=query.transport_event_type_code,
                equipment_event_type_codes=query.equipment_event_type_code,
                vessel_imo_number=query.vessel_imo_number,
                carrier_voyage_number=query.carrier_voyage_number,
                export_voyage_number=query.export_voyage_number,
                carrier_service_code=query.carrier_service_code,
                un_location_code=query.un_location_code,
                event_created_date_time=query.to_date_time_filter(),
                limit=query.limit,
                cursor=query.cursor,
                sort=query.sort,
            ),
        )
        diagnostics.extend(
            (
                MappingDiagnostic(
                    source_path="query",
                    target_path="verification_requirements.minimum_independence_level",
                    fidelity=MappingFidelity.DEFAULTED,
                    code="VERIFICATION_LEVEL_DEFAULTED",
                    message="read-only tracking uses the CargoMesh L1 verification default",
                ),
                MappingDiagnostic(
                    source_path="query",
                    target_path="risk_class",
                    fidelity=MappingFidelity.DEFAULTED,
                    code="RISK_CLASS_DEFAULTED",
                    message="shipment tracking is classified as READ_ONLY",
                ),
            )
        )
        return MappingResult(
            value=command,
            source_schema_version=DCSA_TNT_QUERY_VERSION,
            target_schema_version=IR_SCHEMA_VERSION,
            diagnostics=tuple(diagnostics),
        )

    @staticmethod
    def _exact_mapping_diagnostics(query: DCSATNTQueryV2) -> list[MappingDiagnostic]:
        paths = {
            "event_type": "parameters.event_types",
            "shipment_event_type_code": "parameters.shipment_event_type_codes",
            "document_type_code": "parameters.document_type_codes",
            "carrier_booking_reference": "subject.carrier_booking_reference",
            "booking_reference": "subject.booking_reference",
            "transport_document_id": "subject.transport_document_id",
            "transport_document_reference": "subject.transport_document_reference",
            "transport_event_type_code": "parameters.transport_event_type_codes",
            "schedule_id": "subject.schedule_id",
            "transport_call_id": "subject.transport_call_id",
            "vessel_imo_number": "parameters.vessel_imo_number",
            "carrier_voyage_number": "parameters.carrier_voyage_number",
            "export_voyage_number": "parameters.export_voyage_number",
            "carrier_service_code": "parameters.carrier_service_code",
            "un_location_code": "parameters.un_location_code",
            "equipment_event_type_code": "parameters.equipment_event_type_codes",
            "equipment_reference": "subject.equipment_reference",
            "limit": "parameters.limit",
            "cursor": "parameters.cursor",
            "sort": "parameters.sort",
        }
        diagnostics = [
            MappingDiagnostic(
                source_path=DCSATNTQueryV2.model_fields[name].alias or name,
                target_path=target,
                fidelity=MappingFidelity.EXACT,
                code="FIELD_MAPPED_EXACTLY",
                message="DCSA query field maps without semantic loss",
            )
            for name, target in paths.items()
            if getattr(query, name)
        ]
        if query.to_date_time_filter() is not None:
            diagnostics.append(
                MappingDiagnostic(
                    source_path="eventCreatedDateTime[:operator]",
                    target_path="parameters.event_created_date_time",
                    fidelity=MappingFidelity.NORMALIZED,
                    code="DATE_TIME_PREDICATE_NORMALIZED",
                    message="DCSA parameter-name operators were normalized into a typed predicate",
                )
            )
        return diagnostics

    def from_ir(self, command: TransactionCommand) -> MappingResult[DCSATNTQueryV2]:
        diagnostics: list[MappingDiagnostic] = []
        if not isinstance(command.subject, ShipmentSubject) or not isinstance(
            command.parameters, TrackFilters
        ):
            raise MappingError(
                (
                    MappingDiagnostic(
                        source_path="transaction_type",
                        fidelity=MappingFidelity.UNSUPPORTED,
                        code="TRANSACTION_TYPE_NOT_SUPPORTED",
                        message="DCSA TNT mapping only accepts shipment.track transactions",
                        blocking=True,
                    ),
                )
            )
        if command.extensions:
            diagnostics.append(
                MappingDiagnostic(
                    source_path="extensions",
                    fidelity=MappingFidelity.PARTIAL,
                    code="EXTENSIONS_NOT_REPRESENTABLE",
                    message=(
                        "CargoMesh namespaced extensions are not representable in TNT 2.3 query"
                    ),
                    blocking=True,
                )
            )
        filters = command.parameters
        subject = command.subject
        code_sets = (
            (
                "parameters.shipment_event_type_codes",
                filters.shipment_event_type_codes,
                SHIPMENT_EVENT_TYPE_CODES,
            ),
            ("parameters.document_type_codes", filters.document_type_codes, DOCUMENT_TYPE_CODES),
            (
                "parameters.transport_event_type_codes",
                filters.transport_event_type_codes,
                TRANSPORT_EVENT_TYPE_CODES,
            ),
            (
                "parameters.equipment_event_type_codes",
                filters.equipment_event_type_codes,
                EQUIPMENT_EVENT_TYPE_CODES,
            ),
        )
        for source_path, values, allowed in code_sets:
            unknown = sorted(set(values) - allowed)
            if unknown:
                diagnostics.append(
                    MappingDiagnostic(
                        source_path=source_path,
                        fidelity=MappingFidelity.UNSUPPORTED,
                        code="CODE_NOT_IN_DCSA_TNT_2_3",
                        message="IR contains codes outside the pinned DCSA TNT 2.3 code list",
                        blocking=True,
                    )
                )
        query = DCSATNTQueryV2(
            eventType=filters.event_types,
            shipmentEventTypeCode=cast(
                tuple[ShipmentEventTypeCode, ...],
                tuple(
                    value
                    for value in filters.shipment_event_type_codes
                    if value in SHIPMENT_EVENT_TYPE_CODES
                ),
            ),
            documentTypeCode=cast(
                tuple[DocumentTypeCode, ...],
                tuple(
                    value for value in filters.document_type_codes if value in DOCUMENT_TYPE_CODES
                ),
            ),
            carrierBookingReference=subject.carrier_booking_reference,
            bookingReference=subject.booking_reference,
            transportDocumentID=subject.transport_document_id,
            transportDocumentReference=subject.transport_document_reference,
            transportEventTypeCode=cast(
                tuple[TransportEventTypeCode, ...],
                tuple(
                    value
                    for value in filters.transport_event_type_codes
                    if value in TRANSPORT_EVENT_TYPE_CODES
                ),
            ),
            scheduleID=subject.schedule_id,
            transportCallID=subject.transport_call_id,
            vesselIMONumber=filters.vessel_imo_number,
            carrierVoyageNumber=filters.carrier_voyage_number,
            exportVoyageNumber=filters.export_voyage_number,
            carrierServiceCode=filters.carrier_service_code,
            UNLocationCode=filters.un_location_code,
            equipmentEventTypeCode=cast(
                tuple[EquipmentEventTypeCode, ...],
                tuple(
                    value
                    for value in filters.equipment_event_type_codes
                    if value in EQUIPMENT_EVENT_TYPE_CODES
                ),
            ),
            equipmentReference=subject.equipment_reference,
            eventCreatedDateTime=(
                filters.event_created_date_time.eq
                if filters.event_created_date_time is not None
                else None
            ),
            **(
                {
                    "eventCreatedDateTime:gt": filters.event_created_date_time.gt,
                    "eventCreatedDateTime:gte": filters.event_created_date_time.gte,
                    "eventCreatedDateTime:lt": filters.event_created_date_time.lt,
                    "eventCreatedDateTime:lte": filters.event_created_date_time.lte,
                }
                if filters.event_created_date_time is not None
                else {}
            ),
            limit=filters.limit,
            cursor=filters.cursor,
            sort=filters.sort,
        )
        return MappingResult(
            value=query,
            source_schema_version=IR_SCHEMA_VERSION,
            target_schema_version=DCSA_TNT_QUERY_VERSION,
            diagnostics=tuple(diagnostics),
        )
