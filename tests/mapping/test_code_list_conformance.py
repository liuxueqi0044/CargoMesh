from pathlib import Path

from cargomesh.mapping.dcsa_tnt_v2 import (
    DOCUMENT_TYPE_CODES,
    EQUIPMENT_EVENT_TYPE_CODES,
    SHIPMENT_EVENT_TYPE_CODES,
    TRANSPORT_EVENT_TYPE_CODES,
)
from cargomesh.standards import OpenAPICodeListImporter

PROJECT_ROOT = Path(__file__).resolve().parents[2]
EVENT_DOMAIN = (
    PROJECT_ROOT
    / "third_party"
    / "dcsa"
    / "domain"
    / "event"
    / "event_domain_v2.0.0.yaml"
)


def test_mapper_code_guards_match_pinned_openapi() -> None:
    importer = OpenAPICodeListImporter()
    mappings = {
        "shipmentEventTypeCode": SHIPMENT_EVENT_TYPE_CODES,
        "equipmentEventTypeCode": EQUIPMENT_EVENT_TYPE_CODES,
        "transportEventTypeCode": TRANSPORT_EVENT_TYPE_CODES,
        "documentTypeCode": DOCUMENT_TYPE_CODES,
    }

    for schema_name, expected in mappings.items():
        imported = importer.import_schema_enum(
            EVENT_DOMAIN,
            schema_name=schema_name,
            namespace="test",
            source_version="2.3.0",
        )
        assert {record.code for record in imported} == expected
