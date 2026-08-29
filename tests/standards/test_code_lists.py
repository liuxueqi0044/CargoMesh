from pathlib import Path

from cargomesh.standards import OpenAPICodeListImporter, default_reference_data_catalog

PROJECT_ROOT = Path(__file__).resolve().parents[2]
EVENT_DOMAIN = (
    PROJECT_ROOT
    / "third_party"
    / "dcsa"
    / "domain"
    / "event"
    / "event_domain_v2.0.0.yaml"
)


def test_packaged_code_lists_match_pinned_openapi_enums() -> None:
    importer = OpenAPICodeListImporter()
    catalog = default_reference_data_catalog()
    mappings = {
        "shipmentEventTypeCode": "dcsa.tnt.shipment_event_type",
        "equipmentEventTypeCode": "dcsa.tnt.equipment_event_type",
        "transportEventTypeCode": "dcsa.tnt.transport_event_type",
        "documentTypeCode": "dcsa.tnt.document_type",
    }

    for schema_name, namespace in mappings.items():
        imported = importer.import_schema_enum(
            EVENT_DOMAIN,
            schema_name=schema_name,
            namespace=namespace,
            source_version="2.3.0",
        )
        assert {record.code for record in imported} == {
            record.code for record in catalog.list(namespace)
        }
