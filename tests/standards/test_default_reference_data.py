from cargomesh.standards import default_reference_data_catalog


def test_packaged_tnt_event_types_are_available() -> None:
    catalog = default_reference_data_catalog()

    shipment = catalog.get("dcsa.tnt.event_type", "SHIPMENT")
    assert shipment is not None
    assert shipment.name == "Shipment event"
    assert [item.code for item in catalog.suggest("dcsa.tnt.event_type", "equipment")] == [
        "EQUIPMENT"
    ]
    issued = catalog.get("dcsa.tnt.shipment_event_type", "ISSU")
    gated_in = catalog.get("dcsa.tnt.equipment_event_type", "GTIN")
    assert issued is not None and issued.name == "Issued"
    assert gated_in is not None and gated_in.status == "active"
