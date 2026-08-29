import pytest

from cargomesh.ir import IR_SCHEMA_VERSION
from cargomesh.mapping import (
    DCSA_TNT_QUERY_VERSION,
    DCSATNTV2Mapper,
    MappingKey,
    MappingNotFoundError,
    MappingRegistry,
    default_mapping_registry,
)


def test_default_registry_resolves_only_explicit_version_and_capability() -> None:
    registry = default_mapping_registry()
    supported = MappingKey(
        DCSA_TNT_QUERY_VERSION,
        IR_SCHEMA_VERSION,
        "shipment.track.read",
    )

    assert isinstance(registry.resolve(supported), DCSATNTV2Mapper)
    with pytest.raises(MappingNotFoundError):
        registry.resolve(
            MappingKey(DCSA_TNT_QUERY_VERSION, IR_SCHEMA_VERSION, "booking.submit")
        )


def test_registry_rejects_ambiguous_duplicate_registration() -> None:
    registry = MappingRegistry()
    key = MappingKey("source/v1", "target/v1", "shipment.track.read")
    registry.register(key, object)

    with pytest.raises(ValueError, match="already registered"):
        registry.register(key, object)
