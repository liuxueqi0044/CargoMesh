"""Version-aware registry for independently deployable contract mappers."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any


class MappingNotFoundError(LookupError):
    """Raised when no explicitly registered conversion exists."""


@dataclass(frozen=True, slots=True, order=True)
class MappingKey:
    source_schema_version: str
    target_schema_version: str
    capability: str


MapperFactory = Callable[[], Any]


class MappingRegistry:
    """Fail-closed mapper registry keyed by both versions and capability."""

    def __init__(self) -> None:
        self._factories: dict[MappingKey, MapperFactory] = {}

    def register(self, key: MappingKey, factory: MapperFactory) -> None:
        if key in self._factories:
            raise ValueError(f"mapper already registered: {key!r}")
        self._factories[key] = factory

    def resolve(self, key: MappingKey) -> Any:
        try:
            factory = self._factories[key]
        except KeyError as exc:
            raise MappingNotFoundError(f"no mapper registered for {key!r}") from exc
        return factory()

    def supported(self) -> tuple[MappingKey, ...]:
        return tuple(sorted(self._factories))


def default_mapping_registry() -> MappingRegistry:
    """Build the production mapping registry without module-level mutable state."""

    from cargomesh.ir import IR_SCHEMA_VERSION

    from .dcsa_tnt_v2 import DCSA_TNT_QUERY_VERSION, DCSATNTV2Mapper

    registry = MappingRegistry()
    registry.register(
        MappingKey(DCSA_TNT_QUERY_VERSION, IR_SCHEMA_VERSION, "shipment.track.read"),
        DCSATNTV2Mapper,
    )
    return registry
