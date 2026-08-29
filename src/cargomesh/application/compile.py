"""Compile source contract payloads into CargoMesh Transaction IR.

This module deliberately talks to the public interfaces of ``cargomesh.ir`` and
``cargomesh.mapping`` only.  Imports are resolved lazily so the application
package can be imported while an integration is assembling those packages (and
so tests can supply small fakes).
"""

from __future__ import annotations

from dataclasses import asdict, is_dataclass
from typing import Any, Protocol, cast

IR_SCHEMA_VERSION = "cargomesh.transaction/v1"
TNT_SCHEMA_VERSION = "dcsa.tnt.query/v2.3"
SUPPORTED_SOURCE_VERSIONS = frozenset({IR_SCHEMA_VERSION, TNT_SCHEMA_VERSION})


class CompilationError(ValueError):
    """A safe, expected failure while validating or mapping a source payload."""

    def __init__(self, code: str, message: str, *, diagnostics: list[Any] | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.diagnostics = diagnostics or []


class MapperProtocol(Protocol):
    """Public mapper shape used by :class:`CompileService`."""

    def to_ir(self, query: Any, context: Any = None) -> Any: ...


class MapperRegistryProtocol(Protocol):
    def resolve(self, key: Any) -> Any: ...


class CompilationResult:
    """Transport-neutral result returned by the compile application service."""

    def __init__(
        self,
        *,
        command: Any,
        canonical_json: str,
        digest: str,
        diagnostics: list[Any],
        source_schema_version: str,
    ) -> None:
        self.command = command
        self.canonical_json = canonical_json
        self.digest = digest
        self.diagnostics = diagnostics
        self.source_schema_version = source_schema_version
        self.target_schema_version = IR_SCHEMA_VERSION


class CompileService:
    """Validate and normalize an IR or DCSA TNT query without executing it.

    ``mapper`` is injectable primarily for offline tests and for keeping the API
    independent from mapping implementation details.  The default mapper is
    constructed from the public ``DCSATNTV2Mapper`` interface at call time.
    """

    def __init__(
        self,
        mapper: MapperProtocol | None = None,
        registry: MapperRegistryProtocol | None = None,
    ) -> None:
        self._mapper = mapper
        self._registry = registry

    def compile(
        self,
        source_schema_version: str,
        payload: Any,
        *,
        context: Any = None,
    ) -> CompilationResult:
        if source_schema_version not in SUPPORTED_SOURCE_VERSIONS:
            raise CompilationError(
                "unsupported_source_schema",
                f"Unsupported source schema version: {source_schema_version}",
            )

        try:
            if source_schema_version == IR_SCHEMA_VERSION:
                command = self._validate_ir(payload)
                diagnostics: list[Any] = []
            else:
                command, diagnostics = self._map_tnt(payload, context)
        except CompilationError:
            raise
        except Exception as exc:
            # Do not allow implementation exception text (which may contain
            # paths, SQL, or tracebacks) to cross the application boundary.
            raise CompilationError("invalid_source", "Source payload failed validation") from exc

        canonical_json, digest = self._canonicalize(command)
        return CompilationResult(
            command=command,
            canonical_json=canonical_json,
            digest=digest,
            diagnostics=diagnostics,
            source_schema_version=source_schema_version,
        )

    @staticmethod
    def _validate_ir(payload: Any) -> Any:
        if not isinstance(payload, dict):
            raise CompilationError("invalid_payload", "Source payload must be a JSON object")
        from cargomesh.ir import TransactionCommand

        try:
            return TransactionCommand.model_validate(payload)
        except Exception as exc:
            raise CompilationError(
                "invalid_ir", "Payload is not valid CargoMesh Transaction IR"
            ) from exc

    def _map_tnt(self, payload: Any, context: Any) -> tuple[Any, list[Any]]:
        if not isinstance(payload, dict):
            raise CompilationError("invalid_payload", "Source payload must be a JSON object")
        from cargomesh.mapping import (
            DCSATNTQueryV2,
            MappingContext,
            MappingError,
            MappingKey,
            default_mapping_registry,
        )

        try:
            query = DCSATNTQueryV2.model_validate(payload)
        except Exception as exc:
            raise CompilationError(
                "invalid_tnt_query", "Payload is not a valid DCSA TNT 2.3 query"
            ) from exc

        if self._mapper is not None:
            mapper = self._mapper
        else:
            registry = self._registry or default_mapping_registry()
            mapper = cast(
                MapperProtocol,
                registry.resolve(
                    MappingKey(TNT_SCHEMA_VERSION, IR_SCHEMA_VERSION, "shipment.track.read")
                ),
            )
        if context is None:
            raise CompilationError(
                "missing_mapping_context",
                "DCSA TNT compilation requires tenant context",
            )
        if isinstance(context, dict):
            try:
                context = MappingContext.model_validate(context)
            except Exception as exc:
                raise CompilationError(
                    "invalid_mapping_context",
                    "DCSA TNT compilation context is invalid",
                ) from exc
        try:
            mapped = mapper.to_ir(query, context)
        except MappingError as exc:
            raise CompilationError(
                "mapping_rejected",
                "DCSA TNT query contains unsupported or partial required mappings",
                diagnostics=list(exc.diagnostics),
            ) from exc
        except Exception as exc:
            # MappingError is intentionally normalized along with validation
            # failures; its details are represented by diagnostics when the
            # mapper returns them, not by leaking exception internals.
            raise CompilationError(
                "mapping_failed",
                "DCSA TNT query could not be mapped to Transaction IR",
            ) from exc

        command = _first_attr(mapped, "value", "command", "result")
        if command is None:
            raise CompilationError("mapping_failed", "Mapper returned no Transaction IR command")
        diagnostics = _first_attr(mapped, "diagnostics") or []
        diagnostics_list = list(diagnostics) if not isinstance(diagnostics, list) else diagnostics
        if _has_critical_mapping_diagnostic(diagnostics_list):
            raise CompilationError(
                "mapping_rejected",
                "DCSA TNT query contains unsupported or partial required mappings",
                diagnostics=diagnostics_list,
            )
        return command, diagnostics_list

    @staticmethod
    def _canonicalize(command: Any) -> tuple[str, str]:
        from cargomesh.ir import business_digest, canonical_business_json

        try:
            canonical = canonical_business_json(command)
            digest = business_digest(command)
        except Exception as exc:
            raise CompilationError(
                "canonicalization_failed", "Transaction IR could not be canonicalized"
            ) from exc
        if not isinstance(canonical, str) or not isinstance(digest, str):
            raise CompilationError(
                "canonicalization_failed",
                "Transaction IR canonicalization returned invalid data",
            )
        return canonical, digest


def _first_attr(value: Any, *names: str) -> Any:
    for name in names:
        if hasattr(value, name):
            return getattr(value, name)
    return None


def _has_critical_mapping_diagnostic(diagnostics: list[Any]) -> bool:
    for diagnostic in diagnostics:
        fidelity = _first_attr(diagnostic, "fidelity")
        if fidelity is None and isinstance(diagnostic, dict):
            fidelity = diagnostic.get("fidelity")
        fidelity_text = getattr(fidelity, "value", fidelity)
        if str(fidelity_text).upper() in {"PARTIAL", "UNSUPPORTED"}:
            blocking = _first_attr(diagnostic, "blocking", "critical")
            if blocking is None and isinstance(diagnostic, dict):
                blocking = diagnostic.get("blocking", diagnostic.get("critical", True))
            if blocking is not False:
                return True
    return False


def jsonable(value: Any) -> Any:
    """Convert public model/dataclass diagnostics and IR into JSON-safe values."""

    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json", by_alias=True, exclude_none=True)
    if is_dataclass(value):
        return asdict(value)  # type: ignore[arg-type]
    if isinstance(value, dict):
        return {str(key): jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [jsonable(item) for item in value]
    if hasattr(value, "value") and not isinstance(value, (str, bytes)):
        return value.value
    return value
