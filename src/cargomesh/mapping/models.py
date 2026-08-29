"""Mapping diagnostics shared by industry-contract mappers."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict


class MappingFidelity(StrEnum):
    EXACT = "EXACT"
    NORMALIZED = "NORMALIZED"
    DEFAULTED = "DEFAULTED"
    PARTIAL = "PARTIAL"
    UNSUPPORTED = "UNSUPPORTED"


class MappingDiagnostic(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    source_path: str
    target_path: str | None = None
    fidelity: MappingFidelity
    code: str
    message: str
    blocking: bool = False


class MappingResult[MappedT](BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, arbitrary_types_allowed=True)

    value: MappedT
    source_schema_version: str
    target_schema_version: str
    diagnostics: tuple[MappingDiagnostic, ...] = ()

    @property
    def has_blocking_diagnostics(self) -> bool:
        return any(item.blocking for item in self.diagnostics)

    def require_supported(self) -> MappedT:
        if self.has_blocking_diagnostics:
            raise MappingError(self.diagnostics)
        return self.value


class MappingError(ValueError):
    """Raised when a mapping would silently lose critical business meaning."""

    def __init__(self, diagnostics: tuple[MappingDiagnostic, ...]) -> None:
        self.diagnostics = diagnostics
        codes = ", ".join(item.code for item in diagnostics if item.blocking)
        super().__init__(f"mapping has blocking diagnostics: {codes}")
