"""Pydantic request models for the contract API."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class CompileRequest(BaseModel):
    """An explicit, fail-closed compilation request.

    Public contract endpoints do not infer a source format from business data.
    That avoids a future DCSA field addition silently selecting the wrong mapper.
    """

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    source_schema_version: str = Field(alias="sourceSchemaVersion")
    payload: dict[str, Any]
    context: dict[str, Any] | None = None
