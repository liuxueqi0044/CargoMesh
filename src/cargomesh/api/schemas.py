"""Pydantic request models for the contract API."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator


class CompileRequest(BaseModel):
    """An explicit, fail-closed compilation request.

    Public contract endpoints do not infer a source format from business data.
    That avoids a future DCSA field addition silently selecting the wrong mapper.
    """

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    source_schema_version: str = Field(alias="sourceSchemaVersion")
    payload: dict[str, Any]
    context: dict[str, Any] | None = None


class ApprovalRequest(BaseModel):
    """Explicit approval/rejection decision at a runtime approval boundary."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    step_id: str = Field(min_length=1, max_length=128)
    approved: bool
    decided_by: str = Field(min_length=1, max_length=256)
    reason: str | None = Field(default=None, max_length=1000)

    @model_validator(mode="after")
    def require_rejection_reason(self) -> ApprovalRequest:
        if not self.approved and not self.reason:
            raise ValueError("a rejected approval requires a reason")
        return self
