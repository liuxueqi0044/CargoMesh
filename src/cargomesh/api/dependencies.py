"""FastAPI dependency accessors, kept override-friendly for offline tests."""

from __future__ import annotations

from typing import cast

from fastapi import Request

from cargomesh.application.compile import CompileService
from cargomesh.application.reference_data import ReferenceDataService


def get_compile_service(request: Request) -> CompileService:
    return cast(CompileService, request.app.state.compile_service)


def get_reference_data_service(request: Request) -> ReferenceDataService:
    return cast(ReferenceDataService, request.app.state.reference_data_service)
