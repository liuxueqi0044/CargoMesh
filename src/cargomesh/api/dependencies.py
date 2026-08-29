"""FastAPI dependency accessors, kept override-friendly for offline tests."""

from __future__ import annotations

from typing import Any, Protocol, cast

from fastapi import Request

from cargomesh.application.compile import CompilationResult, CompileService
from cargomesh.application.reference_data import ReferenceDataService


class TransactionServiceProtocol(Protocol):
    """Async runtime boundary used by the transaction HTTP transport.

    The API deliberately knows nothing about Temporal, SQLite, or workflow
    objects.  A service receives the already compiled result and returns a
    JSON-serializable snapshot or submission record.
    """

    async def submit(self, compilation: CompilationResult, idempotency_key: str) -> Any: ...

    async def get(self, transaction_id: str) -> Any: ...

    async def approve(self, transaction_id: str, decision: Any) -> Any: ...

    async def cancel(self, transaction_id: str) -> Any: ...


def get_compile_service(request: Request) -> CompileService:
    return cast(CompileService, request.app.state.compile_service)


def get_reference_data_service(request: Request) -> ReferenceDataService:
    return cast(ReferenceDataService, request.app.state.reference_data_service)


def get_transaction_service(request: Request) -> TransactionServiceProtocol | None:
    return cast(TransactionServiceProtocol | None, request.app.state.transaction_service)
