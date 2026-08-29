"""CargoMesh Board 1 contract-facing FastAPI application."""

from __future__ import annotations

import re
import uuid
from typing import Any, cast

from fastapi import Depends, FastAPI, Query, Request
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.responses import Response

from cargomesh.api.dependencies import get_compile_service, get_reference_data_service
from cargomesh.api.errors import (
    compilation_error_handler,
    http_error_handler,
    request_validation_error_handler,
    unhandled_error_handler,
)
from cargomesh.api.schemas import CompileRequest
from cargomesh.application.compile import CompilationError, CompileService, jsonable
from cargomesh.application.reference_data import (
    ReferenceDataService,
)
from cargomesh.standards import default_reference_data_catalog

_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")


def create_app(
    *,
    compile_service: CompileService | None = None,
    reference_data_provider: Any | None = None,
) -> FastAPI:
    application = FastAPI(title="CargoMesh API", version="0.1.0")
    application.state.compile_service = compile_service or CompileService()
    application.state.reference_data_service = ReferenceDataService(
        reference_data_provider
        if reference_data_provider is not None
        else default_reference_data_catalog()
    )

    application.add_exception_handler(CompilationError, cast(Any, compilation_error_handler))
    application.add_exception_handler(
        RequestValidationError, cast(Any, request_validation_error_handler)
    )
    application.add_exception_handler(Exception, unhandled_error_handler)
    application.add_exception_handler(StarletteHTTPException, cast(Any, http_error_handler))

    @application.middleware("http")
    async def request_id_middleware(request: Request, call_next: Any) -> Response:
        incoming = request.headers.get("X-Request-ID", "")
        request_id = incoming if _REQUEST_ID_RE.fullmatch(incoming) else str(uuid.uuid4())
        request.state.request_id = request_id
        response = cast(Response, await call_next(request))
        response.headers["X-Request-ID"] = request_id
        return response

    @application.get("/healthz")
    async def healthz(request: Request) -> dict[str, str]:
        del request
        return {"status": "ok"}

    @application.get("/v1/contracts/transaction-ir/schema")
    async def transaction_ir_schema() -> dict[str, Any]:
        from cargomesh.ir import TransactionCommand

        return TransactionCommand.model_json_schema()

    @application.post("/v1/ir/compile")
    async def compile_ir(
        request: CompileRequest,
        service: CompileService = Depends(get_compile_service),  # noqa: B008
    ) -> dict[str, Any]:
        result = service.compile(
            request.source_schema_version,
            request.payload,
            context=request.context,
        )
        return {
            "transaction_ir": jsonable(result.command),
            "canonical_business_json": result.canonical_json,
            "business_digest": result.digest,
            "mapping_diagnostics": jsonable(result.diagnostics),
            "source_schema_version": result.source_schema_version,
            "target_schema_version": result.target_schema_version,
        }

    @application.get("/v1/contracts/dcsa-tnt-query-v2.3/schema")
    async def dcsa_tnt_query_schema() -> dict[str, Any]:
        from cargomesh.mapping import DCSATNTQueryV2

        return DCSATNTQueryV2.model_json_schema(by_alias=True)

    @application.get("/v1/capabilities")
    async def capabilities() -> dict[str, Any]:
        from cargomesh.mapping import default_mapping_registry

        return {
            "capabilities": [
                {
                    "name": key.capability,
                    "source_schema_version": key.source_schema_version,
                    "target_schema_version": key.target_schema_version,
                }
                for key in default_mapping_registry().supported()
            ]
        }

    @application.get("/v1/reference-data/{namespace:path}")
    async def reference_data(
        namespace: str,
        as_of: str | None = Query(default=None),
        at: str | None = Query(default=None),
        service: ReferenceDataService = Depends(get_reference_data_service),  # noqa: B008
    ) -> Any:
        requested_date = as_of or at
        try:
            return jsonable(service.get_namespace(namespace, as_of=requested_date))
        except KeyError as exc:
            raise CompilationError(
                "reference_data_not_found", "Reference-data namespace was not found"
            ) from exc
        except CompilationError:
            raise
        except Exception as exc:
            raise CompilationError(
                "reference_data_unavailable", "Reference data is unavailable"
            ) from exc

    return application


app = create_app()


def run() -> None:
    import uvicorn

    uvicorn.run("cargomesh.api.main:app", host="127.0.0.1", port=8000, reload=False)
