"""Stable error envelopes for the CargoMesh API."""

from __future__ import annotations

from fastapi import Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from cargomesh.application.compile import CompilationError, jsonable


def error_response(request: Request, code: str, message: str, status_code: int) -> JSONResponse:
    request_id = getattr(request.state, "request_id", "unknown")
    return JSONResponse(
        status_code=status_code,
        content={"error": {"code": code, "message": message, "request_id": request_id}},
        headers={"X-Request-ID": request_id},
    )


async def compilation_error_handler(request: Request, exc: CompilationError) -> JSONResponse:
    status = 400 if exc.code == "unsupported_source_schema" else 422
    content = {
        "error": {
            "code": exc.code,
            "message": exc.message,
            "request_id": getattr(request.state, "request_id", "unknown"),
        }
    }
    if exc.diagnostics:
        content["error"]["diagnostics"] = jsonable(exc.diagnostics)
    return JSONResponse(
        status_code=status,
        content=content,
        headers={"X-Request-ID": getattr(request.state, "request_id", "unknown")},
    )


async def request_validation_error_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    del exc
    return error_response(request, "invalid_request", "Request validation failed", 422)


async def http_error_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
    status = exc.status_code
    message = "Request failed" if status >= 500 else str(exc.detail)
    return error_response(request, "http_error", message, status)


async def unhandled_error_handler(request: Request, exc: Exception) -> JSONResponse:
    del exc
    return error_response(request, "internal_error", "Internal server error", 500)
