"""CargoMesh contract compiler and durable transaction FastAPI application."""

from __future__ import annotations

import re
import uuid
from typing import Any, cast

from fastapi import Depends, FastAPI, Header, Query, Request
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.responses import JSONResponse, Response

from cargomesh import __version__
from cargomesh.api.dependencies import (
    TransactionServiceProtocol,
    get_access_controller,
    get_compile_service,
    get_reference_data_service,
    get_transaction_service,
)
from cargomesh.api.errors import (
    compilation_error_handler,
    http_error_handler,
    request_validation_error_handler,
    unhandled_error_handler,
)
from cargomesh.api.schemas import ApprovalRequest, CompileRequest
from cargomesh.application.compile import CompilationError, CompileService, jsonable
from cargomesh.application.reference_data import (
    ReferenceDataService,
)
from cargomesh.controlplane import AccessAction, Principal
from cargomesh.controlplane.access import AccessControlError, AccessController, AccessGrant
from cargomesh.standards import default_reference_data_catalog

_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_IDEMPOTENCY_KEY_RE = re.compile(r"^[^\x00-\x20\x7f]{1,256}$")
_SAFE_ERROR_CODE_RE = re.compile(r"^[a-z][a-z0-9_:-]{1,63}$")
_UNSAFE_ERROR_MARKERS = ("traceback", "temporal", "sqlite", "password", "c:\\", "/home/")


def _runtime_error_response(request: Request, exc: Exception) -> JSONResponse:
    """Turn a service failure into a bounded, transport-safe error envelope."""

    raw_code = getattr(exc, "code", "runtime_error")
    code = (
        raw_code
        if isinstance(raw_code, str) and _SAFE_ERROR_CODE_RE.fullmatch(raw_code)
        else "runtime_error"
    )
    raw_message = getattr(exc, "message", "Runtime operation failed")
    message = (
        raw_message
        if isinstance(raw_message, str) and raw_message.strip()
        else "Runtime operation failed"
    )
    lowered = message.casefold()
    if len(message) > 500 or any(marker in lowered for marker in _UNSAFE_ERROR_MARKERS):
        message = "Runtime operation failed"
    raw_status = getattr(exc, "status_code", 500)
    status_code = raw_status if isinstance(raw_status, int) and 400 <= raw_status <= 599 else 500
    request_id = getattr(request.state, "request_id", "unknown")
    headers = {"X-Request-ID": request_id}
    if bool(getattr(exc, "authenticate_header", False)):
        headers["WWW-Authenticate"] = "Bearer"
    return JSONResponse(
        status_code=status_code,
        content={"error": {"code": code, "message": message, "request_id": request_id}},
        headers=headers,
    )


class _RequestError(Exception):
    def __init__(self, code: str, message: str, status_code: int) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code


def _runtime_unavailable(request: Request) -> JSONResponse:
    class RuntimeUnavailable(Exception):
        code = "runtime_unavailable"
        message = "Transaction runtime is unavailable"
        status_code = 503

    return _runtime_error_response(request, RuntimeUnavailable())


def _submission_was_replayed(value: Any) -> bool:
    if isinstance(value, dict):
        if "created" in value:
            return not bool(value["created"])
        return bool(
            value.get(
                "replayed",
                value.get("idempotent_replay", value.get("idempotency_replayed", False)),
            )
        )
    if hasattr(value, "created"):
        return not bool(value.created)
    return bool(
        getattr(
            value,
            "replayed",
            getattr(value, "idempotent_replay", getattr(value, "idempotency_replayed", False)),
        )
    )


async def _authenticate_request(
    request: Request, controller: AccessController | None
) -> Principal | None:
    if controller is None:
        return None
    return await controller.authenticate(request.headers.get("Authorization"))


def _resource_tenant_id(value: Any) -> str:
    candidate = (
        value.get("tenant_id")
        if isinstance(value, dict)
        else getattr(value, "tenant_id", None)
    )
    if not isinstance(candidate, str) or not candidate or candidate != candidate.strip():
        raise AccessControlError(
            "resource_scope_unavailable",
            "Resource authorization scope is unavailable",
            status_code=503,
        )
    return candidate


def _require_access(
    request: Request,
    controller: AccessController | None,
    principal: Principal | None,
    *,
    action: AccessAction,
    tenant_id: str,
    resource_id: str | None,
) -> AccessGrant | None:
    if controller is None:
        return None
    if principal is None:
        raise AccessControlError(
            "authentication_required",
            "Bearer authentication is required",
            status_code=401,
            authenticate_header=True,
        )
    return controller.require(
        principal,
        action=action,
        tenant_id=tenant_id,
        resource_type="transaction",
        resource_id=resource_id,
        request_id=getattr(request.state, "request_id", "unknown"),
    )


def _record_access_outcome(
    controller: AccessController | None,
    grant: AccessGrant | None,
    *,
    succeeded: bool,
    reason_code: str,
    details: dict[str, str | int | bool | None] | None = None,
) -> None:
    if controller is not None and grant is not None:
        controller.record_outcome(
            grant,
            succeeded=succeeded,
            reason_code=reason_code,
            details=details,
        )


def _bounded_runtime_reason(exc: Exception) -> str:
    raw_code = getattr(exc, "code", "runtime_error")
    if isinstance(raw_code, str) and _SAFE_ERROR_CODE_RE.fullmatch(raw_code):
        return raw_code
    return "runtime_error"


def create_app(
    *,
    compile_service: CompileService | None = None,
    reference_data_provider: Any | None = None,
    transaction_service: TransactionServiceProtocol | None = None,
    access_controller: AccessController | None = None,
) -> FastAPI:
    application = FastAPI(title="CargoMesh API", version=__version__)
    application.state.compile_service = compile_service or CompileService()
    application.state.transaction_service = transaction_service
    application.state.access_controller = access_controller
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

    @application.post("/v1/transactions")
    async def create_transaction(
        request: Request,
        body: CompileRequest,
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
        compiler: CompileService = Depends(get_compile_service),  # noqa: B008
        service: TransactionServiceProtocol | None = Depends(get_transaction_service),  # noqa: B008
        controller: AccessController | None = Depends(get_access_controller),  # noqa: B008
    ) -> Response:
        try:
            principal = await _authenticate_request(request, controller)
        except AccessControlError as exc:
            return _runtime_error_response(request, exc)
        if idempotency_key is None:
            return _runtime_error_response(
                request,
                _RequestError(
                    "missing_idempotency_key",
                    "Idempotency-Key header is required",
                    400,
                ),
            )
        if _IDEMPOTENCY_KEY_RE.fullmatch(idempotency_key) is None:
            return _runtime_error_response(
                request,
                _RequestError(
                    "invalid_idempotency_key",
                    "Idempotency-Key header is invalid",
                    400,
                ),
            )
        grant: AccessGrant | None = None
        try:
            compilation = compiler.compile(
                body.source_schema_version,
                body.payload,
                context=body.context,
            )
            if controller is not None:
                tenant_id = _resource_tenant_id(compilation.command)
                grant = _require_access(
                    request,
                    controller,
                    principal,
                    action=AccessAction.TRANSACTION_CREATE,
                    tenant_id=tenant_id,
                    resource_id=None,
                )
            if service is None:
                _record_access_outcome(
                    controller,
                    grant,
                    succeeded=False,
                    reason_code="runtime_unavailable",
                )
                return _runtime_unavailable(request)
            result = await service.submit(compilation, idempotency_key)
        except CompilationError:
            raise
        except AccessControlError as exc:
            return _runtime_error_response(request, exc)
        except Exception as exc:
            try:
                _record_access_outcome(
                    controller,
                    grant,
                    succeeded=False,
                    reason_code=_bounded_runtime_reason(exc),
                )
            except AccessControlError as audit_exc:
                return _runtime_error_response(request, audit_exc)
            return _runtime_error_response(request, exc)
        status_code = 200 if _submission_was_replayed(result) else 202
        try:
            _record_access_outcome(
                controller,
                grant,
                succeeded=True,
                reason_code=(
                    "transaction_replayed" if status_code == 200 else "transaction_created"
                ),
                details={"replayed": status_code == 200},
            )
        except AccessControlError as exc:
            return _runtime_error_response(request, exc)
        return JSONResponse(status_code=status_code, content=jsonable(result))

    @application.get("/v1/transactions/{transaction_id}")
    async def get_transaction(
        request: Request,
        transaction_id: str,
        service: TransactionServiceProtocol | None = Depends(get_transaction_service),  # noqa: B008
        controller: AccessController | None = Depends(get_access_controller),  # noqa: B008
    ) -> Response:
        try:
            principal = await _authenticate_request(request, controller)
        except AccessControlError as exc:
            return _runtime_error_response(request, exc)
        if service is None:
            return _runtime_unavailable(request)
        try:
            result = await service.get(transaction_id)
            grant = None
            if controller is not None:
                grant = _require_access(
                    request,
                    controller,
                    principal,
                    action=AccessAction.TRANSACTION_READ,
                    tenant_id=_resource_tenant_id(result),
                    resource_id=transaction_id,
                )
            _record_access_outcome(
                controller,
                grant,
                succeeded=True,
                reason_code="transaction_read",
            )
        except AccessControlError as exc:
            return _runtime_error_response(request, exc)
        except Exception as exc:
            return _runtime_error_response(request, exc)
        return JSONResponse(status_code=200, content=jsonable(result))

    @application.post("/v1/transactions/{transaction_id}/approval")
    async def approve_transaction(
        request: Request,
        transaction_id: str,
        decision: ApprovalRequest,
        service: TransactionServiceProtocol | None = Depends(get_transaction_service),  # noqa: B008
        controller: AccessController | None = Depends(get_access_controller),  # noqa: B008
    ) -> Response:
        try:
            principal = await _authenticate_request(request, controller)
        except AccessControlError as exc:
            return _runtime_error_response(request, exc)
        if service is None:
            return _runtime_unavailable(request)
        grant: AccessGrant | None = None
        try:
            if controller is not None:
                existing = await service.get(transaction_id)
                grant = _require_access(
                    request,
                    controller,
                    principal,
                    action=AccessAction.TRANSACTION_APPROVE,
                    tenant_id=_resource_tenant_id(existing),
                    resource_id=transaction_id,
                )
                if principal is None:
                    raise AccessControlError(
                        "authentication_required",
                        "Bearer authentication is required",
                        status_code=401,
                        authenticate_header=True,
                    )
                decision = decision.model_copy(update={"decided_by": principal.subject})
            result = await service.approve(transaction_id, decision)
            _record_access_outcome(
                controller,
                grant,
                succeeded=True,
                reason_code="approval_delivered",
                details={"approved": decision.approved},
            )
        except AccessControlError as exc:
            return _runtime_error_response(request, exc)
        except Exception as exc:
            try:
                _record_access_outcome(
                    controller,
                    grant,
                    succeeded=False,
                    reason_code=_bounded_runtime_reason(exc),
                )
            except AccessControlError as audit_exc:
                return _runtime_error_response(request, audit_exc)
            return _runtime_error_response(request, exc)
        return JSONResponse(status_code=200, content=jsonable(result))

    @application.post("/v1/transactions/{transaction_id}/cancel")
    async def cancel_transaction(
        request: Request,
        transaction_id: str,
        service: TransactionServiceProtocol | None = Depends(get_transaction_service),  # noqa: B008
        controller: AccessController | None = Depends(get_access_controller),  # noqa: B008
    ) -> Response:
        try:
            principal = await _authenticate_request(request, controller)
        except AccessControlError as exc:
            return _runtime_error_response(request, exc)
        if service is None:
            return _runtime_unavailable(request)
        grant: AccessGrant | None = None
        try:
            if controller is not None:
                existing = await service.get(transaction_id)
                grant = _require_access(
                    request,
                    controller,
                    principal,
                    action=AccessAction.TRANSACTION_CANCEL,
                    tenant_id=_resource_tenant_id(existing),
                    resource_id=transaction_id,
                )
            result = await service.cancel(transaction_id)
            _record_access_outcome(
                controller,
                grant,
                succeeded=True,
                reason_code="cancellation_delivered",
            )
        except AccessControlError as exc:
            return _runtime_error_response(request, exc)
        except Exception as exc:
            try:
                _record_access_outcome(
                    controller,
                    grant,
                    succeeded=False,
                    reason_code=_bounded_runtime_reason(exc),
                )
            except AccessControlError as audit_exc:
                return _runtime_error_response(request, audit_exc)
            return _runtime_error_response(request, exc)
        return JSONResponse(status_code=200, content=jsonable(result))

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
