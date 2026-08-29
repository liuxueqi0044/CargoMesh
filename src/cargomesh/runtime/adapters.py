"""Worker-side adapter registry and the generic Temporal activity boundary."""

from __future__ import annotations

from typing import Protocol

from pydantic import JsonValue
from temporalio import activity
from temporalio.exceptions import ApplicationError

from .models import AdapterInvocation, AdapterResult

EXECUTE_ADAPTER_ACTIVITY = "cargomesh.execute-adapter"


class AdapterExecutor(Protocol):
    async def execute(self, invocation: AdapterInvocation) -> AdapterResult: ...


class AdapterExecutionError(RuntimeError):
    """Safe adapter failure that can cross the activity boundary."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        retryable: bool,
        diagnostics: dict[str, JsonValue] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.retryable = retryable
        self.diagnostics = diagnostics or {}


class AdapterRegistry:
    """Boot-time registry. It is accessed only from activities, never workflows."""

    def __init__(self) -> None:
        self._executors: dict[str, AdapterExecutor] = {}

    def register(self, name: str, executor: AdapterExecutor) -> None:
        if name in self._executors:
            raise ValueError(f"adapter {name} is already registered")
        self._executors[name] = executor

    async def invoke(self, invocation: AdapterInvocation) -> AdapterResult:
        try:
            executor = self._executors[invocation.adapter]
        except KeyError as exc:
            raise AdapterExecutionError(
                "adapter_not_found", "Requested adapter is not registered", retryable=False
            ) from exc
        try:
            result = await executor.execute(invocation)
        except AdapterExecutionError:
            raise
        except Exception as exc:
            raise AdapterExecutionError(
                "adapter_internal", "Adapter failed without a safe diagnostic", retryable=False
            ) from exc
        if not isinstance(result, AdapterResult):
            raise AdapterExecutionError(
                "invalid_adapter_result", "Adapter returned an invalid result", retryable=False
            )
        return result


class AdapterActivities:
    def __init__(self, registry: AdapterRegistry) -> None:
        self._registry = registry

    @activity.defn(name=EXECUTE_ADAPTER_ACTIVITY)
    async def execute(self, invocation: AdapterInvocation) -> AdapterResult:
        try:
            return await self._registry.invoke(invocation)
        except AdapterExecutionError as exc:
            details = (exc.diagnostics,) if exc.diagnostics else ()
            raise ApplicationError(
                exc.message,
                *details,
                type=exc.code,
                non_retryable=not exc.retryable,
            ) from exc


class SyntheticTrackingAdapter:
    """Offline demonstration adapter; it does not represent a carrier result."""

    async def execute(self, invocation: AdapterInvocation) -> AdapterResult:
        if invocation.operation != "fetch":
            raise AdapterExecutionError(
                "operation_not_supported",
                "Synthetic adapter supports only the fetch operation",
                retryable=False,
            )
        return AdapterResult(
            output={
                "synthetic": True,
                "events": [],
                "notice": "No carrier transaction was executed",
            }
        )
