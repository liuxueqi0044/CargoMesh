"""Worker-side adapter registry and the generic Temporal activity boundary."""

from __future__ import annotations

import hashlib
import time
from collections.abc import Awaitable, Callable, Mapping
from datetime import UTC, datetime
from typing import Protocol

from pydantic import JsonValue
from temporalio import activity
from temporalio.exceptions import ApplicationError

from cargomesh.credentials import (
    CredentialBindingStore,
    ResolveContext,
    SecretLease,
    SecretProvider,
)
from cargomesh.routing.models import RouteOutcome, RouteOutcomeKind
from cargomesh.routing.store import RouteOutcomeStore

from .models import AdapterInvocation, AdapterResult

EXECUTE_ADAPTER_ACTIVITY = "cargomesh.execute-adapter"


class AdapterExecutor(Protocol):
    async def execute(self, invocation: AdapterInvocation) -> AdapterResult: ...


class CredentialAwareAdapterExecutor(Protocol):
    async def execute_with_credentials(
        self, invocation: AdapterInvocation, credentials: CredentialLeaseSet
    ) -> AdapterResult: ...


class CredentialLeaseSet:
    """Non-serializable, short-lived credential leases exposed to one adapter call."""

    __slots__ = ("_closed", "_leases")

    def __init__(self, leases: Mapping[str, SecretLease]) -> None:
        if not leases:
            raise ValueError("credential lease set must not be empty")
        self._leases = dict(leases)
        self._closed = False

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(sorted(self._leases))

    def read(self, name: str) -> bytes:
        if self._closed:
            raise AdapterExecutionError(
                "credential_lease_closed", "Credential lease is closed", retryable=False
            )
        try:
            return self._leases[name].read()
        except KeyError as exc:
            raise AdapterExecutionError(
                "credential_name_unavailable",
                "Requested credential is unavailable",
                retryable=False,
            ) from exc

    def __getitem__(self, name: str) -> bytes:
        return self.read(name)

    def close(self) -> None:
        if self._closed:
            return
        for lease in self._leases.values():
            lease.close()
        self._closed = True

    def __enter__(self) -> CredentialLeaseSet:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def __repr__(self) -> str:
        return f"<CredentialLeaseSet names={len(self._leases)} closed={self._closed}>"


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
        self._credential_executors: dict[str, CredentialAwareAdapterExecutor] = {}

    def register(self, name: str, executor: AdapterExecutor) -> None:
        if name in self._executors or name in self._credential_executors:
            raise ValueError(f"adapter {name} is already registered")
        self._executors[name] = executor

    def register_credential_aware(
        self, name: str, executor: CredentialAwareAdapterExecutor
    ) -> None:
        if name in self._executors or name in self._credential_executors:
            raise ValueError(f"adapter {name} is already registered")
        self._credential_executors[name] = executor

    async def invoke(self, invocation: AdapterInvocation) -> AdapterResult:
        if invocation.credential_binding_digest is not None:
            raise AdapterExecutionError(
                "credential_boundary_required",
                "Adapter invocation requires the credential boundary",
                retryable=False,
            )
        try:
            executor = self._executors[invocation.adapter]
        except KeyError as exc:
            raise AdapterExecutionError(
                "adapter_not_found", "Requested adapter is not registered", retryable=False
            ) from exc
        return await self._invoke(lambda: executor.execute(invocation))

    async def invoke_with_credentials(
        self, invocation: AdapterInvocation, credentials: CredentialLeaseSet
    ) -> AdapterResult:
        try:
            executor = self._credential_executors[invocation.adapter]
        except KeyError as exc:
            raise AdapterExecutionError(
                "credential_aware_adapter_not_found",
                "Requested credential-aware adapter is not registered",
                retryable=False,
            ) from exc
        return await self._invoke(
            lambda: executor.execute_with_credentials(invocation, credentials)
        )

    @staticmethod
    async def _invoke(operation: Callable[[], Awaitable[AdapterResult]]) -> AdapterResult:
        try:
            result = await operation()
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
    def __init__(
        self,
        registry: AdapterRegistry,
        *,
        outcome_store: RouteOutcomeStore | None = None,
        clock: Callable[[], datetime] | None = None,
        monotonic: Callable[[], float] | None = None,
        attempt_provider: Callable[[], int] | None = None,
        credential_bindings: CredentialBindingStore | None = None,
        secret_providers: Mapping[str, SecretProvider] | None = None,
    ) -> None:
        self._registry = registry
        self._outcome_store = outcome_store
        self._clock = clock or (lambda: datetime.now(UTC))
        self._monotonic = monotonic or time.monotonic
        self._attempt_provider = attempt_provider or _activity_attempt
        self._credential_bindings = credential_bindings
        self._secret_providers = dict(secret_providers or {})

    @activity.defn(name=EXECUTE_ADAPTER_ACTIVITY)
    async def execute(self, invocation: AdapterInvocation) -> AdapterResult:
        started = self._monotonic()
        try:
            result = await self._invoke(invocation)
        except AdapterExecutionError as exc:
            self._record_outcome(
                invocation,
                kind=(
                    RouteOutcomeKind.RETRYABLE_FAILURE
                    if exc.retryable
                    else RouteOutcomeKind.TERMINAL_FAILURE
                ),
                latency_ms=_latency_ms(started, self._monotonic()),
                failure_code=exc.code,
            )
            details = (exc.diagnostics,) if exc.diagnostics else ()
            raise ApplicationError(
                exc.message,
                *details,
                type=exc.code,
                non_retryable=not exc.retryable,
            ) from exc
        self._record_outcome(
            invocation,
            kind=RouteOutcomeKind.SUCCESS,
            latency_ms=_latency_ms(started, self._monotonic()),
        )
        return result

    async def _invoke(self, invocation: AdapterInvocation) -> AdapterResult:
        if invocation.credential_binding_digest is None:
            return await self._registry.invoke(invocation)
        credentials = self._resolve_credentials(invocation)
        try:
            return await self._registry.invoke_with_credentials(invocation, credentials)
        finally:
            credentials.close()

    def _resolve_credentials(self, invocation: AdapterInvocation) -> CredentialLeaseSet:
        if self._credential_bindings is None or invocation.capability is None:
            raise AdapterExecutionError(
                "credential_unavailable",
                "Credential metadata is unavailable",
                retryable=False,
            )
        try:
            binding = self._credential_bindings.get(
                invocation.tenant_id,
                invocation.environment_id,
                invocation.adapter,
                invocation.capability,
            )
            if (
                binding is None
                or binding.binding_digest != invocation.credential_binding_digest
            ):
                raise ValueError("credential binding identity mismatch")
            context = ResolveContext(
                tenant_id=invocation.tenant_id,
                environment_id=invocation.environment_id,
                adapter=invocation.adapter,
                capability=invocation.capability,
            )
            leases: dict[str, SecretLease] = {}
            try:
                for name, reference in binding.secrets.items():
                    provider = self._secret_providers.get(reference.provider)
                    if provider is None:
                        raise ValueError("secret provider is unavailable")
                    leases[name] = provider.resolve(reference, context)
            except Exception:
                for lease in leases.values():
                    lease.close()
                raise
            return CredentialLeaseSet(leases)
        except AdapterExecutionError:
            raise
        except Exception as exc:
            raise AdapterExecutionError(
                "credential_unavailable",
                "Credentials could not be resolved",
                retryable=False,
            ) from exc

    def _record_outcome(
        self,
        invocation: AdapterInvocation,
        *,
        kind: RouteOutcomeKind,
        latency_ms: int,
        failure_code: str | None = None,
    ) -> None:
        if self._outcome_store is None or invocation.route_candidate_id is None:
            return
        attempt = self._attempt_provider()
        event_id = _outcome_event_id(invocation, attempt)
        try:
            self._outcome_store.append(
                RouteOutcome.issue(
                    event_id=event_id,
                    tenant_id=invocation.tenant_id,
                    transaction_id=invocation.transaction_id,
                    step_id=invocation.step_id,
                    candidate_id=invocation.route_candidate_id,
                    temporal_attempt=attempt,
                    kind=kind,
                    latency_ms=latency_ms,
                    failure_code=failure_code,
                    occurred_at=self._clock(),
                )
            )
        except Exception:
            # Routing telemetry must never change the business activity outcome.
            return


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


def _activity_attempt() -> int:
    try:
        return max(1, min(100, activity.info().attempt))
    except RuntimeError:
        return 1


def _latency_ms(started: float, finished: float) -> int:
    return max(0, min(86_400_000, round((finished - started) * 1000)))


def _outcome_event_id(invocation: AdapterInvocation, attempt: int) -> str:
    canonical = (
        f"{invocation.tenant_id}\0{invocation.transaction_id}\0{invocation.step_id}\0"
        f"{invocation.route_candidate_id}\0{attempt}"
    ).encode()
    return "route-outcome:" + hashlib.sha256(canonical).hexdigest()
