"""Deterministic Playwright executor for restricted CargoMesh browser recipes."""

from __future__ import annotations

import asyncio
import hashlib
import json
import tempfile
from contextlib import suppress
from pathlib import Path
from typing import Any, Protocol, cast
from urllib.parse import urljoin, urlsplit

from playwright.async_api import (
    Browser,
    BrowserContext,
    Locator,
    Page,
    Playwright,
    Route,
    async_playwright,
)
from playwright.async_api import Error as PlaywrightError
from playwright.async_api import TimeoutError as PlaywrightTimeoutError
from pydantic import BaseModel, ConfigDict, Field, JsonValue, model_validator

from cargomesh.runtime.adapters import AdapterExecutionError
from cargomesh.runtime.models import AdapterInvocation, AdapterResult
from cargomesh.verification.models import EvidenceChannel, ExecutionSource

from .artifacts import ArtifactDescriptor, ArtifactSink
from .contracts import (
    AssertTextAction,
    BrowserRecipe,
    ClickAction,
    ExtractTextAction,
    FillAction,
    InputBinding,
    LiteralBinding,
    LoadedAdapterPackage,
    LocatorSpec,
    NavigateAction,
    RoleLocator,
    SignatureProbe,
    WaitVisibleAction,
    text_matches,
)


class BrowserAdapterConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    base_url: str
    headless: bool = True
    default_timeout_ms: int = Field(default=15_000, ge=100, le=120_000)
    navigation_timeout_ms: int = Field(default=30_000, ge=100, le=120_000)
    max_concurrent_contexts: int = Field(default=4, ge=1, le=32)
    trace_on_failure: bool = False

    @model_validator(mode="after")
    def require_origin_only_base_url(self) -> BrowserAdapterConfig:
        parsed = urlsplit(self.base_url)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
        ):
            raise ValueError("base_url must contain only an http(s) origin")
        return self


class BrowserAuthenticationStateProvider(Protocol):
    async def storage_state(self, *, tenant_id: str, adapter: str) -> dict[str, Any] | None:
        """Resolve worker-local authentication without entering workflow history."""


class NoAuthenticationState:
    async def storage_state(self, *, tenant_id: str, adapter: str) -> dict[str, Any] | None:
        del tenant_id, adapter
        return None


class OriginPolicy:
    """Exact-origin request allowlist used for navigation and subresources."""

    def __init__(self, base_url: str) -> None:
        parsed = urlsplit(base_url)
        self._scheme = parsed.scheme.lower()
        self._host = (parsed.hostname or "").lower()
        self._port = parsed.port or (443 if self._scheme == "https" else 80)
        self.base_url = f"{self._scheme}://{self._host}"
        if self._port != (443 if self._scheme == "https" else 80):
            self.base_url += f":{self._port}"

    def allows(self, url: str) -> bool:
        try:
            parsed = urlsplit(url)
            port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
        except ValueError:
            return False
        return (
            parsed.scheme.lower() == self._scheme
            and (parsed.hostname or "").lower() == self._host
            and port == self._port
            and parsed.username is None
            and parsed.password is None
        )

    def resolve(self, path: str) -> str:
        resolved = urljoin(self.base_url + "/", path)
        if not self.allows(resolved):
            raise ValueError("navigation escaped configured origin")
        return resolved

    @staticmethod
    def safe_origin(url: str) -> str:
        try:
            parsed = urlsplit(url)
            if not parsed.scheme or not parsed.hostname:
                return "invalid-origin"
            port = f":{parsed.port}" if parsed.port is not None else ""
            return f"{parsed.scheme.lower()}://{parsed.hostname.lower()}{port}"
        except ValueError:
            return "invalid-origin"


class BrowserRecipeError(RuntimeError):
    pass


class PortalDriftError(BrowserRecipeError):
    pass


class PortalResponseError(BrowserRecipeError):
    def __init__(self, status_code: int) -> None:
        super().__init__("portal returned an unsuccessful HTTP status")
        self.status_code = status_code


class InputBindingError(BrowserRecipeError):
    pass


class PlaywrightBrowserAdapter:
    """Shared browser process with one isolated context per adapter invocation."""

    def __init__(
        self,
        package: LoadedAdapterPackage,
        config: BrowserAdapterConfig,
        *,
        authentication: BrowserAuthenticationStateProvider | None = None,
        artifact_sink: ArtifactSink | None = None,
    ) -> None:
        if config.trace_on_failure and artifact_sink is None:
            raise ValueError("trace_on_failure requires an artifact sink")
        self._package = package
        self._config = config
        self._authentication = authentication or NoAuthenticationState()
        self._artifact_sink = artifact_sink
        self._origin = OriginPolicy(config.base_url)
        self._semaphore = asyncio.Semaphore(config.max_concurrent_contexts)
        self._playwright: Playwright | None = None
        self._browser: Browser | None = None

    async def start(self) -> None:
        if self._browser is not None:
            return
        playwright = await async_playwright().start()
        try:
            browser = await playwright.chromium.launch(headless=self._config.headless)
        except Exception:
            await playwright.stop()
            raise
        self._playwright = playwright
        self._browser = browser

    async def close(self) -> None:
        browser, playwright = self._browser, self._playwright
        self._browser = None
        self._playwright = None
        if browser is not None:
            await browser.close()
        if playwright is not None:
            await playwright.stop()

    async def __aenter__(self) -> PlaywrightBrowserAdapter:
        await self.start()
        return self

    async def __aexit__(self, exc_type: object, exc: object, traceback: object) -> None:
        del exc_type, exc, traceback
        await self.close()

    @property
    def active_context_count(self) -> int:
        return len(self._browser.contexts) if self._browser is not None else 0

    async def execute(self, invocation: AdapterInvocation) -> AdapterResult:
        if invocation.adapter != self._package.manifest.name:
            raise AdapterExecutionError(
                "adapter_identity_mismatch",
                "Invocation does not match the loaded adapter package",
                retryable=False,
            )
        try:
            recipe = self._package.recipes[invocation.operation]
        except KeyError as exc:
            raise AdapterExecutionError(
                "operation_not_supported",
                "Adapter operation is not declared by the loaded package",
                retryable=False,
            ) from exc
        browser = self._browser
        if browser is None or not browser.is_connected():
            raise AdapterExecutionError(
                "browser_unavailable", "Browser runtime is not started", retryable=True
            )
        async with self._semaphore:
            return await self._execute_in_context(browser, recipe, invocation)

    async def _execute_in_context(
        self, browser: Browser, recipe: BrowserRecipe, invocation: AdapterInvocation
    ) -> AdapterResult:
        storage_state = await self._authentication.storage_state(
            tenant_id=invocation.tenant_id, adapter=invocation.adapter
        )
        context = await browser.new_context(
            accept_downloads=False,
            base_url=self._origin.base_url,
            color_scheme="light",
            locale="en-US",
            reduced_motion="reduce",
            service_workers="block",
            storage_state=cast(Any, storage_state),
            strict_selectors=True,
            timezone_id="UTC",
            viewport={"width": 1440, "height": 900},
        )
        context.set_default_timeout(self._config.default_timeout_ms)
        context.set_default_navigation_timeout(self._config.navigation_timeout_ms)
        blocked_origins: set[str] = set()
        blocked_methods: set[str] = set()
        blocked_features: set[str] = set()
        trace_started = False
        trace_stopped = False

        async def route_request(route: Route) -> None:
            request_url = route.request.url
            if not self._origin.allows(request_url):
                blocked_origins.add(self._origin.safe_origin(request_url))
                await route.abort("blockedbyclient")
                return
            if route.request.method not in {"GET", "HEAD", "OPTIONS"}:
                blocked_methods.add(route.request.method)
                await route.abort("blockedbyclient")
                return
            await route.continue_()

        await context.route("**/*", route_request)
        if self._config.trace_on_failure:
            await context.tracing.start(screenshots=True, snapshots=True, sources=False)
            trace_started = True
        try:
            page = await context.new_page()
            page.on("download", lambda _: blocked_features.add("download"))
            page.on("popup", lambda _: blocked_features.add("popup"))
            outputs, signature_digest = await self._run_recipe(page, recipe, invocation.input)
            if blocked_origins or blocked_methods or blocked_features:
                raise BrowserRecipeError("browser violated its execution policy")
            if trace_started:
                await context.tracing.stop()
                trace_stopped = True
            return AdapterResult(
                output={
                    "adapter": self._package.manifest.name,
                    "adapter_version": self._package.manifest.version,
                    "operation": recipe.operation,
                    "portal_version": self._package.manifest.portal_version,
                    "portal_signature_digest": signature_digest,
                    "synthetic": self._package.manifest.name.startswith("synthetic."),
                    "data": outputs,
                },
                execution_source=ExecutionSource(
                    source_system=self._package.manifest.source_system,
                    channel=EvidenceChannel.BROWSER,
                    adapter_id=self._package.manifest.name,
                    collection_id=_execution_collection_id(invocation),
                    synthetic=self._package.manifest.name.startswith("synthetic."),
                ),
            )
        except PortalDriftError as exc:
            descriptor, trace_stopped = await self._failure_trace(context, trace_started)
            policy_error = _policy_error(
                artifact=descriptor,
                blocked_origins=blocked_origins,
                blocked_methods=blocked_methods,
                blocked_features=blocked_features,
            )
            if policy_error is not None:
                raise policy_error from exc
            raise _adapter_error(
                "portal_drift_detected",
                "Portal signature no longer matches the certified adapter",
                retryable=False,
                artifact=descriptor,
            ) from exc
        except PortalResponseError as exc:
            descriptor, trace_stopped = await self._failure_trace(context, trace_started)
            policy_error = _policy_error(
                artifact=descriptor,
                blocked_origins=blocked_origins,
                blocked_methods=blocked_methods,
                blocked_features=blocked_features,
            )
            if policy_error is not None:
                raise policy_error from exc
            raise _adapter_error(
                "portal_server_error" if exc.status_code >= 500 else "portal_request_rejected",
                "Portal returned an unsuccessful response",
                retryable=exc.status_code >= 500,
                artifact=descriptor,
                portal_status=exc.status_code,
            ) from exc
        except InputBindingError as exc:
            descriptor, trace_stopped = await self._failure_trace(context, trace_started)
            policy_error = _policy_error(
                artifact=descriptor,
                blocked_origins=blocked_origins,
                blocked_methods=blocked_methods,
                blocked_features=blocked_features,
            )
            if policy_error is not None:
                raise policy_error from exc
            raise _adapter_error(
                "invalid_adapter_input",
                "Adapter input does not satisfy the certified recipe",
                retryable=False,
                artifact=descriptor,
            ) from exc
        except PlaywrightTimeoutError as exc:
            descriptor, trace_stopped = await self._failure_trace(context, trace_started)
            policy_error = _policy_error(
                artifact=descriptor,
                blocked_origins=blocked_origins,
                blocked_methods=blocked_methods,
                blocked_features=blocked_features,
            )
            if policy_error is not None:
                raise policy_error from exc
            raise _adapter_error(
                "browser_action_timeout",
                "Browser action timed out",
                retryable=True,
                artifact=descriptor,
            ) from exc
        except (PlaywrightError, BrowserRecipeError) as exc:
            descriptor, trace_stopped = await self._failure_trace(context, trace_started)
            policy_error = _policy_error(
                artifact=descriptor,
                blocked_origins=blocked_origins,
                blocked_methods=blocked_methods,
                blocked_features=blocked_features,
            )
            if policy_error is not None:
                raise policy_error from exc
            raise _adapter_error(
                "browser_execution_failed",
                "Browser execution failed",
                retryable=True,
                artifact=descriptor,
            ) from exc
        finally:
            if trace_started and not trace_stopped:
                with suppress(PlaywrightError):
                    await context.tracing.stop()
            await context.close()

    async def _failure_trace(
        self, context: BrowserContext, trace_started: bool
    ) -> tuple[ArtifactDescriptor | None, bool]:
        if not trace_started or self._artifact_sink is None:
            return None, False
        try:
            with tempfile.TemporaryDirectory(prefix="cargomesh-trace-") as temporary:
                trace_path = Path(temporary) / "trace.zip"
                await context.tracing.stop(path=trace_path)
                content = await asyncio.to_thread(trace_path.read_bytes)
            descriptor = await self._artifact_sink.store(
                kind="playwright_trace", content=content
            )
            return descriptor, True
        except Exception:
            return None, True

    async def _run_recipe(
        self, page: Page, recipe: BrowserRecipe, payload: dict[str, JsonValue]
    ) -> tuple[dict[str, JsonValue], str]:
        outputs: dict[str, JsonValue] = {}
        signature_digest = ""
        for index, action in enumerate(recipe.actions):
            timeout = action.timeout_ms or self._config.default_timeout_ms
            if isinstance(action, NavigateAction):
                response = await page.goto(
                    self._origin.resolve(action.path),
                    wait_until=action.wait_until,
                    timeout=timeout,
                )
                if not self._origin.allows(page.url):
                    raise BrowserRecipeError("navigation escaped configured origin")
                if response is None:
                    raise BrowserRecipeError("navigation returned no HTTP response")
                if not response.ok:
                    raise PortalResponseError(response.status)
                if index == 0:
                    signature_digest = await self._check_signatures(
                        page, recipe.portal_signatures, timeout
                    )
            elif isinstance(action, FillAction):
                locator = await _visible_unique(page, action.locator, timeout)
                await locator.fill(resolve_binding(payload, action.value), timeout=timeout)
            elif isinstance(action, ClickAction):
                locator = await _visible_unique(page, action.locator, timeout)
                await locator.click(timeout=timeout)
            elif isinstance(action, WaitVisibleAction):
                await _visible_unique(page, action.locator, timeout)
            elif isinstance(action, AssertTextAction):
                locator = await _visible_unique(page, action.locator, timeout)
                actual = _normalize_text(await locator.inner_text(timeout=timeout))
                if not text_matches(actual, action.expectation):
                    raise BrowserRecipeError("text assertion did not match")
            elif isinstance(action, ExtractTextAction):
                locator = await _visible_unique(page, action.locator, timeout)
                value = _normalize_text(await locator.inner_text(timeout=timeout))
                if len(value) > action.max_length:
                    raise BrowserRecipeError("extracted text exceeded declared maximum")
                outputs[action.output_key] = value
        if not signature_digest:
            raise PortalDriftError("portal signature was not evaluated")
        return outputs, signature_digest

    async def _check_signatures(
        self, page: Page, probes: tuple[SignatureProbe, ...], timeout: int
    ) -> str:
        observations: list[dict[str, str]] = []
        try:
            for probe in probes:
                locator = await _visible_unique(page, probe.locator, timeout)
                text = _normalize_text(await locator.inner_text(timeout=timeout))
                if probe.expectation is not None and not text_matches(text, probe.expectation):
                    raise PortalDriftError("portal signature text changed")
                observations.append({"key": probe.key, "text": text})
        except PlaywrightError as exc:
            raise PortalDriftError("portal signature locator changed") from exc
        canonical = json.dumps(
            observations, ensure_ascii=False, separators=(",", ":"), sort_keys=True
        ).encode("utf-8")
        return "sha256:" + hashlib.sha256(canonical).hexdigest()


def resolve_binding(
    payload: dict[str, JsonValue], binding: LiteralBinding | InputBinding
) -> str:
    if isinstance(binding, LiteralBinding):
        return binding.value
    value = resolve_json_pointer(payload, binding.pointer)
    if isinstance(value, bool):
        return "true" if value else "false"
    if not isinstance(value, str | int | float):
        raise InputBindingError("JSON Pointer must resolve to a scalar")
    return str(value)


def resolve_json_pointer(document: JsonValue, pointer: str) -> JsonValue:
    current = document
    for raw_token in pointer.split("/")[1:]:
        token = raw_token.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict):
            if token not in current:
                raise InputBindingError("JSON Pointer field is missing")
            current = current[token]
        elif isinstance(current, list):
            if not token.isdigit() or (len(token) > 1 and token.startswith("0")):
                raise InputBindingError("JSON Pointer array index is invalid")
            index = int(token)
            if index >= len(current):
                raise InputBindingError("JSON Pointer array index is out of range")
            current = current[index]
        else:
            raise InputBindingError("JSON Pointer traversed a scalar")
    return current


def locator_for(page: Page, spec: LocatorSpec) -> Locator:
    if isinstance(spec, RoleLocator):
        return page.get_by_role(spec.role, name=spec.name, exact=spec.exact)
    if spec.kind == "label":
        return page.get_by_label(spec.value, exact=spec.exact)
    if spec.kind == "test_id":
        return page.get_by_test_id(spec.value)
    if spec.kind == "text":
        return page.get_by_text(spec.value, exact=spec.exact)
    return page.get_by_placeholder(spec.value, exact=spec.exact)


async def _visible_unique(page: Page, spec: LocatorSpec, timeout: int) -> Locator:
    locator = locator_for(page, spec)
    await locator.first.wait_for(state="visible", timeout=timeout)
    if await locator.count() != 1:
        raise BrowserRecipeError("semantic locator did not resolve uniquely")
    return locator


def _normalize_text(value: str) -> str:
    return " ".join(value.split())


def _execution_collection_id(invocation: AdapterInvocation) -> str:
    canonical = (
        f"{invocation.tenant_id}\0{invocation.transaction_id}\0"
        f"{invocation.step_id}\0{invocation.adapter}"
    ).encode()
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def _adapter_error(
    code: str,
    message: str,
    *,
    retryable: bool,
    artifact: ArtifactDescriptor | None,
    blocked_origins: set[str] | None = None,
    blocked_methods: set[str] | None = None,
    blocked_features: set[str] | None = None,
    portal_status: int | None = None,
) -> AdapterExecutionError:
    diagnostics: dict[str, JsonValue] = {}
    if artifact is not None:
        diagnostics["artifact"] = cast(JsonValue, artifact.model_dump(mode="json"))
    if blocked_origins:
        diagnostics["blocked_origins"] = cast(JsonValue, sorted(blocked_origins))
    if blocked_methods:
        diagnostics["blocked_methods"] = cast(JsonValue, sorted(blocked_methods))
    if blocked_features:
        diagnostics["blocked_features"] = cast(JsonValue, sorted(blocked_features))
    if portal_status is not None:
        diagnostics["portal_status"] = portal_status
    return AdapterExecutionError(
        code, message, retryable=retryable, diagnostics=diagnostics
    )


def _policy_error(
    *,
    artifact: ArtifactDescriptor | None,
    blocked_origins: set[str],
    blocked_methods: set[str],
    blocked_features: set[str],
) -> AdapterExecutionError | None:
    violations = sum(bool(value) for value in (blocked_origins, blocked_methods, blocked_features))
    if not violations:
        return None
    if violations > 1:
        code = "browser_policy_blocked"
    elif blocked_origins:
        code = "external_request_blocked"
    elif blocked_methods:
        code = "unsafe_http_method_blocked"
    else:
        feature = next(iter(blocked_features))
        code = f"{feature}_blocked"
    return _adapter_error(
        code,
        "Browser execution was blocked by policy",
        retryable=False,
        artifact=artifact,
        blocked_origins=blocked_origins,
        blocked_methods=blocked_methods,
        blocked_features=blocked_features,
    )
