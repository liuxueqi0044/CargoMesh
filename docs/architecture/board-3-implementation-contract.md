# Board 3 implementation contract

## Purpose

Board 3 turns the generic Board 2 adapter activity into a deterministic browser
execution path. It introduces a package format for certified portal recipes, a
restricted read-only action language, portal drift detection, a synthetic
logistics portal, and browser-backed Adapter CI.

It does not claim that returned portal text is independent evidence. A browser
adapter finishing still produces Board 2's `EXECUTED_UNVERIFIED` state.

## Reuse decisions

- Reuse the official Playwright Python library for Chromium control, locator
  strictness, auto-waiting, isolated browser contexts, network routing, traces,
  and screenshots.
- Reuse FastAPI for the synthetic portal already used by CargoMesh HTTP tests.
- Use JSON and Pydantic for adapter packages. A new template engine, browser
  driver, polling framework, or general RPA language would add risk without
  product value.
- Do not integrate OpenAdapt yet. Board 3 consumes reviewed deterministic
  recipes; demonstration capture and AI repair are later isolated tooling.

## Package ownership

```text
cargomesh.adapters.contracts/browser + integration  Sol
cargomesh.adapters.package/CLI/data                  Tera
cargomesh.adapters.synthetic_portal                  Luna
```

## Adapter package contract

Every package contains one `cargomesh.adapter-manifest/v1` manifest and one or
more `cargomesh.browser-recipe/v1` JSON recipes. The manifest records:

- adapter name and SemVer version;
- supported portal version and CargoMesh capability;
- operation-to-recipe mapping;
- exact recipe SHA-256;
- minimum CargoMesh runtime version.

Package loading rejects path traversal, duplicate operations, a missing or
modified recipe, digest case differences, extra fields, and manifest/recipe
operation mismatches. Normal execution never downloads package files.

## Restricted recipe contract

Board 3 recipes are `READ_ONLY`. The only supported actions are:

- navigate to a relative same-origin path;
- fill a semantic locator from a literal or JSON Pointer input binding;
- click a semantic locator;
- wait for a locator to become visible;
- assert exact/contained text;
- extract bounded text into a named output.

Locators are restricted to role/name, label, test id, visible text, and
placeholder. Coordinates, XPath, raw CSS, arbitrary JavaScript, absolute URLs,
fixed sleep, upload/download, keyboard macros, and popup control are absent from
the schema, rather than accepted and filtered at execution time.

The first action must navigate. Recipes contain at most 100 actions. Output names
are unique. JSON Pointer bindings fail closed when absent or non-scalar.

## Browser isolation and network policy

Each invocation receives a new non-persistent `BrowserContext`; cookies, cache,
local storage, and pages are discarded on close. Service workers and downloads
are blocked. The context has fixed locale, timezone, viewport, color scheme, and
reduced motion. Every HTTP request must match the configured base origin and use
`GET`, `HEAD`, or `OPTIONS`; an external redirect/subresource or HTTP write is
aborted. Popup/download attempts also fail the invocation.

The base URL and authentication state are worker configuration, not Temporal
payload. Board 3's synthetic adapter uses no authentication. A future credential
resolver must inject storage state in the worker without returning it in output,
logs, screenshots, traces, or workflow history.

## Drift contract

After the initial navigation and before business actions, the executor evaluates
the recipe's portal signature probes. Each probe must resolve to exactly one
visible element and may require exact or contained text. The canonical observed
probe values produce a SHA-256 signature digest.

A missing, ambiguous, or mismatched probe raises non-retryable
`portal_drift_detected`; it does not fall back to a guessed selector. Browser and
network failures use separate safe codes.

## Artifact contract

Failure traces are opt-in through an injected artifact sink. The adapter result
or error may expose only an opaque artifact id, kind, content type, size, and
SHA-256—not an absolute path or artifact bytes. Traces are debugging material,
not business evidence, and are disabled when no sink is configured.

## Synthetic portal and Adapter CI

The local portal implements `shipment.track.read` for fixed synthetic booking
references and can expose controlled label, result, delay, and server-failure
variants. It carries a visible “synthetic / no carrier transaction” notice.

Adapter CI must run:

1. manifest and recipe schema validation;
2. checksum and operation lockstep checks;
3. unit tests for JSON Pointer, locators, origin policy, and safe errors;
4. a real headless Chromium healthy-path test;
5. a real headless Chromium drift test that halts before filling/clicking;
6. wheel installation and built-in package integrity checks.

## Acceptance

1. A Board 1 TNT/IR command reaches the synthetic portal through Board 2's
   `AdapterExecutor` interface and returns normalized synthetic tracking text.
2. Every invocation uses a fresh context and closes it on success or failure.
3. External requests, redirects, HTTP writes, popups, downloads, and service
   workers are blocked.
4. Portal drift is non-retryable and never causes fallback guessing.
5. Tampered recipe bytes fail before a browser launches.
6. Traces are absent by default and bounded/opaque when explicitly enabled.
7. No recipe or result contains `SUCCESS`/`VERIFIED` business verdicts.
8. Offline tests, browser tests, Ruff, strict Mypy, build, and wheel smoke pass.
