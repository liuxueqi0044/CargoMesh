# CargoMesh

CargoMesh is a business-transaction compiler and durable execution runtime for
container logistics. Board 1 turns a pinned DCSA Track & Trace 2.3 query into
deterministic, versioned Transaction IR. Board 2 submits an execution plan
idempotently and runs it through Temporal with explicit approval, retry,
compensation, cancellation, and queryable state.
Board 3 executes checksum-pinned, read-only browser recipes in isolated
Playwright contexts and stops on portal drift.

Execution completion is deliberately named `EXECUTED_UNVERIFIED`. Independent
cross-channel evidence is a later board, so CargoMesh never turns “the adapter
returned” into an unsupported `SUCCESS` or `VERIFIED` claim.

## Implemented surface

| Area | Implementation |
|---|---|
| DCSA source mirror | Immutable commit, per-file URL/license/SHA-256, local `$ref` normalization, offline `check`, explicit `sync` |
| Compatibility | Structural OpenAPI/YAML diff with a non-zero exit for breaking changes |
| Contract guard | Pinned `GET /v2/events` query parameters checked against the Pydantic model |
| Transaction IR | Strict immutable schema, typed date-time predicates, extensions, canonical JSON and digest |
| Mapping | Version/capability registry, bidirectional TNT 2.3 mapping and field-level fidelity diagnostics |
| Migration | Explicit graph, pure v0alpha1 → v1 step, before/after canonical documents and digests |
| Reference data | Version/status/validity model, exact lookup, separate alias suggestions, 44 pinned TNT values |
| HTTP API | Compile, schemas, supported capabilities, reference data, health and stable error envelopes |
| Execution plan | Immutable v1 plan, ordered dependencies, explicit adapter operations, timeout/retry/approval/compensation |
| Durable runtime | Temporal Workflow, Activity boundary, approval/cancel signals, status query and reverse compensation |
| Idempotency | Atomic tenant-scoped SQLite reference index with replay, conflict and failed-start retry semantics |
| Adapter boundary | Worker-side registry, safe failures and explicit synthetic local-demo adapter |
| Transaction API | Create, status, approval and cancel with required `Idempotency-Key` |
| Adapter packages | Strict manifest/recipe schemas, SHA-256 pinning, offline package checks and CLI |
| Browser executor | Semantic locators, fresh contexts, exact-origin HTTP policy and drift signatures |
| Adapter CI | Synthetic portal fault variants and real headless Chromium acceptance tests |

The first accepted capability remains `shipment.track.read`. Board 3 supplies a
synthetic browser adapter, not a real carrier integration. Route optimization,
evidence verdicts, production authentication/authorization and a distributed
control-plane database belong to later boards.

## Quick start

Requires Python 3.12 and [uv](https://docs.astral.sh/uv/).

```powershell
uv sync --dev
uv run playwright install chromium
uv run pytest
uv run ruff check .
uv run mypy src
uv run cargomesh-dcsa check
uv run cargomesh-adapter check
uv run uvicorn cargomesh.api.main:app --reload
```

Swagger UI is then available at `http://127.0.0.1:8000/docs`.

Compile a DCSA query:

```powershell
$body = @{
  sourceSchemaVersion = "dcsa.tnt.query/v2.3"
  payload = @{
    carrierBookingReference = "ABC-123"
    eventType = "SHIPMENT,EQUIPMENT"
    "eventCreatedDateTime:gte" = "2026-08-01T00:00:00Z"
  }
  context = @{ tenant_id = "tenant-a" }
} | ConvertTo-Json -Depth 8

Invoke-RestMethod `
  -Method Post `
  -Uri http://127.0.0.1:8000/v1/ir/compile `
  -ContentType application/json `
  -Body $body
```

The response includes normalized Transaction IR, canonical business JSON, a
`sha256:` business digest, and field-level mapping diagnostics.

## API contracts

- `GET /healthz`
- `GET /v1/capabilities`
- `GET /v1/contracts/transaction-ir/schema`
- `GET /v1/contracts/dcsa-tnt-query-v2.3/schema`
- `POST /v1/ir/compile`
- `GET /v1/reference-data/{namespace}?as_of=YYYY-MM-DD`
- `POST /v1/transactions` (requires `Idempotency-Key`)
- `GET /v1/transactions/{transaction_id}`
- `POST /v1/transactions/{transaction_id}/approval`
- `POST /v1/transactions/{transaction_id}/cancel`

The compile request is deliberately explicit and rejects unknown fields:

```json
{
  "sourceSchemaVersion": "dcsa.tnt.query/v2.3",
  "payload": {"transportDocumentReference": "BOL-123"},
  "context": {"tenant_id": "tenant-a"}
}
```

## Durable runtime

CargoMesh reuses the official Temporal Python SDK rather than implementing its
own workflow engine. Run a Temporal development server separately, then start the
two Board 2 processes for the explicit synthetic demonstration:

```powershell
uv run cargomesh-worker --enable-synthetic-adapter
uv run cargomesh-runtime-api --enable-synthetic-adapter-binding
```

Both commands use `localhost:7233` and task queue
`cargomesh-transactions-v1` by default. They can be configured with
`CARGOMESH_TEMPORAL_TARGET`, `CARGOMESH_TEMPORAL_NAMESPACE`,
`CARGOMESH_TEMPORAL_TASK_QUEUE`, and `CARGOMESH_SUBMISSION_DATABASE`.

The flags are intentionally explicit: the included adapter returns an empty,
synthetic event set and the notice `No carrier transaction was executed`. A real
deployment must register a separately certified carrier or browser adapter.

### Board 3 browser path

With the Temporal development server running, start the local synthetic portal,
the browser-enabled worker, and the matching runtime API in separate terminals:

```powershell
uv run cargomesh-synthetic-portal
uv run cargomesh-worker --enable-synthetic-browser-adapter
uv run cargomesh-runtime-api --enable-synthetic-browser-binding
```

The built-in `synthetic.browser.track` package is loaded offline and its recipe
bytes must match the SHA-256 recorded in the manifest. The executor accepts only
the restricted read-only recipe language documented in
`docs/architecture/board-3-implementation-contract.md`; it does not execute
arbitrary JavaScript, CSS/XPath selectors, absolute URLs, uploads, downloads, or
fixed sleeps.

Every invocation gets a new non-persistent browser context. HTTP subresources
outside the configured portal origin are aborted, and the label/heading/notice
signature is checked before form interaction. Controlled failure traces are off
by default; opt in with `--browser-trace-directory PATH`. Temporal receives only
opaque trace metadata, never the path or trace bytes.

Use a different local portal origin with `CARGOMESH_SYNTHETIC_PORTAL_URL` or
`--synthetic-portal-url`. Validate an adapter package without launching a browser:

```powershell
uv run cargomesh-adapter check
uv run cargomesh-adapter check --path C:\path\to\adapter-package
```

Submit a compiled IR or DCSA TNT source using the same body accepted by the
compiler endpoint:

```http
POST /v1/transactions
Idempotency-Key: customer-request-123
Content-Type: application/json
```

An equivalent replay returns the original transaction with HTTP 200; the first
accepted submission returns HTTP 202. Reusing the key for a different business
digest returns HTTP 409.

## Standards lifecycle

The production manifest is `third_party/dcsa/SOURCES.yaml`. Normal operation is
offline. Network access occurs only when a developer intentionally runs `sync`:

```powershell
uv run cargomesh-dcsa check
uv run cargomesh-dcsa sync
uv run cargomesh-dcsa diff --baseline old.yaml --candidate new.yaml
```

`diff` prints JSON and exits `2` when it detects a breaking change. Model/source
lockstep is enforced by `tests/standards/test_compatibility.py`.

## Repository map

```text
src/cargomesh/
├─ adapters/        versioned packages, restricted browser executor and synthetic portal
├─ api/             FastAPI transport and safe error envelopes
├─ application/     compile and reference-data use cases
├─ ir/              Transaction IR, canonicalization and migrations
├─ mapping/         DCSA TNT mapper, diagnostics and registry
├─ runtime/         plans, state machine, idempotency, Temporal and adapter boundary
└─ standards/       source integrity, compatibility and reference data

third_party/dcsa/   pinned upstream bytes and license
tests/              offline unit, contract and API tests
docs/               architecture decisions, provenance and acceptance record
```

## Build

```powershell
uv build
```

The wheel includes reference CSVs and the pinned DCSA source snapshot, so
`cargomesh-dcsa check` also works after installation outside the source checkout.

## License and upstream reuse

CargoMesh metadata declares Apache-2.0. The vendored DCSA files remain under
DCSA's Apache-2.0 license and retain their exact upstream license and provenance.
See `NOTICE`, `docs/standards/dcsa-provenance.md`, and the Board 2 architecture
and acceptance records under `docs/architecture/`.
