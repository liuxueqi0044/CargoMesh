# CargoMesh

CargoMesh is a business-transaction compiler and durable execution runtime for
container logistics. Board 1 turns a pinned DCSA Track & Trace 2.3 query into
deterministic, versioned Transaction IR. Board 2 submits an execution plan
idempotently and runs it through Temporal with explicit approval, retry,
compensation, cancellation, and queryable state.
Board 3 executes checksum-pinned, read-only browser recipes in isolated
Playwright contexts and stops on portal drift.
Board 4 collects separately sourced evidence, persists immutable receipts, and
produces deterministic, digest-protected verification reports.
Board 5 selects among API, EDI, browser, and attended paths using digest-bound
policy, outcome-derived health, integer scoring, and audited read-only fallback.
Board 6 verifies externally issued OIDC tokens, resolves tenant/environment
membership from CargoMesh-owned data, applies a fixed RBAC matrix, and writes
append-only per-tenant audit hash chains.
Board 7 freezes payload-free policy decisions for every possible execution
attempt and resolves opaque credential references only inside the worker
Activity that invokes a credential-aware adapter.
Board 8 supplies an offline Private Runner reference boundary for one-time
enrollment, pinned identity, fenced task leases, heartbeat recovery, artifact
relay, sandbox declarations, and signed-release policy.
Board 9 adds one explicitly synthetic DCSA Booking 2.0.5 write slice with a
typed dry-container IR, mandatory approval, tenant policy, credential-scoped
submit/cancel, single-attempt unknown-effect reconciliation, and independent
ledger verification.
Board 10 adds bounded EDIFACT parsing, fail-closed MIME/PDF metadata ingestion,
fenced attended-human tasks, and deterministic EDI/HUMAN plan compilation.
Board 11 adds a metadata-only Adapter Factory that compiles reviewed semantic
bindings into the existing package format and certifies exact package digests
with a deterministic fault/drift TCK.

Execution without a configured verifier remains deliberately named
`EXECUTED_UNVERIFIED`. Only a separate evidence collector can produce
`VERIFIED`; conflicts become `NEEDS_REVIEW`, and missing, stale, or insufficient
evidence becomes `HALTED`.

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
| Evidence contracts | Immutable bounded observations, provenance, canonical digests and typed reports |
| Verification engine | Pure claim matching and computed L0–L3 cross-channel independence |
| Evidence receipts | Tenant-scoped append-only SQLite store with idempotent replay and conflict detection |
| Evidence channel | Separate bounded HTTP collector and synthetic system-of-record fault service |
| Route optimizer | Immutable candidate/policy contracts, hard gates, integer scoring and deterministic ties |
| Route health | Append-only tenant-scoped outcomes, rolling p95/success metrics and cooldown circuits |
| Safe fallback | Workflow-frozen alternatives; read-only and explicit safe error codes only |
| Synthetic API path | Strict bounded HTTP adapter plus healthy and controlled-fault local service |
| OIDC boundary | RS256 allowlist, exact issuer/audience, bounded HTTPS JWKS retrieval and one unknown-key refresh |
| Tenant RBAC | Server-owned memberships for six transaction/control-plane actions with fail-closed provider handling |
| Security audit | Bounded immutable events in independent tenant hash chains with replay and tamper detection |
| Protected runtime | Explicit opt-in 401/403/404 enforcement and verified approval actors; local mode stays compatible |
| Execution policy | Digest-bound embedded/OPA-shaped decisions, deterministic rules, fail-closed denial, frozen approval requirements |
| Credential boundary | Tenant/environment/adapter/capability-scoped references, metadata-only SQLite directory, ephemeral wiped leases |
| Private Runner identity | One-time hashed enrollment challenges, pinned public-key digests, scoped queues, revocation and health state |
| Runner task transport | Atomic SQLite acquisition, monotonic fencing, bounded heartbeat, conservative recovery and idempotent receipts |
| Runner execution policy | Artifact relay, sandbox/egress/session contracts, SemVer compatibility and non-overclaiming deployment profiles |
| Verified Booking write | Pinned DCSA 2.0.5 subset, approval, idempotent synthetic submit, L2 ledger read-back and reference-bound cancellation |
| Additional channels | Metadata-only EDIFACT and MIME/PDF boundaries, attended-task fencing and existing-plan compilation |
| Adapter Factory | Reviewed semantic bindings, canonical existing-format packages, fault/drift TCK and digest-bound certification |

The accepted execution demonstrations are `shipment.track.read` and the
explicitly synthetic `booking.create` vertical slice. Board 3 supplies a
synthetic API and browser adapters, not real carrier integrations. Boards 6–10
supply single-node production-style control and channel boundaries;
identity-provider/Vault/OPA hosting, real EDI/mail/human delivery, management
APIs, and a distributed control-plane database remain external.

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

### Board 4 verified browser path

With Temporal running, start the execution portal, the separate evidence
service, the worker, and runtime API in separate terminals:

```powershell
uv run cargomesh-synthetic-portal
uv run cargomesh-synthetic-evidence
uv run cargomesh-worker --enable-synthetic-browser-adapter --enable-synthetic-verifier
uv run cargomesh-runtime-api --enable-synthetic-browser-binding --enable-synthetic-verification-binding
```

The browser adapter declares `synthetic.portal` as its execution source. The
evidence collector reads `synthetic.ledger` over a second process with redirects
and environment proxies disabled and a 64 KiB response ceiling. Receipt rows are
stored before evaluation in `cargomesh-evidence.sqlite3`; configure this with
`CARGOMESH_EVIDENCE_DATABASE` or `--evidence-database`.

This demonstration can achieve L2 because collection is separate and the source
system differs from execution. It is still synthetic and does not confirm a real
carrier transaction. Use `cargomesh-synthetic-evidence --variant conflict`,
`missing`, `stale`, or `server_error` to exercise fail-closed paths.

### Board 5 optimized dual path

Board 5 adds a separate synthetic tracking API on port 8767. With Temporal
running, start these processes in separate terminals:

```powershell
uv run cargomesh-synthetic-portal
uv run cargomesh-synthetic-api
uv run cargomesh-synthetic-evidence
uv run cargomesh-worker --enable-synthetic-api-adapter --enable-synthetic-browser-adapter --enable-synthetic-verifier --enable-routing-outcomes
uv run cargomesh-runtime-api --enable-synthetic-optimized-binding
```

The API and runtime default to `cargomesh-routing.sqlite3`; configure both with
`CARGOMESH_ROUTING_DATABASE` or `--routing-database`. A new transaction freezes
the policy digest, health snapshot, component scores, ranking, chosen path, and
safe fallback order before Temporal starts. Empty or healthy history selects
`synthetic.api.track`. Three recent consecutive API failures open its local
circuit and make the next plan select `synthetic.browser.track`.

Automatic fall-through is deliberately narrow: the step must be `READ_ONLY`,
the failing candidate must list the bounded ApplicationError code, and the next
candidate must already be present in the frozen decision. Effectful work and
unknown errors halt instead of guessing whether a write occurred. Every real
Activity attempt records only route identity, outcome, safe error code, and
latency—never transaction input or adapter output.

Use `cargomesh-synthetic-api --variant server_error`, `malformed`, or
`not_found` to exercise fallback and fail-closed response validation. Board 4's
separate `synthetic.ledger` collector can verify either execution path and can
reach L2 when the submitted IR requires L2.

### Board 9 verified synthetic Booking path

The Booking slice never contacts a real carrier. Start the Temporal development
server, then run the synthetic carrier, its separate ledger, the worker and the
runtime API in separate terminals:

```powershell
uv run cargomesh-synthetic-booking-carrier
uv run cargomesh-synthetic-booking-ledger
uv run cargomesh-worker --enable-synthetic-booking-adapter --enable-synthetic-booking-verifier
uv run cargomesh-runtime-api --enable-synthetic-booking-binding
```

Both synthetic services share `synthetic-booking.sqlite3`. The local policy is
restricted to tenant `tenant-a` and environment `local` by default; matching
scope overrides must be supplied to both worker and API. Submit a complete
`cargomesh.transaction/v1` `booking.create` command, then approve its
`submit-booking` step through the normal approval endpoint. The write has one
attempt only. If the result is indeterminate, CargoMesh reads the independent
ledger instead of resubmitting or guessing a cancellation.

This reference path uses an in-memory, clearly synthetic credential provider.
It is not a carrier certification, production credential configuration, or
permission to automate a third-party service.

### Board 6 access-control boundary

Local development remains unchanged when access control is absent. To enable
enforcement, configure all six values and pass the explicit flag:

```powershell
$env:CARGOMESH_OIDC_ISSUER = "https://identity.example"
$env:CARGOMESH_OIDC_AUDIENCE = "cargomesh"
$env:CARGOMESH_OIDC_JWKS_URL = "https://identity.example/.well-known/jwks.json"
$env:CARGOMESH_ENVIRONMENT_ID = "production"
$env:CARGOMESH_MEMBERSHIP_DATABASE = "cargomesh-memberships.sqlite3"
$env:CARGOMESH_AUDIT_DATABASE = "cargomesh-audit.sqlite3"

uv run cargomesh-runtime-api `
  --enable-synthetic-optimized-binding `
  --enforce-access-control
```

CargoMesh does not host login pages, store passwords, or mint user tokens. The
configured identity provider signs access tokens; CargoMesh ignores tenant and
role claims and resolves authority from `SQLiteMembershipStore`. Memberships
must be provisioned by trusted deployment/bootstrap code before enforcement is
used. The public `TenantMembership.issue()` and `SQLiteMembershipStore.provision()`
interfaces are the current bootstrap surface; an authenticated management API
is intentionally deferred.

Missing/invalid bearer credentials return 401. A principal outside the resource
tenant sees 404, while an in-tenant role without the action sees 403. Protected
requests write authorization and outcome events to the audit ledger; an audit
or membership-provider failure prevents the operation. Use
`SQLiteAuditStore.verify_chain(tenant_id)` to detect the first damaged record.

### Board 7 policy and credential boundary

`apply_execution_policy` evaluates metadata-only inputs before Temporal starts.
Its immutable plan records the exact policy, input, decision, route, channel,
and optional credential-binding digest for every primary and fallback attempt.
`DENY` stops submission, provider failures fail closed, and
`REQUIRE_APPROVAL` becomes a durable approval boundary.

Credential bindings contain provider-qualified opaque references, never secret
values. `AdapterActivities` rechecks the complete tenant/environment/adapter/
capability scope and frozen binding digest, resolves short-lived leases through
an explicitly registered provider, calls only a credential-aware adapter, and
closes every lease on success, failure, or partial resolution. The included
environment and memory providers are explicit local/bootstrap surfaces; a
production secret manager remains deployment-owned.

### Board 8 Private Runner reference

The `cargomesh.runner` package provides a local reference control boundary.
Enrollment tokens are random, one-time and short-lived; SQLite stores only their
SHA-256 digests. A runner identity pins a runner-generated public-key digest,
tenant, environment, pool, capabilities, platform, version and opaque queue id.
No private key or certificate bytes cross this interface.

`SQLiteTaskStore` authorizes that exact active identity before leasing work.
Every reacquisition receives a larger fencing token. An expired lease is never
silently reassigned: a pre-effect checkpoint may be requeued explicitly, while
post-effect or ambiguous state moves to verification/reconciliation. Results
are digest-only, fenced and idempotent.

The artifact relay enforces type, MIME, size, classification and sanitization
policy before an injected sink receives bytes; SQLite stores metadata receipts
only. Sandbox, egress, browser-session and update objects are enforceable
contracts for an external runner implementation. This repository does not
claim production mTLS, CA issuance, hardened containers/VMs, object storage or
an installed customer-network daemon.

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
├─ channels/        bounded EDI, MIME/PDF and attended-human contracts
├─ controlplane/    OIDC principals, tenant RBAC, access orchestration and audit chains
├─ factory/         reviewed semantic bindings, package builder, TCK and drift reports
├─ ir/              Transaction IR, canonicalization and migrations
├─ mapping/         DCSA TNT mapper, diagnostics and registry
├─ routing/         execution candidates, policy ranking, outcomes and circuit health
├─ runtime/         plans, state machine, idempotency, Temporal and adapter boundary
├─ standards/       source integrity, compatibility and reference data
└─ verification/    evidence collectors, receipts and deterministic verdict engine

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
