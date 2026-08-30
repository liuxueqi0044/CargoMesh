# CargoMesh contributor instructions

## Roles

- Sol is the architecture owner and final reviewer. Sol owns cross-module contracts, Transaction IR, migrations, integration, security-critical decisions, and final acceptance.
- Tera implements bounded infrastructure and standards tasks assigned by Sol. Tera must not change IR or API contracts without approval.
- Luna implements bounded application/API tasks assigned by Sol. Luna must not invent persistence or workflow behavior belonging to later boards.

## Implemented scope

Board 1 implements:

- pinned DCSA standards and source provenance;
- reference data;
- Transaction IR v1;
- DCSA TNT v2.3 query mapping;
- schema migration framework;
- compile/schema/reference-data HTTP APIs.

Board 2 implements:

- deterministic execution plans and state transitions;
- idempotent transaction submission;
- Temporal workflow/activity integration and a worker entry point;
- approval signals, retry policy, reverse-order compensation, and cancellation;
- transaction create/status/approval/cancel HTTP APIs.

Board 3 implements:

- versioned, checksum-pinned browser adapter packages;
- a deliberately restricted, read-only browser recipe contract;
- Playwright execution in isolated contexts with same-origin network policy;
- semantic locators, portal signatures, drift diagnostics, and bounded artifacts;
- a synthetic logistics portal and browser-backed Adapter CI.

Board 4 implements:

- immutable evidence observations and append-only local receipts;
- separately registered read-only evidence collectors;
- deterministic claim matching and L0-L3 independence computation;
- durable `VERIFYING`, `VERIFIED`, `NEEDS_REVIEW`, and `HALTED` outcomes;
- a separate synthetic system-of-record service for cross-channel tests.

Board 5 implements:

- immutable execution-path candidates, policies, health snapshots, and decisions;
- deterministic integer constraint filtering and multi-factor route ranking;
- append-only adapter outcome events and outcome-derived circuit health;
- audited read-only fallback on explicit safe error codes only;
- separate synthetic API and browser paths verified through the Board 4 ledger.

Board 6 implements:

- externally issued OIDC access-token verification with bounded JWKS retrieval;
- server-owned tenant/environment memberships and a fixed fail-closed RBAC matrix;
- opt-in enforcement on transaction create/read/approve/cancel operations;
- verified approval actors and cross-tenant resource hiding;
- append-only, tenant-independent SQLite audit hash chains.

Board 7 implements:

- immutable, payload-free execution-policy inputs, rules, sets, and decisions;
- deterministic embedded evaluation and a strict fail-closed OPA-shaped HTTPS provider;
- policy decisions and approval requirements frozen before Workflow start;
- tenant/environment/adapter/capability-scoped opaque credential bindings;
- worker-only ephemeral secret resolution with best-effort buffer wiping.

Board 8 implements:

- one-time, digest-only Private Runner enrollment and pinned public-key identity;
- tenant/environment/pool/capability-scoped runner authorization and revocation;
- atomic SQLite task leases with fencing, heartbeat and conservative recovery;
- metadata-only artifact receipts with an injected bounded content sink;
- sandbox, egress, browser-session, release and deployment-profile contracts.

It does not implement real carrier credentials/adapters, AI repair, an identity
provider/login UI, control-plane management APIs, hosted OPA/Vault, or a
horizontally-scaled SQL control plane yet. The Private Runner package does not
provide production mTLS/CA, hardened container/VM execution or a daemon installer.

## Dependency rules

- `cargomesh.ir` is pure domain code. It must not import FastAPI, HTTPX, SQLAlchemy, Temporal, or Playwright.
- `cargomesh.mapping` may depend on `cargomesh.ir`, but not on the API package.
- `cargomesh.standards` must not depend on the API package or IR implementation details.
- `cargomesh.runtime.models` and `cargomesh.runtime.state_machine` are pure domain code.
- Temporal SDK imports are confined to `cargomesh.runtime.temporal` and worker wiring.
- `cargomesh.runtime.idempotency` must not import FastAPI or Temporal.
- `cargomesh.adapters.contracts` and package verification must not import Playwright.
- Playwright imports are confined to `cargomesh.adapters.browser` and worker wiring.
- Browser recipes may not contain raw CSS/XPath, coordinates, JavaScript, fixed sleeps,
  file upload, credential values, or absolute navigation URLs.
- `cargomesh.verification.models` and `cargomesh.verification.engine` are pure;
  they must not import Temporal, FastAPI, Playwright, HTTP clients, or SQLite.
- Evidence collectors and execution adapters use separate registries; one may not
  be silently substituted for the other.
- Routing decisions are immutable Workflow input. Workflows must not query health,
  policy, databases, or clocks to recompute a route during replay.
- Automatic fallback is forbidden for effectful steps and for undeclared failure codes.
- Routing outcome stores must not persist transaction input, adapter output, or secrets.
- `cargomesh.controlplane.models` and the authorization evaluator are pure domain code;
  they must not import FastAPI, HTTP/JWT clients, Temporal, Playwright, or SQLite.
- Bearer tokens may exist only at the authentication boundary and must never enter
  memberships, decisions, audit events, logs, workflow inputs, or error messages.
- Tenant/environment/role authority comes only from the server-side membership store;
  token claims and request bodies are not authorization sources.
- Protected writes fail closed when membership or audit providers are unavailable.
- Policy providers receive metadata only. Transaction payloads and credentials may
  never enter a policy input or decision.
- Every primary and fallback attempt must have an allowed frozen policy decision;
  Workflows never call policy services or credential stores.
- Secret values may exist only in short-lived worker-side leases. Workflow inputs,
  plans, databases, logs, diagnostics, adapter results, and exceptions contain only
  opaque references or digests.
- Runner enrollment tokens are single-use bootstrap values; persistence contains
  only their digest. Private keys never cross the enrollment boundary.
- An expired effectful task lease must be recovered before reassignment. Unknown or
  post-effect state always enters verification/reconciliation.
- Runner artifacts are governed by declared type and MIME, never filename extension;
  blob bytes stay outside SQLite and receipt metadata contains only opaque references.
- `cargomesh.api` may depend on IR, mapping, and standards public interfaces.
- Tests must not require internet access. Network synchronization is tested through injected transports or local fixtures.

## Quality bar

- Python 3.12, typed public APIs, Pydantic v2.
- `ruff check .`, `mypy src`, and `pytest` must pass.
- All third-party material must record repository, commit, source path, SHA-256, and license.
- Canonical digests must be deterministic and must exclude runtime-generated metadata documented by the IR contract.
- Unknown or lossy mappings must produce diagnostics; they must never be silently accepted.
- Do not add a dependency when a small standard-library implementation is clearer.
