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

It does not implement carrier/browser adapters, route optimization, evidence
verdicts, authentication/authorization, or a horizontally-scaled SQL control
plane yet.

## Dependency rules

- `cargomesh.ir` is pure domain code. It must not import FastAPI, HTTPX, SQLAlchemy, Temporal, or Playwright.
- `cargomesh.mapping` may depend on `cargomesh.ir`, but not on the API package.
- `cargomesh.standards` must not depend on the API package or IR implementation details.
- `cargomesh.runtime.models` and `cargomesh.runtime.state_machine` are pure domain code.
- Temporal SDK imports are confined to `cargomesh.runtime.temporal` and worker wiring.
- `cargomesh.runtime.idempotency` must not import FastAPI or Temporal.
- `cargomesh.api` may depend on IR, mapping, and standards public interfaces.
- Tests must not require internet access. Network synchronization is tested through injected transports or local fixtures.

## Quality bar

- Python 3.12, typed public APIs, Pydantic v2.
- `ruff check .`, `mypy src`, and `pytest` must pass.
- All third-party material must record repository, commit, source path, SHA-256, and license.
- Canonical digests must be deterministic and must exclude runtime-generated metadata documented by the IR contract.
- Unknown or lossy mappings must produce diagnostics; they must never be silently accepted.
- Do not add a dependency when a small standard-library implementation is clearer.
