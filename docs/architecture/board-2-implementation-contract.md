# Board 2 implementation contract

## Purpose

Board 2 turns an already compiled `TransactionCommand` into a durable,
idempotently submitted execution. Temporal supplies workflow durability; CargoMesh
owns the logistics-specific plan contract, state semantics, approval boundary,
compensation rules, and adapter invocation envelope.

An execution finishing its adapter steps is `EXECUTED_UNVERIFIED`. Board 2 must
never return `SUCCESS` or `VERIFIED`: independent evidence and verdicts belong to
the later cross-channel verification board.

## Reuse decisions

- Reuse the official Temporal Python SDK for workflow history, timers, activity
  retries, signals, queries, cancellation, and worker polling.
- Use Python's `sqlite3` for the single-node idempotency index. Its job is a small
  atomic unique-key reservation, so SQLAlchemy would add more adaptation than
  value. A distributed SQL implementation can replace the protocol later.
- Do not build a workflow engine, retry scheduler, browser executor, policy
  engine, or adapter optimizer in this board.

## Package ownership

```text
cargomesh.runtime.models/state_machine/planner/temporal  Sol
cargomesh.runtime.idempotency                            Tera
cargomesh.application.transactions + HTTP API            Luna
```

## Execution-plan contract

`ExecutionPlan` is immutable, versioned as `cargomesh.execution-plan/v1`, and
contains:

- transaction, tenant, and canonical business digest identifiers;
- the IR risk class and required verification level;
- one or more ordered `ExecutionStep` values;
- explicit adapter and operation names;
- JSON-only adapter input;
- activity timeout and retry policy;
- whether approval is required before a step;
- an optional compensation operation.

Each step declares its own risk class, and the plan risk must equal the highest
step risk. Compensation operations are required to be idempotent and safe when
the original effect is absent: an Activity failure is outcome-ambiguous, so the
runtime attempts the failing write step's compensation as well as compensating
previous completed writes. A write without such a boundary can only halt.

Plans reject duplicate step ids, unknown dependencies, forward dependencies,
secret-looking input keys, compensation on read-only plans, and an approval
timeout without an approval boundary. The runtime transports references to
credentials, never credentials themselves.

Board 2 uses an explicitly configured static capability binding. Dynamic route
selection using health, cost, or policy is a later board.

## State contract

The externally visible states are:

```text
ACCEPTED -> RUNNING -> [WAITING_APPROVAL] -> EXECUTED_UNVERIFIED
                    \-> COMPENSATING -> COMPENSATED
                    \-> HALTED
                    \-> CANCELLED
WAITING_APPROVAL -> REJECTED
```

Only declared transitions are legal. `EXECUTED_UNVERIFIED`, `COMPENSATED`,
`REJECTED`, `HALTED`, and `CANCELLED` are terminal. A completed adapter operation
is recorded before moving to the next step; compensation runs completed,
compensatable steps in reverse order.

## Idempotent submission contract

The unique key is `(tenant_id, idempotency_key)`. The first request atomically
stores the transaction id, workflow id, business digest, and `RESERVED` state.

- Repeating the same key and digest returns the original reservation.
- Repeating the same key with another digest fails with `idempotency_conflict`.
- A deterministic workflow id is stored before calling Temporal.
- Start acknowledgement changes the row to `STARTED`.
- A transient launch failure changes it to `START_FAILED`; retrying the same
  request reuses the same workflow id and reservation.

The ledger does not duplicate Temporal workflow history and is not an evidence
store.

## Temporal contract

`CargoMeshTransactionWorkflow`:

1. starts from the immutable execution plan;
2. waits for an approval signal when the next step requires approval;
3. invokes the generic adapter activity with SDK retry and timeout options;
4. on a terminal step failure, compensates completed steps in reverse order;
5. exposes a read-only status query and approval/cancel signals;
6. returns a terminal `ExecutionSnapshot` without claiming verification.

Workflow code is deterministic. Network, filesystem, adapter registry access,
and wall-clock side effects exist only in activities or client code.

## Adapter boundary

An `AdapterExecutor` accepts `AdapterInvocation` and returns `AdapterResult`.
The registry is configured in the worker process. Unknown adapters/operations,
malformed results, and undeclared effects fail closed. Board 2 ships a synthetic
read-only adapter only for local demonstration and acceptance; it is never
advertised as a carrier integration.

## HTTP contract

- `POST /v1/transactions` requires `Idempotency-Key`, compiles the explicit
  source payload, submits the plan, and returns `202` for a new reservation or
  `200` for an idempotent replay.
- `GET /v1/transactions/{transaction_id}` returns the durable runtime snapshot.
- `POST /v1/transactions/{transaction_id}/approval` sends an explicit approve or
  reject decision.
- `POST /v1/transactions/{transaction_id}/cancel` requests cancellation.

Stable error codes are returned without Temporal, SQL, path, or traceback text.

## Acceptance

1. Concurrent same-key/same-digest reservations converge on one transaction.
2. Same-key/different-digest requests fail closed.
3. Retrying a failed Temporal launch reuses the workflow id.
4. Approval blocks the affected step; reject is terminal and invokes no adapter.
5. Activity failures honor retry configuration and trigger reverse compensation.
6. Cancellation and approval are idempotent where repeating them is safe.
7. Workflow status never reports `VERIFIED` or generic `SUCCESS`.
8. Unit/contract tests run without a network or Temporal server.
9. `pytest`, `ruff check .`, strict `mypy`, package build, and wheel smoke tests pass.
