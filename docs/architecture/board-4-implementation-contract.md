# Board 4 implementation contract

## Purpose

Board 4 converts an executed transaction into an independently supported
verification verdict. Execution output is an assertion, not evidence. A
separate collector must obtain bounded observations from a separately declared
session/source, and a deterministic engine must compare those observations with
the original transaction and execution output.

The only verification verdicts are `VERIFIED`, `NEEDS_REVIEW`, and `HALTED`.
`SUCCESS` remains absent. A transaction without a configured verifier remains
`EXECUTED_UNVERIFIED`.

## Reuse decisions

- Reuse Pydantic for strict immutable evidence, plan, and report contracts.
- Reuse Temporal Activities for retryable collection and durable recording of
  the final report; raw observations are not copied into Workflow history.
- Reuse SQLite as the local append-only evidence receipt store. It is a
  reference implementation, not the future distributed control plane.
- Reuse HTTPX2 for bounded asynchronous read-only evidence collection.
- Reuse FastAPI for a second synthetic process representing an independent
  system-of-record channel.
- Do not add an LLM, vector database, policy engine, PDF parser, email client, or
  real carrier credential in this board.

## Ownership

```text
verification models/engine/runtime integration  Sol
synthetic independent evidence service          Tera
HTTP collector and append-only receipt store    Luna
final integration and acceptance                Sol
```

## Evidence contract

An `EvidenceObservation` contains:

- tenant and transaction identity;
- an opaque evidence id and source record id;
- source system, channel, collector id, and collection id;
- timezone-aware observation and optional expiry times;
- a bounded flat claim map;
- a canonical SHA-256 content digest;
- an explicit `synthetic` marker.

The model rejects unknown fields, NaN/infinity, secret-like claim names,
timezone-naive dates, invalid expiry ordering, an incorrect digest, and
unbounded observations. Raw HTTP bodies, credentials, cookies, file paths, and
trace bytes are never Workflow payloads.

## Independence levels

- `L0`: no independent observation; it can never produce `VERIFIED`.
- `L1`: a separately collected observation whose collector and collection id
  differ from execution.
- `L2`: at least one L1 observation from a source system different from every
  execution source.
- `L3`: at least two mutually distinct non-execution source systems spanning at
  least two evidence channels.

The engine computes the achieved level from provenance; collectors cannot
self-assert it. Synthetic data obeys the same rules but every report remains
visibly marked `synthetic=true`.

## Deterministic claim evaluation

A `VerificationPlan` declares collectors and exact claim rules. Expected values
are read through validated JSON Pointers from a bounded execution document that
contains the original transaction and step outputs. Board 4 supports exact
scalar equality with an explicit optional case-fold normalization only; fuzzy
matching, regex, embeddings, and model judgment are absent.

Verdict rules are fail closed:

- all required claims match and the required independence level is achieved:
  `VERIFIED`;
- evidence exists but required values conflict: `NEEDS_REVIEW`;
- evidence is missing, stale, structurally invalid, or insufficiently
  independent: `HALTED`.

The report binds the transaction id and canonical business digest, then includes
bounded reason codes, per-claim results, evidence receipt summaries,
achieved/required levels, and its own canonical digest. It never contains raw
evidence bytes.

## Collection and persistence

Verification collectors live in a registry separate from execution adapters.
The synthetic HTTP collector accepts only one fixed read operation, an exact
configured origin, redirects disabled, `GET` only, environment proxies disabled,
strict timeouts, JSON content type, and a 64 KiB response limit.
The body is streamed and collection aborts as soon as the decoded byte ceiling
is crossed; it is not buffered without a bound first.

Every accepted observation is appended to an SQLite receipt store before the
verdict is returned. Replaying the same evidence id and digest is idempotent;
reusing the id with different content is a hard conflict. Reads revalidate the
stored observation and digest.

## Durable runtime

An execution plan may carry one optional verification plan. After all execution
steps finish:

1. no verification plan or `L0` -> `EXECUTED_UNVERIFIED`;
2. configured verification -> `VERIFYING` and one verification Activity;
3. report verdict -> matching `VERIFIED`, `NEEDS_REVIEW`, or `HALTED` state;
4. collection/runtime failure -> `HALTED` with a safe failure code.

The final `ExecutionSnapshot` contains the typed verification report. Temporal
history contains the report and opaque receipts, not raw HTTP responses.

## Synthetic independent channel

The Board 3 portal remains one process/source. Board 4 adds a different local
process/source representing a system-of-record ledger with fixed records and
healthy, conflict, missing, stale, and server-error variants. It is explicitly
synthetic and does not represent a carrier confirmation.

Adapter manifest v2 adds the required `source_system` provenance field and pins
its minimum CargoMesh runtime to 0.4.0. This is intentionally a schema-versioned
change rather than silently changing the v1 contract.

## Acceptance

1. Board 1 IR -> Board 2 Workflow -> Board 3 browser output -> Board 4 separate
   HTTP evidence source reaches a synthetic `VERIFIED` report.
2. Same-source fresh collection achieves only L1; a different source can reach
   L2; two distinct sources/channels are required for L3.
3. Conflicting evidence produces `NEEDS_REVIEW`; missing/stale/insufficient
   evidence produces `HALTED`.
4. Execution output alone never produces `VERIFIED`.
5. Evidence receipts are digest-checked, append-only, tenant-scoped, bounded,
   and idempotent under Temporal retry.
6. Collector redirects, oversized bodies, wrong content type, non-matching
   references, and HTTP failures fail safely.
7. Existing unverified workflows retain `EXECUTED_UNVERIFIED` behavior.
8. Full tests, Ruff, strict Mypy, build, wheel smoke, fresh-clone smoke, and
   GitHub CI pass.
