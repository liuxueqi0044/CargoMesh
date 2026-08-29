# Board 5 implementation contract

## Purpose

Board 5 turns a static capability binding into an auditable execution-path
decision. For one business capability CargoMesh may have an official API, EDI,
certified browser workflow, or attended human path. The router first applies
hard policy and safety constraints, then deterministically ranks the remaining
candidates using reliability, latency, cost, health, data classification,
transaction risk, approval requirements, and achievable verification level.

Routing is production control logic. It contains no LLM, fuzzy judgment,
randomness, hidden wall-clock reads, or self-reported adapter health.

## Reuse decisions

- Reuse Pydantic for immutable route profiles, policies, health snapshots,
  decisions, attempts, and outcome events.
- Reuse SQLite for the local append-only outcome ledger and rolling health
  snapshots. This remains a single-node reference implementation.
- Reuse Temporal's existing Activity boundary. Adapter attempts are measured in
  the worker, outside deterministic Workflow code.
- Reuse HTTPX2 and FastAPI for a separate synthetic official-API path.
- Reuse Board 4's verification plan and ledger for both API and browser output.
- Do not add OR-Tools. This board ranks at most 16 independent candidates; it is
  not solving a vehicle-routing or graph-search problem.
- Do not embed OPA yet. The policy model has an id/version/digest and a narrow
  provider boundary so a future OPA Data API or Wasm evaluator can replace the
  local policy provider without changing routing semantics.
- Do not add an OpenTelemetry SDK yet. Outcome events are the routing source of
  truth; a future exporter can emit the same bounded events as telemetry.

## Ownership

```text
architecture, route models/engine, runtime integration  Sol
independent synthetic API service                      Tera
append-only outcome store and health aggregation       Luna
HTTP API execution adapter, final acceptance           Sol
```

## Candidate profile

A `RouteCandidate` is boot-time operator configuration, not transaction input.
It declares:

- stable candidate id, capability, adapter, operation, and channel;
- baseline success basis points, expected p95 latency, and cost micros;
- maximum risk class, data classification, and verification level;
- approval, timeout, retry, and explicit fallback-safe error codes;
- a deterministic static priority used only after score ties.

Profiles reject unknown fields, duplicate fallback codes, secret-like values,
floats for money/score inputs, unsupported ranges, and more than 16 candidates
per decision.

## Policy and hard gates

`RoutingPolicy` has a stable id, semantic version, canonical digest, and:

- allowed channels and optional candidate allow/deny sets;
- minimum reliability, maximum latency, and maximum cost;
- maximum data classification and risk class;
- minimum verification level;
- circuit-breaker threshold/cooldown and minimum history sample count;
- integer weights for reliability, latency, and cost.

The engine evaluates hard gates before scoring. A candidate is ineligible when
any policy, capability, risk, sensitivity, verification, health, or approval
constraint fails. No score can override a hard rejection. Zero eligible
candidates raises a bounded `no_eligible_route` planning failure.

## Health and outcome ledger

Every real adapter Activity attempt produces one bounded `RouteOutcome`:

- tenant, transaction, step, candidate, and Temporal attempt identity;
- `SUCCESS`, `RETRYABLE_FAILURE`, or `TERMINAL_FAILURE`;
- bounded latency and safe failure code;
- timezone-aware occurrence time.

The SQLite store is tenant-scoped and append-only. Replaying the same event and
digest is idempotent; reusing an id with different content is a conflict. Health
aggregation reads a bounded recent window, derives successes, failures,
consecutive failures, integer p95 latency, and circuit state, and never stores
raw transaction input or adapter output.

With insufficient samples, reliability is blended with the candidate baseline
using an explicit prior weight. A circuit opens only from recent consecutive
failures and closes after the configured cooldown. An empty history is
`UNKNOWN`, not fabricated 100% health.

## Deterministic ranking

All scores use integer basis points. Eligible candidates receive:

```text
weighted_score =
  reliability_bps * reliability_weight
  + latency_score_bps * latency_weight
  + cost_score_bps * cost_weight
```

The engine divides by the integer weight sum, then orders by:

1. score descending;
2. static priority ascending;
3. candidate id ascending.

The signed decision binds request, policy digest, candidate profiles, health
snapshots, every rejection reason/component score, selected candidate, ranking,
and evaluation time. Temporal receives this decision; it never recomputes it.

## Safe fallback

The decision may carry ranked fallbacks, but automatic fallback is allowed only
for `READ_ONLY` steps and only when the failed candidate explicitly lists the
safe ApplicationError code. Timeouts or arbitrary exceptions do not silently
fall through unless they were converted to an approved bounded code.

Reversible or consequential writes never auto-fallback because a timeout cannot
prove that no side effect occurred. They retain the existing compensation and
human-review behavior.

Every attempted route is added to `ExecutionSnapshot.route_attempts` with
candidate, adapter, outcome, and safe failure code. The snapshot also includes
the immutable route decision. A fallback success does not erase earlier failed
attempts.

## Synthetic dual-path acceptance

Board 5 adds a separate synthetic official API with the same fixed shipment
records as the browser portal and variants for healthy, server error, malformed
response, not found, and bounded latency. A strict HTTP adapter emits the same
normalized `output.data` shape as the browser adapter and declares
`source_system=synthetic.api`, `channel=API`.

The default policy ranks the API above the browser on cost and latency. Outcome
history can open the API circuit, causing a new transaction to choose the
browser. Board 4's independent `synthetic.ledger` verifies either path at L2.

## Acceptance

1. With empty/healthy history, the API route wins deterministically and its
   normalized output reaches a synthetic L2 `VERIFIED` report.
2. After the configured consecutive API failures, the next plan excludes the
   open circuit and selects the real Playwright browser route; ledger
   verification still reaches L2.
3. Equal scores always resolve by static priority then candidate id.
4. Policy, risk, sensitivity, cost, latency, verification, health, and approval
   gates expose explicit rejection reasons.
5. No eligible route fails planning with a safe error and starts no Workflow.
6. Runtime fallback occurs only for read-only steps and explicitly approved
   codes; writes and unknown failures halt.
7. Outcome recording is idempotent, append-only, tenant-scoped, bounded, and
   does not expose business input/output.
8. Existing static planners and Board 2-4 behavior remain compatible.
9. Full tests, Ruff, strict Mypy, build, wheel smoke, fresh-clone smoke, and
   GitHub CI pass before completion.
