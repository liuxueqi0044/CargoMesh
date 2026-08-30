# Board 9 acceptance — verified synthetic Booking write

## Accepted scope

- Pinned DCSA Booking OpenAPI 2.0.5 at the recorded upstream commit and digest.
- Strict `booking.create` Transaction IR for the reviewed dry-container subset.
- Pure draft preflight followed by a mandatory-approval consequential submit.
- Credential-aware POST/GET/PATCH adapter with exact status and response bounds.
- SQLite synthetic carrier with exact external-reference idempotency and faults.
- Separate read-only ledger collector and L2 claim verification.
- Single-attempt unknown-effect reconciliation with no automatic route fallback.
- Reference-bound, separately authorized and credentialed cancellation.
- Explicit local worker/API flags, policy rules and synthetic credential provider.

## Safety acceptance

- A response-loss error cannot issue a second POST or a blind cancellation.
- Compensation without a recorded effect reference halts before adapter invocation.
- Submit, cancel and draft each receive their own frozen policy decision.
- The carrier-facing request uses DCSA field names; CargoMesh idempotency stays in
  the synthetic `Idempotency-Key` header.
- Carrier GET is DCSA-shaped; CargoMesh provenance exists only on the separate
  synthetic ledger surface.
- All defaults are loopback and explicitly synthetic. No real booking was made.

## Verification record

The Board 9 test suite covers the pinned contract, IR invariants, draft planning,
policy and credential freezing, carrier idempotency/conflicts/faults, strict HTTP
adapter behavior, independent ledger parsing, L2 end-to-end verification,
unknown-effect workflow recovery and reference-bound compensation.

External carrier accounts, customer identity/policy/secret providers, legal
permission, production Temporal hosting and carrier certification remain external
acceptance blockers.
