# Board 9 implementation contract

## Goal and truth boundary

Implement one consequential vertical slice: prepare a DCSA-aligned Booking
request, wait for explicit approval, submit it to a synthetic carrier, read it
back through a separate synthetic ledger collector, and cancel it as bounded
compensation when requested.

No real carrier request is sent. All executable defaults use loopback synthetic
services and are labelled `synthetic=True`.

## Standards baseline

- DCSA Booking OpenAPI `2.0.5`.
- Repository `https://github.com/dcsaorg/DCSA-OpenAPI.git`.
- Commit `7767437e7a752437538786e64f2734c95b513d52`.
- Source `bkg/v2/BKG_v2.0.5.yaml`.
- SHA-256 `c5a04f84d37c0086a4ad71aeeb489f87e98d12ad5bd24b0fef5e85d0b9d1400f`.
- Apache-2.0, reused through the existing source manifest and offline checker.

The adapter intentionally supports a reviewed minimum dry-container subset; it
does not claim conformance with every conditional field in the 338 KiB OpenAPI.

## Ownership

- Tera: synthetic carrier persistence/service and controlled fault variants.
- Luna: strict DCSA subset contracts, HTTP execution adapter and separate ledger
  evidence collector.
- Sol: Transaction IR changes, effect-state runtime semantics, booking planner,
  policy/credential integration, worker/server wiring and final acceptance.

## Transaction IR

Add `booking.create` with a `BookingSubject` and typed `BookingParameters`.
Required capabilities are exactly `booking.draft.prepare` then `booking.submit`.
Risk is `CONSEQUENTIAL_WRITE`, required verification is at least L2, and expected
effects are booking request accepted plus independently observed `RECEIVED`.

The existing shipment tracking command and canonical digest remain compatible.
Booking commands reject contradictory route/contract fields, missing POL/POD,
duplicate locations and invalid equipment/weight/party values.

## Execution plan

1. `prepare-booking-draft`: pure local adapter validation, no external effect.
2. `submit-booking`: synthetic DCSA `POST /v2/bookings`, mandatory approval,
   maximum one attempt, consequential risk and optional credential binding.
3. Verification: separate SYSTEM_RECORD collector reads by stable external
   reference and matches that reference plus expected `RECEIVED` status at L2.

Compensation calls DCSA cancellation using the effect reference returned by the
submit step. Compensation has its own capability, policy decision and credential
binding. It may never reuse an unapproved primary-step decision.

## Effect-state rules

- Schema rejection is known pre-effect and halts without compensation.
- A transport/server/protocol failure after submission is `booking_effect_unknown`
  and non-retryable. The Workflow must not resubmit or blindly compensate.
- Unknown effect immediately enters independent reconciliation. A matching
  ledger observation may produce `VERIFIED`; mismatch produces `NEEDS_REVIEW`;
  missing/unavailable evidence produces `HALTED`.
- A successful submit followed by cancellation uses the returned booking request
  reference. Cancellation is idempotent in the synthetic carrier.
- Automatic route fallback remains forbidden for all write steps.

## Synthetic carrier

Use a metadata/business SQLite store shared by two separate local services:

- carrier API: POST/GET/PATCH on `/v2/bookings`;
- ledger API: read-only `/synthetic-ledger/bookings/by-external-reference/{ref}`.

Stable fault modes: normal, reject-before-effect, effect-then-lose-response,
ledger-missing, ledger-conflict and cancellation-failure. The fault header and
endpoints are explicitly synthetic and must not be accepted by a real adapter.

POST is idempotent by the CargoMesh external reference in this synthetic model;
equivalent replay returns the existing request reference, conflicting content
returns 409. This is a test guarantee, not a DCSA-wide claim.

## HTTP boundaries

- exact loopback origin by default; redirects and environment proxies disabled;
- JSON only, bounded request/response sizes and timeouts;
- strict 202 create response containing only `carrierBookingRequestReference`;
- strict GET subset and cancellation response;
- no credentials, cookies, payloads or remote exception text in diagnostics;
- execution and evidence use separate registries and distinct source identities.

## Acceptance

- existing TNT/IR compatibility tests remain green;
- pinned Booking source passes offline digest and endpoint/schema guards;
- draft validation, approval freeze and compensation-policy tests;
- normal submit -> read-back -> `VERIFIED` end-to-end;
- effect-then-response-loss reconciles without a second POST;
- conflict -> `NEEDS_REVIEW`, missing -> `HALTED`;
- cancel signal invokes one idempotent cancellation using the effect reference;
- no approval means no POST; rejected policy means no Workflow;
- full offline tests, ruff, strict mypy, build, clean install, bundle and push.
