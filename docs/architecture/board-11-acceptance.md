# Board 11 acceptance — deterministic Adapter Factory

## Accepted scope

Board 11 supplies a safe factory pipeline from demonstration metadata and a
reviewed SOP to canonical existing-format adapter bytes, plus an Adapter TCK,
drift report and package certification record. The package is read-only and
contains parameter pointers rather than captured business values.

## Acceptance gates

- Capture tests reject external/query-bearing paths, unsupported locator kinds,
  raw-content fields and secret-like metadata.
- Compiler tests require evidence for every binding, distinguish hard evidence
  blockers from human-resolvable locator choices and prevent false READY state.
- Package tests prove deterministic bytes/digests, existing loader round-trip,
  absence of evidence/business values and fail-closed unsupported actions.
- TCK tests require exact case coverage and outcomes, detect drift and bind all
  reports to package/suite identities.
- Certification rejects package mismatch, incompatible reports and suites with
  no passing security-critical coverage.
- Ruff, strict mypy, the complete pytest suite, DCSA source verification and
  wheel/sdist builds pass for release `0.11.0`.

## Explicit non-claims

No real portal was captured or certified. No generated package was installed,
published or executed against a carrier. The synthetic TCK is a reusable local
contract, not evidence of external interoperability.
