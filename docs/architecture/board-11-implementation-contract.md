# Board 11 implementation contract — deterministic Adapter Factory

## Goal and reuse boundary

Turn a metadata-only demonstration plus a human-reviewed structured SOP into a
restricted adapter package, then qualify that exact package through a
deterministic Adapter TCK. The factory reuses CargoMesh's existing
`AdapterManifest`, `BrowserRecipe`, semantic locator, package loader and
synthetic portal contracts. It does not generate Python, JavaScript, CSS,
XPath, arbitrary browser commands or a second adapter runtime.

## Capture and reviewed specification

- A capture contains a query-free same-origin path, a page-signature digest and
  semantic actions. Fill/select actions retain parameter names, never values.
- Screenshots, HTML, raw payloads, credentials and free-text SOP instructions
  are not representable.
- A reviewed SOP is structured and digest-bound. Its declared parameters must
  exactly match its bindable actions.
- Every parameter binding requires independent evidence references with a
  consistent value digest.
- Missing/conflicting evidence, unsupported parameters and missing actions are
  hard blockers. Choosing an action cannot resolve an evidence blocker.
- A human `Resolution` may choose only among reviewed SOP action candidates.
  READY/CERTIFIED specifications require nonempty executable bindings and no
  unresolved ambiguity.

## Restricted package construction

- Only READY/CERTIFIED specifications enter the builder.
- The builder emits one read-only `BrowserRecipe` and `AdapterManifest` using
  the existing contracts and input JSON pointers.
- Canonical in-memory bytes and per-file/package SHA-256 identities are
  returned. Persistence remains a caller-owned boundary.
- The current safe subset supports fill bindings and result extraction; select,
  click, write operations and executable-code generation fail closed.

## TCK, drift and certification

- A digest-bound suite declares expected outcomes for healthy and fault portal
  variants, including security-critical cases.
- Observations must cover each case exactly once. Compatibility requires every
  actual outcome to match its frozen expected outcome.
- Drift reports bind the package, distinct signature digests and changed
  semantic identifiers without retaining page content.
- Certification binds specification, package, suite and report digests. The
  exact package must be compatible and the report must contain passing
  security-critical coverage.

## External blockers and non-claims

The repository does not record a real browser session, inspect a third-party
portal, obtain portal permission, distribute generated packages or certify a
carrier integration. Those require external systems and human authorization.
