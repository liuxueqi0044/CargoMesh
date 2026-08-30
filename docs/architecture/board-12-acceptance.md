# Board 12 acceptance — isolated AI repair lifecycle

## Accepted scope

Board 12 adds an optional, injected repair proposal path for a drifted adapter.
A scoped request and frozen integer budget lead to ephemeral JSON replacements,
base-package verification, TCK/security gates, a time-bounded proposal, verified
human approval, independent canary evidence, promotion or rollback. No model is
present on the healthy execution path.

## Acceptance gates

- Requests permit exact relative JSON files only and bind drift, base package
  and sanitized fixture artifact digests.
- SQLite reserves budget before every unique attempt, freezes request/budget per
  tenant/environment/job, consumes failed attempts conservatively and rejects
  replay, conflict, tampering and cross-tenant lookup.
- The base package is loaded and identity-checked before model invocation.
  Replacements cannot traverse paths, add code or exceed reserved scope.
- Only compatible TCK and security gates can issue a proposal; persisted models
  retain digests and safe codes rather than prompt, output or business payload.
- Lifecycle transitions bind tenant, environment, request and stage subject in
  an append-only verified chain. Skipped or broken links fail closed.
- Approval expiry/attestation, canary proposal identity, independently verified
  integer thresholds, zero invariant violations, promotion scope and rollback
  are enforced before injected deployment calls.
- Ruff, strict mypy, the complete pytest suite, DCSA source verification and
  wheel/sdist builds pass for release `0.12.0`.

## Explicit non-claims

No LLM, prompt store, container/VM sandbox, KMS signer, CI service, artifact
registry or production rollout controller is included. All such systems remain
injected provider boundaries and require separate operational acceptance.
