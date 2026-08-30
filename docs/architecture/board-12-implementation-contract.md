# Board 12 implementation contract — isolated AI repair lifecycle

## Goal and governing invariant

Turn a Board 11 drift report into a bounded repair proposal without granting a
model credentials, network access or a production mutation path. AI is an
optional, injected proposal source. It is never used on a healthy execution
path and can never certify, approve, deploy or declare its own output safe.

## Repair request and budget

- A digest-bound request identifies tenant/environment, drift report, current
  package and a separately sanitized fixture artifact by digest only.
- The allowlist names exact relative adapter JSON files. Python, JavaScript,
  absolute paths, traversal, symlinks and unlisted files are forbidden.
- A frozen budget limits model calls, input/output tokens, integer cost units,
  file count, total candidate bytes and validation duration.
- A tenant-scoped SQLite budget ledger reserves before a call and finalizes
  actual usage. Replays are idempotent; conflicting or over-budget reservations
  fail closed. No prompt, response, credential or business payload is stored.

## Candidate isolation

- The injected model gateway receives only the repair request, safe diagnostic
  codes and sanitized artifact references. It returns bounded adapter JSON file
  replacements plus usage metadata.
- Base files come from an injected read-only provider. Candidate base digests
  must match before replacement.
- An isolated workspace validates JSON syntax, canonical package loading,
  path/size scope, the full compatible TCK and security gates. Candidate bytes
  are ephemeral; durable contracts retain identities and bounded result codes.
- Network and production credentials are not present in the validator
  protocol. The reference implementation performs no subprocess or network IO.

## Human proposal, canary and rollback

- Only a fully passing validation report may produce a time-bounded proposal.
- Approval is a separate digest-bound attestation from a verified principal;
  an injected verifier checks that attestation and request scope.
- Approval enables a canary request, not full promotion. Canary evidence must
  be independently verified and satisfy frozen integer thresholds with zero
  safety-invariant violations.
- Promotion is an injected deployment boundary. Any failed canary or promotion
  check produces a rollback instruction bound to the previous package digest.
- Terminal and intermediate transitions are append-only/digest-linked; retries
  cannot skip generation, validation, proposal, approval or canary states.

## Reuse and non-claims

The lifecycle reuses Board 11 package/TCK identities and existing adapter
contracts. It does not implement an LLM provider, container sandbox, signing
service, artifact store, CI system, rollout controller or production adapter
deployment. These remain injected and require external credentials and policy.
