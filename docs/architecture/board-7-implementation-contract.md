# Board 7 implementation contract

## Purpose

Board 7 separates tenant business policy and secret resolution from routing,
workflows, adapters and HTTP handlers. A policy decision is evaluated before a
plan starts and is frozen into the plan. A credential is represented everywhere
except the trusted executor by an opaque reference. The board does not build an
identity provider, Vault clone, KMS, login UI or policy language.

## Reuse decisions

- Keep the code-reviewed embedded policy engine for offline/default reference
  deployments; provide an OPA-shaped provider interface instead of embedding
  OPA or Rego evaluation in Python.
- Reuse HTTPX2 for an optional exact-URL OPA REST client with redirects and
  environment proxies disabled, JSON content required, bounded timeout and a
  64 KiB response ceiling.
- Reuse Pydantic immutable models and the repository's canonical SHA-256 model
  pattern.
- Reuse SQLite only for non-secret policy sets and credential-binding metadata.
- Reuse `os.environ` only through an explicitly enabled local provider. Do not
  add HashiCorp Vault/AWS/Azure/GCP SDKs; adapters implement a small protocol.
- Do not encrypt secrets into SQLite. Encryption without an externally managed
  root key would merely relocate the secret and create false assurance.

## Ownership

```text
architecture, plan/API integration, security review and final acceptance  Sol
policy contracts, pure evaluator and optional OPA provider                Tera
credential references, bindings, leases and metadata store               Luna
```

## Policy contracts

`PolicyInput` binds tenant, environment, principal reference, transaction
capability, risk class, data classification, requested verification level,
route/channel, adapter and evaluation time. It contains no transaction body.

`PolicyRule` is a bounded reviewed predicate over those enum/name fields and
produces exactly one effect: `ALLOW`, `DENY`, or `REQUIRE_APPROVAL`. Rules have
explicit integer priority and stable rule id; first matching priority wins,
with rule id as deterministic tie-break. No match denies.

`PolicyDecision` binds the full input, policy id/version/digest, result,
matched rule, approval requirements, safe reason code and evaluation time into
a canonical digest. Provider failures never yield allow.

The optional OPA provider sends canonical policy input only. It requires a
strict response schema that includes policy identity and decision fields; the
client independently constructs and validates the CargoMesh decision digest.
It never sends bearer credentials from transaction requests.

## Credential contracts

`SecretRef` contains provider, opaque key and optional version only. It rejects
URI credentials, path traversal, whitespace, inline values and secret-looking
field names. Its digest is safe to persist.

`CredentialBinding` maps exact tenant/environment/adapter/capability to named
secret references and a revision. It never includes resolved bytes. Exact
replay is idempotent; changes require explicit replacement and revision advance.

`SecretProvider.resolve(ref, context)` returns a short-lived `SecretLease`.
The lease exposes named bytes only inside a context manager, has an expiry,
cannot be serialized by Pydantic/JSON, and zeroes its mutable buffers on close
as best-effort process hygiene. Provider exceptions are bounded and never echo
keys or values.

The environment provider requires an explicit allowlist from safe opaque keys
to environment variable names. Arbitrary environment lookup and prefix scans
are forbidden. The in-memory provider exists only for tests/local demos.

## Runtime integration

- Execution plans may contain policy decision digests and credential binding
  references, never resolved secret material.
- The planner evaluates policy once before Temporal starts. DENY rejects the
  submission; REQUIRE_APPROVAL forces an approval boundary even if the route
  candidate did not request one.
- Activities resolve the binding immediately before calling a credential-aware
  executor and close the lease in `finally`.
- Existing adapters continue to implement the secret-free executor protocol.
  A separate credential-aware protocol receives an ephemeral credential view.
- Resolved values may not be added to AdapterInvocation, AdapterResult,
  Temporal exceptions, routing outcomes or audit details.

## Acceptance

1. Every deterministic policy match/tie/default path has a stable digest and
   no-match denies.
2. Provider errors, malformed OPA responses, redirects, oversize bodies and
   identity/digest mismatches fail closed.
3. Policy DENY prevents Workflow submission; REQUIRE_APPROVAL is frozen into
   the execution step.
4. Secret references reject inline/path/credential-like values; models and
   stores contain no resolved material.
5. Credential binding replay/conflict/revision and tenant/environment isolation
   are tested.
6. Environment resolution is allowlist-only; leases expire, close on success
   and exception, and best-effort wipe buffers.
7. Adapter failures and logs cannot reveal resolved values; missing providers
   stop execution with a bounded safe code.
8. Board 1–6 behavior remains compatible when no policy/credential providers
   are configured.
9. Ruff, strict mypy, full pytest, build, installed-wheel and clean-clone gates
   pass offline.
