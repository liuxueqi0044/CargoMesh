# Board 6 implementation contract

## Purpose

Board 6 establishes the control-plane security boundary required before
CargoMesh adds real credentials, human tasks, or effectful carrier operations.
It authenticates externally issued OIDC access tokens, resolves tenant and
environment membership from CargoMesh-owned data, authorizes explicit actions,
and records bounded append-only audit events. Request bodies are never a source
of identity or authorization.

The existing compiler and synthetic runtime remain usable without access
control for local development. Production-style enforcement is explicit and
fail closed; there is no partially configured permissive mode.

## Reuse decisions

- Reuse an external OIDC provider such as Keycloak or the customer's identity
  provider. CargoMesh never stores passwords, runs login forms, or mints user
  access tokens.
- Reuse PyJWT's maintained JOSE implementation for signature and registered
  claim validation. CargoMesh owns only bounded key retrieval and claim-to-
  principal mapping.
- Reuse the existing HTTPX2 dependency for exact HTTPS JWKS retrieval with
  redirects and environment proxies disabled and a strict response ceiling.
- Reuse Pydantic for immutable principals, memberships, decisions, and audit
  event contracts.
- Reuse SQLite for the single-node membership directory and audit ledger. The
  provider/store protocols deliberately permit a later PostgreSQL replacement.
- Do not embed OpenFGA yet. Seven fixed roles and a small action matrix do not
  justify another service; the authorization request and decision contracts are
  the future OpenFGA boundary.
- Do not trust role, tenant, environment, or approval-actor claims from bearer
  tokens. They are resolved from the server-side membership directory.

## Ownership

```text
architecture, security invariants, API enforcement, final acceptance  Sol
OIDC/JWKS authentication boundary and focused tests                  Tera
membership authorization and append-only audit stores               Luna
```

## Package boundaries

```text
src/cargomesh/controlplane/
├─ models.py          pure identity, membership, action and decision contracts
├─ authentication.py OIDC/JWKS verification; no FastAPI imports
├─ authorization.py  pure role/action evaluation plus membership protocol
├─ membership.py     tenant-scoped SQLite reference directory
├─ audit.py          canonical audit events and append-only hash-chain store
└─ access.py         authentication/authorization/audit orchestration
```

`controlplane.models` and the pure authorization evaluator may not import
FastAPI, HTTP clients, JWT libraries, or SQLite. FastAPI integration remains in
`cargomesh.api`. Raw bearer tokens, JWK private material, credentials, request
bodies, adapter output, and evidence bytes may not enter membership or audit
storage.

## Principal and OIDC contract

An authenticated `Principal` contains only:

- exact issuer and non-empty subject;
- bounded principal type (`HUMAN` or `SERVICE_ACCOUNT` in this board);
- audience and optional client id;
- token issue/expiry times;
- a SHA-256 token identifier used for correlation, never the bearer token or
  raw `jti` value.

The authenticator accepts only an explicitly configured issuer, audience, JWKS
URL, and algorithm allowlist. It requires `iss`, `sub`, `aud`, `iat`, and `exp`;
rejects `none`, symmetric algorithms, missing `kid`, expired/not-yet-valid
tokens, unsupported critical headers, oversized tokens, unknown keys, and
issuer/audience mismatch. Key lookup is bounded and cached. A refresh is
permitted once for an unknown key id; retrieval failure never falls back to an
unverified token.

JWKS retrieval is one exact HTTPS GET with redirects and environment proxies
disabled, JSON media type required, a 64 KiB ceiling, bounded timeout, and no
token attached. Offline tests use an injected static JWKS provider.

## Membership and authorization contract

Membership is keyed by issuer, subject, tenant, environment, and role. The
fixed roles are:

```text
tenant_admin, operator, approver, adapter_developer,
auditor, viewer, service_account
```

Board 6 authorizes these stable actions:

```text
transaction.create
transaction.read
transaction.approve
transaction.cancel
audit.read
membership.manage
```

The role/action matrix is code-reviewed platform policy. A principal may hold
multiple roles and receives their union only inside the exact tenant and
environment membership. No membership is a tenant-scope miss; a membership
without the required action is an explicit denial. Unknown roles/actions and
provider failures deny access.

An immutable `AuthorizationDecision` binds principal identity, tenant,
environment, action, matched roles, allow/deny result, bounded reason code,
membership revision, and decision time into a canonical digest. Evaluation has
no hidden clock or database read: callers provide memberships and time.

The SQLite directory is tenant scoped, uses unique membership keys and an
integer revision, and never stores token claims or secrets. Equivalent
provisioning is idempotent; conflicting role/status changes require an explicit
replacement operation and advance the revision.

## API enforcement contract

`create_app()` accepts an optional access-control service. Its absence preserves
the Board 1–5 local/offline API behavior. When present:

- missing, malformed, or invalid bearer credentials return a bounded 401 and
  `WWW-Authenticate: Bearer`;
- `POST /v1/transactions` authorizes `transaction.create` against the tenant
  in the compiled immutable Transaction IR;
- transaction lookup, approval, and cancellation resolve the stored resource
  tenant before mutation and authorize `read`, `approve`, or `cancel`;
- a caller with no membership in the resource tenant receives the same 404 as
  an unknown transaction, preventing cross-tenant enumeration;
- a same-tenant caller without an action receives a bounded 403;
- an approval actor is derived from the authenticated principal. A
  caller-supplied `decided_by` value is never authoritative;
- contract schemas, capability discovery, reference data, and `/healthz` stay
  public in this board and expose no tenant data.

Runtime wiring exposes one explicit enforcement flag. Enabling it requires a
complete issuer, audience, JWKS URL, membership database, and audit database;
invalid or partial configuration fails at process startup.

## Audit contract

Every authenticated protected request records an `AuditEvent` for its final
allow/deny/error outcome. Events include event id, tenant/environment, actor
reference, action, resource type/id, result, reason code, request/trace id,
authorization decision digest, occurred time, and optional before/after
configuration digests.

The SQLite store is append only and tenant scoped. An event digest binds the
canonical event; each record digest additionally binds the previous record
digest for that tenant, forming independent per-tenant hash chains. Exact replay
is idempotent; reuse of an event id with
different content is a conflict. Verification recomputes the complete selected
tenant chain and reports the first broken sequence.

Audit details reject secret-like keys and values, authorization headers, raw
tokens, cookies, passwords, API keys, filesystem paths, arbitrary exception
messages, transaction input, adapter output, and evidence. Audit write failure
fails the protected operation closed; successful business mutations may not be
reported before their audit record is durable.

## Compatibility and migration

- Transaction response models add `tenant_id`; existing fields and status codes
  remain unchanged when access control is disabled.
- Existing local databases are not rewritten. Board 6 creates separate
  membership and audit databases with explicit schema-version tables.
- Workflow inputs and histories are unchanged; access checks occur before the
  existing application and Temporal boundaries.
- The package version advances to `0.6.0`.

## Acceptance

1. A valid RS256 token from the configured issuer/audience authenticates; bad
   signature, algorithm, issuer, audience, time claims, key id, token size, or
   JWKS response fails closed without leaking token material.
2. Tenant/environment membership and the fixed role matrix deterministically
   allow or deny all six actions; unknown actions deny.
3. Cross-tenant lookup, approval, and cancellation are indistinguishable from a
   missing resource and never call the mutating service method.
4. Same-tenant role denial returns 403; missing/invalid credentials return 401.
5. Approval identity comes from the verified principal, not request JSON.
6. Allowed and denied protected requests produce bounded audit records; no
   token, secret, business payload, adapter output, or evidence enters the
   ledger.
7. Audit replay is idempotent, conflicting ids are rejected, tenant chains are
   independent, and tampering is detected.
8. Access-control or audit-provider failures stop the protected operation; the
   API never silently reverts to disabled mode.
9. Board 1–5 tests remain compatible in explicit local mode, and new unit,
   store, API, and end-to-end security tests run without internet access.
10. `ruff check .`, strict `mypy src`, full `pytest`, wheel build, installed-wheel
    smoke tests, and a fresh-clone test all pass.
