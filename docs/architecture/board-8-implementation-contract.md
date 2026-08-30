# Board 8 implementation contract

## Goal

Board 8 adds the control/data contracts for a customer-network Private Runner.
The deliverable is a real offline SQLite/in-process reference transport. It is
not a claim that this repository terminates production mTLS, launches hardened
containers/VMs, or manages customer PKI.

## Ownership

- Tera: runner enrollment, pinned identity, registry, revocation, health state.
- Luna: task queue, leasing/fencing, heartbeat, recovery, result receipts.
- Sol: sandbox/session/update/deployment policy, artifact relay, integration,
  threat review and final acceptance.

Agents must stay inside their assigned modules and tests. Sol owns public exports
and cross-module changes.

## Package boundaries

```text
cargomesh.runner.identity     one-time enrollment and public-key identity
cargomesh.runner.registry     metadata-only SQLite runner registry
cargomesh.runner.tasks        task/lease/heartbeat/result contracts
cargomesh.runner.task_store   atomic SQLite task transport
cargomesh.runner.artifacts    bounded metadata relay and injected blob sink
cargomesh.runner.security     sandbox, browser session and egress contracts
cargomesh.runner.release      version compatibility and signed-update policy
```

No module imports FastAPI, Temporal, Playwright or a cloud SDK. SQLite stores
metadata only. Blob storage, CA/certificate issuance, containers and remote
transport are provider boundaries.

## 1. Enrollment and identity

- An enrollment challenge is random, one-time, short-lived and scoped to exactly
  one tenant, environment and runner pool.
- The database stores only a SHA-256 token digest. The plaintext token is exposed
  once through a non-serializable object with a secret-free `repr`.
- Enrollment accepts a runner-generated public-key digest; it never accepts or
  transports a private key.
- A runner identity freezes runner id, tenant, environment, pool, opaque task
  queue id, public-key digest, capabilities, platform and version.
- Reusing, expiring or scope-changing a token fails closed. Re-enrollment creates
  a new identity. Revocation prevents task acquisition and future heartbeats.
- This reference pins key identity but does not issue an X.509 certificate.

## 2. Task transport and recovery

- A task is scoped to tenant/environment/pool/capability and binds execution id,
  adapter digest, policy digest, input digest, deadline and a bounded payload
  containing no secret-like keys.
- Acquisition is atomic and verifies the registered runner scope, capability,
  health and revocation state.
- Each acquisition increments a monotonic fencing token. Expired tasks may be
  reacquired; stale renewals, heartbeats and results are rejected.
- Heartbeats contain step id, effect-boundary flag, checkpoint digest, artifact
  upload counts and session liveness only—never business input or secret values.
- Recovery is deterministic: pre-effect expiry may retry from a checkpoint;
  post-effect or ambiguous expiry requires verification/reconciliation.
- Result receipts are digest-bound and idempotent. An equivalent replay succeeds;
  a different result for the same fenced lease conflicts.

## 3. Artifact relay

- Adapters submit bytes only to an injected relay. They receive no object-store
  credentials.
- Policy uses an explicit artifact type, exact MIME allowlist, classification and
  maximum size. Filename extensions never determine policy.
- The relay computes SHA-256 while enforcing limits, sends bytes to an injected
  sink and persists/returns only metadata plus opaque storage reference.
- Payloads marked sensitive or requiring unavailable redaction fail closed.
- Blob sinks must be idempotent by digest. Errors and receipts contain no content,
  path, signed URL or credential.

## 4. Execution security and release policy

- Sandbox specifications freeze CPU/memory/disk/process/deadline limits, isolation
  class, read-only root, writable work area and exact egress host/port allowlist.
- Consequential writes require container or VM isolation and a non-empty egress
  allowlist. AI repair is forbidden in a production runner pool.
- Browser sessions are explicitly `EPHEMERAL`, `SEALED_STORAGE_STATE` or
  `ATTENDED`; session leases contain only opaque profile references and scope.
- Runner versions and adapter SDK ranges use deterministic SemVer compatibility.
  Updates must reference a digest and signature identity; arbitrary scripts are
  never accepted. Drain/canary/rollback are explicit states.
- Deployment profiles identify unmet controls. `developer` is never production
  capable; `standard` and `regulated` remain declarations until their external
  mTLS/container/VM/storage controls are actually supplied.

## Acceptance

- one-time/expiry/scope/revocation enrollment tests;
- no private key or plaintext token in models, SQLite, errors or repr;
- concurrent single-winner acquisition and monotonic fencing;
- stale lease, post-effect recovery and idempotent/conflicting result tests;
- artifact MIME/size/classification/digest/idempotency and secret-free errors;
- sandbox/session/version/deployment validation tests;
- `ruff check .`, `mypy src`, full `pytest`, build and clean install;
- version `0.8.0`, local commit, verified Git bundle, GitHub push and remote SHA check.
