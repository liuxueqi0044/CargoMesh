# CargoMesh remaining code roadmap (v0.7–v0.13)

## Completion boundary

Boards 1–6 established the DCSA/IR compiler, durable runtime, deterministic
browser adapters, independent verification, route optimization, and the
multi-tenant authentication/authorization/audit boundary. This roadmap closes
all remaining implementation work that can be completed safely without a real
carrier account, customer credentials, a paid identity/policy service, legal
authorization to automate a third-party portal, or a production Kubernetes/
cloud account.

“Complete” means a production-shaped, offline-testable reference boundary with
real local execution where that is safe. It never means that a synthetic
carrier, local secret provider, in-process runner, fake document, or test model
is a certified external integration.

## Weighted roadmap

| Board | Version | Weight | Deliverable |
|---|---:|---:|---|
| 7 | 0.7.0 | 12% | Tenant business policy, approval gates, credential references and secret-provider boundary |
| 8 | 0.8.0 | 16% | Private Runner identity, registration, task leasing, heartbeat, recovery and artifact relay contracts |
| 9 | 0.9.0 | 18% | Consequential DCSA Booking draft/approve/submit/verify/compensate vertical slice against a synthetic carrier |
| 10 | 0.10.0 | 12% | EDI, bounded document/email ingestion and attended-human task execution channels |
| 11 | 0.11.0 | 16% | Deterministic domain-binding compiler, capture/SOP import, Adapter TCK and drift/fault workbench |
| 12 | 0.12.0 | 14% | Isolated AI repair proposal, budget, patch validation, approval, canary and rollback lifecycle |
| 13 | 0.13.0 | 12% | OpenTelemetry semantics, SLOs, supply-chain attestations, backup/restore, deployment profiles, usage and marketplace contracts |

Weights describe the remaining code programme, not total commercial product
maturity. Every board is an additive release and must leave `main` releasable.

## Cross-board invariants

- Production transaction execution is deterministic; model output never runs
  directly in a production transaction.
- Secrets are referenced by opaque identifiers and resolved only at the final
  trusted execution boundary. They never enter IR, Temporal history, audit,
  logs, routing outcomes, evidence, artifacts, or API responses.
- Consequential writes require explicit policy allowance, verified human or
  service identity, idempotency, an approval boundary when policy requires it,
  and independent result verification.
- Unknown effect state is `NEEDS_REVIEW` or `HALTED`, never success and never an
  automatic retry through another route.
- Tenant, environment, adapter, runner, policy, artifact and usage records are
  digest-bound and scope-checked at every provider boundary.
- External-provider failures fail closed. Local development substitutes are
  explicit and cannot silently become production defaults.
- New protocols have provider interfaces so PostgreSQL, Vault, OPA, object
  storage, message brokers and remote runners can replace single-node reference
  implementations without changing domain contracts.
- Tests remain offline. Network behavior uses local services or injected
  transports; real-account acceptance is separately blocked and documented.

## Board 7 — policy and credentials

Own immutable business-policy requests/decisions, a deterministic embedded
policy evaluator, an OPA-compatible provider boundary, metadata-only policy
storage, opaque credential bindings, short-lived secret leases, and strict
environment/in-memory reference providers. Freeze policy decisions into plans;
never fetch policy during Temporal replay.

## Board 8 — Private Runner

Own runner identity and enrollment, one-time registration challenges, pinned
public-key identity, scoped capabilities, long-poll task leases, lease fencing,
heartbeat/offline state, idempotent result receipt, artifact metadata relay and
version/upgrade policy. The reference transport is in-process/SQLite and does
not claim to provide production mTLS termination.

## Board 9 — verified Booking write

Add one consequential capability only: booking draft creation and explicit
submission. Use a pinned, documented DCSA-aligned booking contract, a separate
synthetic carrier process, mandatory approval, idempotent submit, independent
read-back evidence, bounded compensation, and unknown-effect fault injection.
No real booking is sent.

## Board 10 — additional channels

Add strict EDI envelope/document contracts, safe MIME/PDF metadata extraction,
quarantine and content limits, and attended-human task claims/completion. These
channels compile to the same ExecutionPlan and evidence contracts. Email send,
mailbox access and trading-partner connectivity remain injected provider
boundaries.

## Board 11 — Adapter Factory

Import a bounded normalized demonstration/capture or reviewed SOP, infer only
evidence-supported parameters, produce a reviewable binding specification and
restricted adapter package, execute the complete Adapter TCK against synthetic
portal variants, compute compatibility/reliability results, and detect drift.
Ambiguous bindings require human resolution.

## Board 12 — AI repair lifecycle

Accept a drift report and frozen sanitized test fixture, issue a bounded repair
job to an injected model gateway, require structured candidate patches, reject
out-of-scope changes, run TCK and security gates in an isolated workspace,
produce a signed review proposal, and support approval, canary promotion,
automatic rollback and budget exhaustion. No model call exists on the healthy
production path.

## Board 13 — platform hardening and commercial surfaces

Define CargoMesh OpenTelemetry attributes without secret/business payloads,
derive SLO windows and alerts, produce SBOM/provenance/adapter attestations,
verify backup/restore, publish local/private deployment profiles, meter only
verified outcomes, and implement marketplace package/catalog/certification
contracts. Payment collection, cloud infrastructure creation and legal adapter
approval remain external integrations.

## External acceptance blockers

The following cannot be truthfully completed from this repository alone:

- a real carrier booking or production portal acceptance test;
- customer IdP/Vault/OPA/KMS configuration and key custody;
- legal permission and terms-of-service review for automation;
- production mTLS certificates, DNS, ingress and Kubernetes/cloud rollout;
- real mailbox, AS2/SFTP/EDI partner, payment processor or marketplace payout;
- commercial pricing, support SLA and data-retention decisions.

Each corresponding code path will have a provider contract, strict configuration
validation, local conformance tests and an explicit acceptance-blocker record.
