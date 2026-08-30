# Board 13 implementation contract — platform hardening and commercial surfaces

## Goal and reuse boundary

Complete the repository-level platform contracts needed to operate and package
CargoMesh without claiming cloud infrastructure or a finished commercial
marketplace. Reuse OpenTelemetry semantic naming, CycloneDX/SLSA-shaped
documents, SQLite's online backup API and the verification/TCK/certification
digests already present in CargoMesh. Do not build a second workflow, identity,
deployment or payment system.

## Payload-free telemetry and SLOs

- An allowlist defines CargoMesh resource/span/metric attributes. Values are
  bounded identifiers, enums, integer counters or digests; transaction input,
  evidence claims, URLs, credentials and exception text are forbidden.
- Export is an injected provider boundary. The core emits no network telemetry.
- SLO windows use integer event counts and durations with deterministic burn
  rates. Missing samples do not become success. Alert decisions are immutable,
  digest-bound and explain their bounded reason codes.

## Supply-chain evidence

- A deterministic CycloneDX-shaped SBOM records pinned components, versions,
  licenses, package URLs and artifact digests.
- SLSA/in-toto-shaped provenance binds source revision, builder identity,
  dependency/material digests and release artifact digests.
- Adapter attestations bind an exact adapter package, Board 11 certification,
  TCK suite/report and provenance identities.
- Signatures and key custody are injected verifier/signer boundaries. An
  unsigned digest record must never be described as cryptographically signed.

## Backup, restore and deployment profiles

- The reference backup service uses SQLite's consistent backup API, explicit
  resolved file targets and SHA-256 manifests. Restore writes only to a new,
  caller-selected file and verifies integrity and application identity before
  returning success.
- Local and private deployment profiles validate database, artifact, TLS,
  ingress/egress, secret-provider and runner requirements. Developer/local
  profiles are explicitly not production-ready.
- Configuration output contains secret references only. No cloud/Kubernetes
  resource is created and no certificate or secret is provisioned.

## Usage and marketplace boundaries

- Usage is recorded once per tenant/environment/transaction only after an
  existing `VERIFIED` report. Executed-unverified, halted, review and failed
  states are never billable.
- Meter records retain capability, verification/report digests and integer
  units only—never transaction inputs, evidence claims or prices.
- Marketplace catalog entries bind publisher metadata, adapter package,
  certification, SBOM/provenance/attestation and compatibility range.
- Publication/installation eligibility is deterministic and fail closed when a
  required identity or accepted certification is absent.
- Payment, tax, payout, contracts, legal approval, malware hosting and package
  distribution are external integrations and are not simulated.

## Acceptance truth boundary

Reference tests prove local deterministic behavior, isolation, replay and
tamper rejection. Production SLO values, real signed releases, disaster
recovery objectives, cloud rollout and commercial authorization remain
external acceptance blockers.
