# Board 13 acceptance — platform hardening and commercial surfaces

## Accepted scope

Board 13 completes repository-level platform contracts for payload-free
telemetry and SLOs, deterministic supply-chain evidence, safe SQLite
backup/restore, local/private deployment configuration, verified-only usage
metering and an evidence-gated adapter catalog.

## Acceptance gates

- Telemetry accepts only fixed signal names and attributes with bounded safe
  scalar values. Export is injected and failures cannot leak exporter text.
- SLO reports recompute integer rates/burn from source counts. Missing samples
  and invalid windows alert rather than silently becoming healthy.
- CycloneDX 1.6 and SLSA/in-toto-shaped documents are canonical and reject
  duplicate identities. Attestation signatures bind exact canonical bytes.
- Marketplace publication binds publisher/capability in the signed publication
  payload and verifies exact package, Board 11 certification, security TCK,
  SBOM root artifact and provenance release artifact identities.
- SQLite backup uses the online backup API. Manifest, byte digest, integrity,
  application identity and user version are revalidated; restore never
  overwrites a destination and cleans only its own failed target.
- Local deployment is explicitly non-production. Private configuration reuses
  the Board 8 runner profile, requires mTLS/external secrets and is labelled
  configuration-complete but not deployed or production-ready.
- Usage metering accepts only digest-valid, non-synthetic VERIFIED reports,
  prevents report reuse across tenant scopes and stores no claims, inputs,
  prices or business payload.
- Ruff, strict mypy, the complete pytest suite, DCSA source verification and
  wheel/sdist builds pass for release `0.13.0`.

## Explicit non-claims

No telemetry backend, KMS key, cloud/Kubernetes resource, certificate, external
artifact registry, disaster-recovery SLA, package distributor, payment/tax/
payout system or legal approval is provided. The local contracts do not prove
that an external production deployment or commercial listing is authorized.
