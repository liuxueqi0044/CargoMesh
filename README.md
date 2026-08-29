# CargoMesh

CargoMesh is a business-transaction compiler for container logistics. Board 1
turns a pinned DCSA Track & Trace 2.3 query into deterministic, versioned
Transaction IR. It validates and explains the conversion; it does not claim that
a carrier transaction has been executed.

## Implemented Board 1 surface

| Area | Implementation |
|---|---|
| DCSA source mirror | Immutable commit, per-file URL/license/SHA-256, local `$ref` normalization, offline `check`, explicit `sync` |
| Compatibility | Structural OpenAPI/YAML diff with a non-zero exit for breaking changes |
| Contract guard | Pinned `GET /v2/events` query parameters checked against the Pydantic model |
| Transaction IR | Strict immutable schema, typed date-time predicates, extensions, canonical JSON and digest |
| Mapping | Version/capability registry, bidirectional TNT 2.3 mapping and field-level fidelity diagnostics |
| Migration | Explicit graph, pure v0alpha1 → v1 step, before/after canonical documents and digests |
| Reference data | Version/status/validity model, exact lookup, separate alias suggestions, 44 pinned TNT values |
| HTTP API | Compile, schemas, supported capabilities, reference data, health and stable error envelopes |

The first accepted capability is `shipment.track.read`. Booking writes,
transaction persistence, Temporal orchestration, carrier adapters, evidence and
authentication belong to later boards. Keeping those outside Board 1 prevents a
contract compiler from pretending to be an execution engine.

## Quick start

Requires Python 3.12 and [uv](https://docs.astral.sh/uv/).

```powershell
uv sync --dev
uv run pytest
uv run ruff check .
uv run mypy src
uv run cargomesh-dcsa check
uv run uvicorn cargomesh.api.main:app --reload
```

Swagger UI is then available at `http://127.0.0.1:8000/docs`.

Compile a DCSA query:

```powershell
$body = @{
  sourceSchemaVersion = "dcsa.tnt.query/v2.3"
  payload = @{
    carrierBookingReference = "ABC-123"
    eventType = "SHIPMENT,EQUIPMENT"
    "eventCreatedDateTime:gte" = "2026-08-01T00:00:00Z"
  }
  context = @{ tenant_id = "tenant-a" }
} | ConvertTo-Json -Depth 8

Invoke-RestMethod `
  -Method Post `
  -Uri http://127.0.0.1:8000/v1/ir/compile `
  -ContentType application/json `
  -Body $body
```

The response includes normalized Transaction IR, canonical business JSON, a
`sha256:` business digest, and field-level mapping diagnostics.

## API contracts

- `GET /healthz`
- `GET /v1/capabilities`
- `GET /v1/contracts/transaction-ir/schema`
- `GET /v1/contracts/dcsa-tnt-query-v2.3/schema`
- `POST /v1/ir/compile`
- `GET /v1/reference-data/{namespace}?as_of=YYYY-MM-DD`

The compile request is deliberately explicit and rejects unknown fields:

```json
{
  "sourceSchemaVersion": "dcsa.tnt.query/v2.3",
  "payload": {"transportDocumentReference": "BOL-123"},
  "context": {"tenant_id": "tenant-a"}
}
```

## Standards lifecycle

The production manifest is `third_party/dcsa/SOURCES.yaml`. Normal operation is
offline. Network access occurs only when a developer intentionally runs `sync`:

```powershell
uv run cargomesh-dcsa check
uv run cargomesh-dcsa sync
uv run cargomesh-dcsa diff --baseline old.yaml --candidate new.yaml
```

`diff` prints JSON and exits `2` when it detects a breaking change. Model/source
lockstep is enforced by `tests/standards/test_compatibility.py`.

## Repository map

```text
src/cargomesh/
├─ api/             FastAPI transport and safe error envelopes
├─ application/     compile and reference-data use cases
├─ ir/              Transaction IR, canonicalization and migrations
├─ mapping/         DCSA TNT mapper, diagnostics and registry
└─ standards/       source integrity, compatibility and reference data

third_party/dcsa/   pinned upstream bytes and license
tests/              offline unit, contract and API tests
docs/               architecture decisions, provenance and acceptance record
```

## Build

```powershell
uv build
```

The wheel includes reference CSVs and the pinned DCSA source snapshot, so
`cargomesh-dcsa check` also works after installation outside the source checkout.

## License and upstream reuse

CargoMesh metadata declares Apache-2.0. The vendored DCSA files remain under
DCSA's Apache-2.0 license and retain their exact upstream license and provenance.
See `NOTICE` and `docs/standards/dcsa-provenance.md`.
