# Board 1 implementation contract

## Supported baseline

- DCSA Track & Trace OpenAPI 2.3.0 from `dcsaorg/DCSA-OpenAPI`.
- Upstream commit pinned in `third_party/dcsa/SOURCES.yaml`.
- CargoMesh Transaction IR `cargomesh.transaction/v1`.
- Initial business capability: `shipment.track.read`.

TNT 3.0 is currently a beta upstream contract and is not a production baseline here.

## Package ownership

```text
cargomesh.ir          Sol
cargomesh.mapping     Sol
cargomesh.standards   Tera
cargomesh.api         Luna
```

## IR public contract

`TransactionCommand` must contain:

- `schema_version = cargomesh.transaction/v1`;
- tenant and optional caller-supplied transaction id;
- `transaction_type = shipment.track` for the first vertical slice;
- an external reference;
- a typed `ShipmentSubject` with at least one DCSA reference;
- typed track filters;
- requested business effects;
- verification requirements and risk class;
- namespaced extensions.

Canonicalization must:

- use deterministic JSON with sorted keys and compact separators;
- normalize UTC datetimes to `Z`;
- exclude `transaction_id` and `requested_at` from the business digest;
- preserve meaningful empty collections only where the model emits them;
- return a `sha256:<lowercase hex>` digest.

## Mapping public contract

`DCSATNTQueryV2` uses DCSA aliases and requires at least one supported subject
reference, including:

- `carrierBookingReference`;
- `bookingReference`;
- `transportDocumentID`;
- `transportDocumentReference`;
- `equipmentReference`;
- `scheduleID`;
- `transportCallID`.

Date-time comparison suffixes are represented as typed IR predicates and must
survive a supported round trip.

The mapper returns `MappingResult[TransactionCommand]` with field-level diagnostics.
Diagnostic fidelity is one of `EXACT`, `NORMALIZED`, `DEFAULTED`, `PARTIAL`, or
`UNSUPPORTED`. Critical `PARTIAL`/`UNSUPPORTED` mappings fail compilation.

## Standards public contract

The standards package must provide:

- typed source-manifest loading;
- local digest verification without network;
- explicit synchronization through an injected/downloader boundary;
- license/provenance metadata;
- versioned reference-data records, exact lookup, alias suggestions, and temporal validity.

Tests must use local fixtures. The production manifest may point at pinned raw GitHub URLs.

## API public contract

Board 1 provides:

- `GET /healthz`;
- `GET /v1/capabilities`;
- `GET /v1/contracts/transaction-ir/schema`;
- `GET /v1/contracts/dcsa-tnt-query-v2.3/schema`;
- `POST /v1/ir/compile`;
- `GET /v1/reference-data/{namespace}`.

`POST /v1/ir/compile` accepts either CargoMesh IR v1 or a DCSA TNT 2.3 query and returns:

- validated normalized Transaction IR;
- canonical business JSON;
- deterministic digest;
- mapping diagnostics;
- source and target schema versions.

It must not pretend to execute or persist a production transaction.

## Acceptance

1. A DCSA TNT query compiles to IR and round-trips through the supported mapper.
2. Equivalent JSON key order and timezone offsets produce the same business digest.
3. Invalid extension namespaces and ambiguous subjects fail closed.
4. A modified pinned DCSA file fails digest verification.
5. Reference data supports historical validity and exact/alias distinction.
6. API errors have stable codes and never expose Python tracebacks.
7. `pytest`, `ruff`, and strict `mypy` pass without network access.
