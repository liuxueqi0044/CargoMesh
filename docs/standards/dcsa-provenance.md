# DCSA TNT 2.3.0 provenance

CargoMesh vendors the DCSA Track & Trace OpenAPI 2.3.0 specification from
`dcsaorg/DCSA-OpenAPI` commit `7767437e7a752437538786e64f2734c95b513d52`.
The upstream project declares Apache License 2.0, whose exact upstream LICENSE
file is vendored beside the specification.

The TNT document uses remote SwaggerHub references. CargoMesh therefore also
vendors the exact Event Domain 2.0.0, DCSA Domain 2.0.0, and Error Domain 1.0.0
files from the same immutable upstream commit. Those files close the dependency
set needed for the supported `GET /v2/events` query parameters and error shape.
Some event response schemas recursively reference DCSA Documentation and Location
domains; Board 1 does not generate or serve DCSA event responses, so it does not
claim that recursive response-schema resolution is offline yet.

`third_party/dcsa/SOURCES.yaml` is the machine-readable authority for each
vendored file's upstream path, raw immutable URL, repository, commit, license,
and SHA-256. Run `cargomesh-dcsa check` for an offline integrity check. Run
`cargomesh-dcsa sync` only when intentionally retrieving the pinned files; it
downloads through an explicit CLI transport and verifies each digest before
replacing a local file.

Reference-data records are CSV rows with the fields
`namespace,code,name,aliases,version,status,valid_from,valid_to`. Aliases are
pipe-delimited. Validity boundaries are inclusive, and exact `get` lookups do
not silently resolve aliases; callers request alias matching with `suggest`.

Event, shipment-event, equipment-event, transport-event, and document code rows
are transcribed from the enums in the pinned TNT/Event Domain documents. Their
`version` is therefore `2.3.0`; they are not an unpinned copy of a mutable code-list
website.

The separate official `dcsaorg/DCSA-Code-Lists` repository was inspected at commit
`36aef74dc30acd285faec16837d20c3f7af1e6a7` (2026-07-06). At that revision it
contains party-code-list-provider and eBL-solution-provider lists, not these TNT
event enums. CargoMesh therefore does not vendor unrelated CSVs merely to reuse a
repository with a promising name; the OpenAPI enum remains the correct authority.

## DCSA Conformance Framework boundary

CargoMesh reuses the official `dcsaorg/Conformance-Gateway` as an external system
test tool instead of vendoring its Java and Angular implementation. The current
framework is designed to run through Docker or a Java 25+/Maven/Node toolchain.
Board 1 exposes a contract compiler rather than the DCSA event service the
framework expects, so its CI gate is the pinned query-surface guard today. Full
framework scenarios become a release gate when the later adapter/runtime boards
expose an executable DCSA-compatible role.
