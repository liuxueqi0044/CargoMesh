# Board 10 acceptance — bounded additional channels

## Accepted scope

Board 10 adds four offline, composable boundaries:

- a bounded EDIFACT envelope/message parser and injected transport protocol;
- fail-closed MIME/PDF metadata ingestion with an injected content scanner;
- tenant- and environment-scoped attended-human tasks with leased fencing;
- deterministic EDI/HUMAN step compilation into the existing execution plan.

All returned contracts are immutable and digest-bound. Raw EDI, MIME body,
attachment bytes, PDF bytes, credentials and human notes are not persisted in
the returned models. Human output is marked as synthetic attended
`SYSTEM_RECORD` evidence and cannot be mistaken for independent carrier proof.

## Acceptance gates

- Valid and malformed EDIFACT fixtures cover envelope, message, reference,
  count, nesting, character, byte and element limits.
- MIME tests cover size/depth/part limits, malformed encodings, duplicate
  critical headers, sanitized filenames and fail-closed scanner behavior.
- PDF preflight rejects malformed, encrypted and active-content indicators.
- SQLite attended tasks cover idempotent creation, tenant isolation, expiring
  claims, monotonic fencing, exact claim sets and terminal replay/conflict.
- Channel compilation rejects secrets and raw documents, requires approval and
  a single attempt for effectful work, and never manufactures verification.
- Ruff, strict mypy, the complete pytest suite, DCSA source verification and
  wheel/sdist builds pass for release `0.10.0`.

## Explicit non-claims

No mailbox, malware service, AS2/SFTP partner, workforce UI, notification
system, OCR engine or real EDI endpoint is included. The PDF check is a bounded
active-content preflight, not full conformance or malware certification.
