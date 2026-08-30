# Board 10 implementation contract — bounded additional channels

## Goal and truth boundary

Add EDI, document/email ingestion and attended-human execution as strict local
contracts that compile into the existing `ExecutionPlan`. The repository does
not connect to a mailbox, trading partner, AS2/SFTP endpoint, messaging service
or workforce product. Those integrations remain injected provider boundaries.

## EDI boundary

- Parse a bounded EDIFACT interchange with optional UNA, one UNB/UNZ envelope
  and one or more balanced UNH/UNT messages.
- Validate charset, size, segment/element counts, message/control references and
  declared totals before issuing metadata.
- Retain only structural metadata and SHA-256 identities, never business element
  values or raw interchange text.
- Provide an `EDITransport` protocol; do not implement network transport.

## MIME/PDF ingestion boundary

- Parse MIME with explicit byte, header, depth, part and attachment ceilings.
- Return filename/media-type/size/digest summaries only; message bodies and
  attachment bytes never enter the returned model.
- Quarantine malformed encoding, duplicate critical headers, scanner failures,
  encrypted/active PDF indicators and all over-budget inputs.
- PDF inspection is a bounded preflight, not a claim of full PDF validation.
- Content scanning is injected and unavailable scanning fails closed.

## Attended-human boundary

- Human tasks are tenant/environment/transaction scoped, digest-bound and free
  of secret-like instruction fields.
- Claims use time-bounded leases and monotonically increasing fencing tokens.
- Completion/rejection is single-owner, terminal and exactly matches the
  required bounded scalar claim set.
- Only a verified principal reference may claim or complete a task.
- A completed task may issue an attended SYSTEM_RECORD evidence observation;
  it never masquerades as independent carrier evidence.

## Execution plan integration

`ChannelStepSpec` supports only EDI or HUMAN channels. Effectful steps require
approval, one attempt and no automatic fallback. Inputs contain metadata and
artifact digests only. Verification is always supplied explicitly by the
caller; the compiler cannot assert success or create evidence by itself.

## External blockers

Real partner connectivity, mailbox permissions, malware service credentials,
PDF conformance certification, human-task notification delivery and production
data retention are not available in this repository and are not claimed.
