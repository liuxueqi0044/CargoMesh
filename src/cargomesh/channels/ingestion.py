"""Bounded, metadata-only MIME and PDF ingestion with fail-closed quarantine."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from email import policy as email_policy
from email.message import Message
from email.parser import BytesParser
from enum import Enum, StrEnum
from typing import Annotated, Literal, Protocol, cast

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

INGESTION_POLICY_SCHEMA_VERSION: Literal["cargomesh.ingestion-policy/v1"] = (
    "cargomesh.ingestion-policy/v1"
)
MESSAGE_SUMMARY_SCHEMA_VERSION: Literal["cargomesh.message-summary/v1"] = (
    "cargomesh.message-summary/v1"
)
ATTACHMENT_SUMMARY_SCHEMA_VERSION: Literal["cargomesh.attachment-summary/v1"] = (
    "cargomesh.attachment-summary/v1"
)
QUARANTINE_RECORD_SCHEMA_VERSION: Literal["cargomesh.quarantine-record/v1"] = (
    "cargomesh.quarantine-record/v1"
)
INGESTION_DECISION_SCHEMA_VERSION: Literal["cargomesh.ingestion-decision/v1"] = (
    "cargomesh.ingestion-decision/v1"
)

IngestionName = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=128,
        pattern=r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$",
    ),
]
Sha256Digest = Annotated[str, StringConstraints(pattern=r"^sha256:[0-9a-f]{64}$")]
SafeFilename = Annotated[
    str, StringConstraints(strip_whitespace=True, min_length=1, max_length=128)
]

_CRITICAL_HEADERS = frozenset(
    {"content-transfer-encoding", "content-type", "mime-version", "message-id"}
)
_TRANSFER_ENCODINGS = frozenset(
    {"7bit", "8bit", "binary", "base64", "quoted-printable"}
)
_PDF_ACTIVE_TOKENS = (b"/javascript", b"/js ", b"/launch", b"/embeddedfiles", b"/filespec")


class IngestionModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class IngestionDisposition(StrEnum):
    ACCEPT = "ACCEPT"
    QUARANTINE = "QUARANTINE"


class IngestionPolicy(IngestionModel):
    """The bounded parser budget; no value permits an unbounded content path."""

    schema_version: Literal["cargomesh.ingestion-policy/v1"] = INGESTION_POLICY_SCHEMA_VERSION
    max_total_bytes: int = Field(default=10 * 1024 * 1024, ge=1, le=50 * 1024 * 1024)
    max_headers: int = Field(default=128, ge=1, le=1024)
    max_header_bytes: int = Field(default=16 * 1024, ge=64, le=256 * 1024)
    max_mime_depth: int = Field(default=8, ge=0, le=32)
    max_parts: int = Field(default=64, ge=1, le=512)
    max_attachments: int = Field(default=16, ge=0, le=128)
    max_attachment_bytes: int = Field(default=5 * 1024 * 1024, ge=1, le=25 * 1024 * 1024)
    policy_digest: Sha256Digest

    @model_validator(mode="after")
    def validate_digest(self) -> IngestionPolicy:
        if self.max_attachment_bytes > self.max_total_bytes:
            raise ValueError("attachment limit cannot exceed total message limit")
        if self.policy_digest != model_digest(self, exclude={"policy_digest"}):
            raise ValueError("ingestion policy digest does not match")
        return self

    @classmethod
    def issue(cls, **values: object) -> IngestionPolicy:
        return cast(
            IngestionPolicy,
            _issue(cls, values, "policy_digest", INGESTION_POLICY_SCHEMA_VERSION),
        )


class AttachmentSummary(IngestionModel):
    schema_version: Literal["cargomesh.attachment-summary/v1"] = (
        ATTACHMENT_SUMMARY_SCHEMA_VERSION
    )
    attachment_index: int = Field(ge=1, le=128)
    filename: SafeFilename
    media_type: IngestionName
    byte_length: int = Field(ge=0, le=25 * 1024 * 1024)
    content_digest: Sha256Digest
    attachment_digest: Sha256Digest

    @model_validator(mode="after")
    def validate_digest(self) -> AttachmentSummary:
        if self.attachment_digest != model_digest(self, exclude={"attachment_digest"}):
            raise ValueError("attachment summary digest does not match")
        return self

    @classmethod
    def issue(cls, **values: object) -> AttachmentSummary:
        return cast(
            AttachmentSummary,
            _issue(cls, values, "attachment_digest", ATTACHMENT_SUMMARY_SCHEMA_VERSION),
        )


class MessageSummary(IngestionModel):
    schema_version: Literal["cargomesh.message-summary/v1"] = MESSAGE_SUMMARY_SCHEMA_VERSION
    message_digest: Sha256Digest
    byte_length: int = Field(ge=0, le=50 * 1024 * 1024)
    top_level_media_type: IngestionName
    header_count: int = Field(ge=0, le=1024)
    part_count: int = Field(ge=1, le=512)
    attachments: tuple[AttachmentSummary, ...] = Field(max_length=128)
    summary_digest: Sha256Digest

    @model_validator(mode="after")
    def validate_digest(self) -> MessageSummary:
        if self.summary_digest != model_digest(self, exclude={"summary_digest"}):
            raise ValueError("message summary digest does not match")
        return self

    @classmethod
    def issue(cls, **values: object) -> MessageSummary:
        return cast(
            MessageSummary,
            _issue(cls, values, "summary_digest", MESSAGE_SUMMARY_SCHEMA_VERSION),
        )


class QuarantineRecord(IngestionModel):
    schema_version: Literal["cargomesh.quarantine-record/v1"] = QUARANTINE_RECORD_SCHEMA_VERSION
    policy_digest: Sha256Digest
    message_digest: Sha256Digest
    reason_code: IngestionName
    occurred_at: datetime
    record_digest: Sha256Digest

    @model_validator(mode="after")
    def validate_digest(self) -> QuarantineRecord:
        if self.occurred_at.tzinfo is None or self.occurred_at.utcoffset() is None:
            raise ValueError("quarantine time must include a timezone")
        if self.record_digest != model_digest(self, exclude={"record_digest"}):
            raise ValueError("quarantine record digest does not match")
        return self

    @classmethod
    def issue(cls, **values: object) -> QuarantineRecord:
        return cast(
            QuarantineRecord,
            _issue(cls, values, "record_digest", QUARANTINE_RECORD_SCHEMA_VERSION),
        )


class IngestionDecision(IngestionModel):
    schema_version: Literal["cargomesh.ingestion-decision/v1"] = INGESTION_DECISION_SCHEMA_VERSION
    disposition: IngestionDisposition
    reason_code: IngestionName
    message: MessageSummary | None = None
    quarantine: QuarantineRecord | None = None
    decision_digest: Sha256Digest

    @model_validator(mode="after")
    def validate_decision(self) -> IngestionDecision:
        if self.disposition is IngestionDisposition.ACCEPT and (
            self.message is None or self.quarantine is not None
        ):
            raise ValueError("accepted ingestion requires only a message summary")
        if self.disposition is IngestionDisposition.QUARANTINE and self.quarantine is None:
            raise ValueError("quarantined ingestion requires a quarantine record")
        if (
            self.message is not None
            and self.quarantine is not None
            and self.message.message_digest != self.quarantine.message_digest
        ):
            raise ValueError("quarantine message identity does not match")
        if self.decision_digest != model_digest(self, exclude={"decision_digest"}):
            raise ValueError("ingestion decision digest does not match")
        return self

    @classmethod
    def issue(cls, **values: object) -> IngestionDecision:
        return cast(
            IngestionDecision,
            _issue(cls, values, "decision_digest", INGESTION_DECISION_SCHEMA_VERSION),
        )


class ContentScanner(Protocol):
    """Injected scanner; it receives ephemeral bytes and returns a clean verdict."""

    def scan(self, content: bytes, attachment: AttachmentSummary) -> bool: ...


# A decision is normally either an accepted summary or this quarantine outcome;
# retain the explicit name for callers that model only the quarantine branch.
QuarantineDecision = IngestionDecision


def ingest_message(
    raw_message: bytes,
    policy: IngestionPolicy,
    *,
    scanner: ContentScanner | None,
    now: datetime | None = None,
) -> IngestionDecision:
    """Parse one in-memory message and emit only safe metadata or quarantine."""

    occurred_at = _now(now)
    raw_digest = (
        _digest_bytes(raw_message) if isinstance(raw_message, bytes) else _digest_bytes(b"")
    )
    try:
        if not isinstance(raw_message, bytes):
            return _quarantine(policy, raw_digest, "message_type_invalid", occurred_at)
        if len(raw_message) > policy.max_total_bytes:
            return _quarantine(policy, raw_digest, "message_too_large", occurred_at)
        header_count = _validate_wire_headers(raw_message, policy)
        message = BytesParser(policy=email_policy.default.clone(raise_on_defect=True)).parsebytes(
            raw_message
        )
        _validate_duplicate_headers(message)
        parts = tuple(_walk_parts(message, policy.max_mime_depth))
        if len(parts) > policy.max_parts:
            return _quarantine(policy, raw_digest, "mime_part_limit", occurred_at)
        attachments = _summarize_attachments(parts, policy, scanner)
        summary = MessageSummary.issue(
            message_digest=raw_digest,
            byte_length=len(raw_message),
            top_level_media_type=_media_type(message),
            header_count=header_count,
            part_count=len(parts),
            attachments=attachments,
        )
        return IngestionDecision.issue(
            disposition=IngestionDisposition.ACCEPT,
            reason_code="accepted",
            message=summary,
        )
    except _Quarantine as exc:
        return _quarantine(policy, raw_digest, exc.code, occurred_at)
    except Exception:
        return _quarantine(policy, raw_digest, "message_parse_invalid", occurred_at)


def _summarize_attachments(
    parts: tuple[Message, ...], policy: IngestionPolicy, scanner: ContentScanner | None
) -> tuple[AttachmentSummary, ...]:
    values: list[AttachmentSummary] = []
    for part in parts:
        if part.is_multipart():
            continue
        _validate_transfer_encoding(part)
        if not _is_attachment(part):
            continue
        if len(values) >= policy.max_attachments:
            raise _Quarantine("attachment_limit")
        payload = part.get_payload(decode=True)
        if not isinstance(payload, bytes):
            raise _Quarantine("attachment_encoding_invalid")
        if len(payload) > policy.max_attachment_bytes:
            raise _Quarantine("attachment_too_large")
        media_type = _media_type(part)
        summary = AttachmentSummary.issue(
            attachment_index=len(values) + 1,
            filename=_safe_filename(part.get_filename(), len(values) + 1),
            media_type=media_type,
            byte_length=len(payload),
            content_digest=_digest_bytes(payload),
        )
        if media_type == "application.pdf":
            _pdf_preflight(payload)
        if scanner is None:
            raise _Quarantine("scanner_unavailable")
        try:
            is_clean = scanner.scan(payload, summary)
        except Exception:
            raise _Quarantine("scanner_unavailable") from None
        if is_clean is not True:
            raise _Quarantine("scanner_rejected")
        values.append(summary)
    return tuple(values)


def _validate_wire_headers(raw_message: bytes, policy: IngestionPolicy) -> int:
    terminator = raw_message.find(b"\r\n\r\n")
    alternate = raw_message.find(b"\n\n")
    if terminator < 0 and alternate < 0:
        raise _Quarantine("header_terminator_missing")
    end = terminator if terminator >= 0 else alternate
    header_block = raw_message[:end]
    if len(header_block) > policy.max_header_bytes:
        raise _Quarantine("header_bytes_limit")
    lines = header_block.splitlines()
    if len(lines) > policy.max_headers:
        raise _Quarantine("header_count_limit")
    if any(len(line) > policy.max_header_bytes for line in lines):
        raise _Quarantine("header_line_limit")
    if any(line.startswith((b" ", b"\t")) for line in lines if b":" not in line):
        raise _Quarantine("header_malformed")
    return len(lines)


def _validate_duplicate_headers(message: Message) -> None:
    for name in _CRITICAL_HEADERS:
        if len(message.get_all(name, [])) > 1:
            raise _Quarantine("header_duplicate_critical")


def _walk_parts(message: Message, maximum_depth: int) -> Sequence[Message]:
    values: list[Message] = []

    def visit(part: Message, depth: int) -> None:
        if depth > maximum_depth:
            raise _Quarantine("mime_depth_limit")
        values.append(part)
        if part.is_multipart():
            payload = part.get_payload()
            if not isinstance(payload, list):
                raise _Quarantine("mime_structure_invalid")
            for child in payload:
                if not isinstance(child, Message):
                    raise _Quarantine("mime_structure_invalid")
                visit(child, depth + 1)

    visit(message, 0)
    return values


def _validate_transfer_encoding(part: Message) -> None:
    transfer = part.get("Content-Transfer-Encoding", "7bit").strip().lower()
    if transfer not in _TRANSFER_ENCODINGS:
        raise _Quarantine("transfer_encoding_invalid")
    raw = part.get_payload(decode=False)
    if not isinstance(raw, str):
        raise _Quarantine("transfer_encoding_invalid")
    try:
        raw_bytes = raw.encode("ascii")
    except UnicodeEncodeError:
        if transfer == "base64":
            raise _Quarantine("transfer_encoding_invalid") from None
        return
    if transfer == "base64":
        compact = re.sub(rb"\s+", b"", raw_bytes)
        try:
            base64.b64decode(compact, validate=True)
        except ValueError:
            raise _Quarantine("transfer_encoding_invalid") from None
    if transfer == "quoted-printable" and _malformed_quoted_printable(raw_bytes):
        raise _Quarantine("transfer_encoding_invalid")


def _malformed_quoted_printable(value: bytes) -> bool:
    for index, item in enumerate(value):
        if item != ord("="):
            continue
        tail = value[index + 1 : index + 3]
        if tail in {b"\r\n", b"\n"}:
            continue
        if len(tail) != 2 or any(byte not in b"0123456789abcdefABCDEF" for byte in tail):
            return True
    return False


def _is_attachment(part: Message) -> bool:
    disposition = (part.get_content_disposition() or "").lower()
    return disposition == "attachment" or part.get_filename() is not None


def _media_type(part: Message) -> str:
    value = part.get_content_type().lower().replace("/", ".")
    if not re.fullmatch(r"[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*", value):
        raise _Quarantine("media_type_invalid")
    return value


def _safe_filename(value: str | None, index: int) -> str:
    if value is None:
        return f"attachment-{index}"
    candidate = value.replace("\\", "/").rsplit("/", 1)[-1]
    candidate = "".join(
        character if character.isalnum() or character in {".", "-", "_", " "} else "_"
        for character in candidate
    ).strip(" .")
    return (candidate[:128] or f"attachment-{index}")


def _pdf_preflight(payload: bytes) -> None:
    if not payload.startswith(b"%PDF-") or b"%%EOF" not in payload[-2048:]:
        raise _Quarantine("pdf_structure_invalid")
    lowered = payload.lower()
    if b"/encrypt" in lowered:
        raise _Quarantine("pdf_encrypted")
    if any(token in lowered for token in _PDF_ACTIVE_TOKENS):
        raise _Quarantine("pdf_active_content")


class _Quarantine(Exception):
    def __init__(self, code: str) -> None:
        self.code = code


def _quarantine(
    policy: IngestionPolicy, message_digest: str, reason_code: str, occurred_at: datetime
) -> IngestionDecision:
    record = QuarantineRecord.issue(
        policy_digest=policy.policy_digest,
        message_digest=message_digest,
        reason_code=reason_code,
        occurred_at=occurred_at,
    )
    return IngestionDecision.issue(
        disposition=IngestionDisposition.QUARANTINE,
        reason_code=reason_code,
        quarantine=record,
    )


def _issue(
    model_type: type[IngestionPolicy]
    | type[AttachmentSummary]
    | type[MessageSummary]
    | type[QuarantineRecord]
    | type[IngestionDecision],
    values: Mapping[str, object],
    digest_field: str,
    schema_version: str,
) -> IngestionPolicy | AttachmentSummary | MessageSummary | QuarantineRecord | IngestionDecision:
    payload = dict(values)
    payload.setdefault("schema_version", schema_version)
    unsigned = model_type.model_construct(_fields_set=set(payload), **payload)
    payload[digest_field] = model_digest(unsigned, exclude={digest_field})
    return model_type.model_validate(payload)


def model_digest(model: BaseModel, *, exclude: set[str]) -> str:
    return value_digest(model.model_dump(mode="python", exclude=exclude, warnings=False))


def value_digest(value: object) -> str:
    canonical = json.dumps(
        _canonical(value),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    ).encode("utf-8")
    return _digest_bytes(canonical)


def _digest_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _canonical(value: object) -> object:
    if isinstance(value, BaseModel):
        return _canonical(value.model_dump(mode="python"))
    if isinstance(value, datetime):
        return _now(value).isoformat(timespec="microseconds")
    if isinstance(value, Enum):
        return _canonical(value.value)
    if isinstance(value, Mapping):
        return {str(key): _canonical(item) for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        return [_canonical(item) for item in value]
    return value


def _now(value: datetime | None) -> datetime:
    result = datetime.now(UTC) if value is None else value
    if result.tzinfo is None or result.utcoffset() is None:
        raise ValueError("ingestion time must include a timezone")
    return result.astimezone(UTC)


__all__ = [
    "ATTACHMENT_SUMMARY_SCHEMA_VERSION",
    "INGESTION_DECISION_SCHEMA_VERSION",
    "INGESTION_POLICY_SCHEMA_VERSION",
    "MESSAGE_SUMMARY_SCHEMA_VERSION",
    "QUARANTINE_RECORD_SCHEMA_VERSION",
    "AttachmentSummary",
    "ContentScanner",
    "IngestionDecision",
    "IngestionDisposition",
    "IngestionPolicy",
    "MessageSummary",
    "QuarantineDecision",
    "QuarantineRecord",
    "ingest_message",
]
