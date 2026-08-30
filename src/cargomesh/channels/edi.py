"""Bounded, metadata-only EDIFACT interchange boundary.

This module deliberately does not expose the interchange text or business
element values.  It is a syntax/identity boundary suitable for a future
transport, not an AS2 or SFTP client.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Annotated, Protocol

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

EDI_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
MAX_EDI_BYTES = 262_144
MAX_EDI_SEGMENTS = 4_096
MAX_EDI_ELEMENTS = 128
MAX_EDI_ELEMENT_BYTES = 4_096

EDIName = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=128,
        pattern=r"^[A-Z][A-Z0-9]{1,9}$",
    ),
]
EDIReference = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=70)]


class EDIParseError(RuntimeError):
    """Safe, bounded parse failure; never contains source document content."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class EDIModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class EDISegment(EDIModel):
    """Segment metadata without its tag's business element values."""

    tag: EDIName
    element_count: int = Field(ge=0, le=MAX_EDI_ELEMENTS)
    element_lengths: tuple[int, ...] = Field(max_length=MAX_EDI_ELEMENTS)
    byte_length: int = Field(ge=3, le=MAX_EDI_BYTES)
    digest: str

    @model_validator(mode="after")
    def validate_segment(self) -> EDISegment:
        if len(self.element_lengths) != self.element_count:
            raise ValueError("segment element metadata is inconsistent")
        if any(length < 0 or length > MAX_EDI_ELEMENT_BYTES for length in self.element_lengths):
            raise ValueError("segment element metadata is out of bounds")
        if not EDI_DIGEST_RE.fullmatch(self.digest):
            raise ValueError("segment digest is invalid")
        if self.digest != _digest(_without_digest(self)):
            raise ValueError("segment digest does not match metadata")
        return self

    @classmethod
    def issue(cls, *, tag: str, element_lengths: tuple[int, ...], byte_length: int) -> EDISegment:
        values: dict[str, object] = {
            "tag": tag,
            "element_count": len(element_lengths),
            "element_lengths": element_lengths,
            "byte_length": byte_length,
        }
        values["digest"] = _digest(values)
        return cls.model_validate(values)


class EDIMessage(EDIModel):
    """UNH...UNT metadata, with no business payload."""

    message_reference: EDIReference
    message_type: EDIName
    segment_count: int = Field(ge=2, le=MAX_EDI_SEGMENTS)
    segments: tuple[EDISegment, ...] = Field(min_length=2, max_length=MAX_EDI_SEGMENTS)
    digest: str

    @model_validator(mode="after")
    def validate_message(self) -> EDIMessage:
        if self.segment_count != len(self.segments):
            raise ValueError("message segment metadata is inconsistent")
        if self.segments[0].tag != "UNH" or self.segments[-1].tag != "UNT":
            raise ValueError("message envelope is unbalanced")
        if not EDI_DIGEST_RE.fullmatch(self.digest):
            raise ValueError("message digest is invalid")
        if self.digest != _digest(_without_digest(self)):
            raise ValueError("message digest does not match metadata")
        return self

    @classmethod
    def issue(
        cls,
        *,
        message_reference: str,
        message_type: str,
        segments: tuple[EDISegment, ...],
    ) -> EDIMessage:
        values: dict[str, object] = {
            "message_reference": message_reference,
            "message_type": message_type,
            "segment_count": len(segments),
            "segments": segments,
        }
        values["digest"] = _digest(values)
        return cls.model_validate(values)


class EDIEnvelope(EDIModel):
    """UNB...UNZ interchange metadata, digest-bound and immutable."""

    syntax_identifier: EDIReference
    interchange_control_reference: EDIReference
    source_digest: str
    message_count: int = Field(ge=1, le=MAX_EDI_SEGMENTS)
    segment_count: int = Field(ge=4, le=MAX_EDI_SEGMENTS)
    messages: tuple[EDIMessage, ...] = Field(min_length=1, max_length=MAX_EDI_SEGMENTS)
    digest: str

    @model_validator(mode="after")
    def validate_envelope(self) -> EDIEnvelope:
        if self.message_count != len(self.messages):
            raise ValueError("interchange message count is inconsistent")
        actual_segments = 2 + sum(message.segment_count for message in self.messages) + 1
        if self.segment_count != actual_segments:
            raise ValueError("interchange segment count is inconsistent")
        references = [message.message_reference for message in self.messages]
        if len(references) != len(set(references)):
            raise ValueError("message references must be unique")
        if not EDI_DIGEST_RE.fullmatch(self.source_digest):
            raise ValueError("interchange source digest is invalid")
        if not EDI_DIGEST_RE.fullmatch(self.digest):
            raise ValueError("envelope digest is invalid")
        if self.digest != _digest(_without_digest(self)):
            raise ValueError("envelope digest does not match metadata")
        return self

    @classmethod
    def parse(cls, document: str | bytes) -> EDIEnvelope:
        return parse_edifact(document)

    @classmethod
    def issue(
        cls,
        *,
        syntax_identifier: str,
        interchange_control_reference: str,
        source_digest: str,
        messages: tuple[EDIMessage, ...],
    ) -> EDIEnvelope:
        values: dict[str, object] = {
            "syntax_identifier": syntax_identifier,
            "interchange_control_reference": interchange_control_reference,
            "source_digest": source_digest,
            "message_count": len(messages),
            "segment_count": 3 + sum(message.segment_count for message in messages),
            "messages": messages,
        }
        values["digest"] = _digest(values)
        return cls.model_validate(values)


class EDITransport(Protocol):
    """Future transport boundary; this package intentionally has no client."""

    async def send(self, envelope: EDIEnvelope) -> None:
        """Send a previously parsed envelope through an external transport."""


def parse_edifact(document: str | bytes) -> EDIEnvelope:
    """Parse one bounded EDIFACT interchange and return metadata only."""

    data = _as_ascii_bytes(document)
    if len(data) > MAX_EDI_BYTES:
        raise EDIParseError("edi_too_large", "EDIFACT interchange exceeds size limit")
    separators, body = _separators(data)
    segments = _split_segments(body, separators)
    if len(segments) > MAX_EDI_SEGMENTS:
        raise EDIParseError("edi_too_many_segments", "EDIFACT interchange has too many segments")
    if not segments or segments[0][0] != "UNB" or segments[-1][0] != "UNZ":
        raise EDIParseError("edi_envelope_invalid", "EDIFACT interchange envelope is invalid")
    if any(segment[0] in {"UNB", "UNZ"} for segment in segments[1:-1]):
        raise EDIParseError("edi_nested_envelope", "EDIFACT interchange contains a nested envelope")

    unb_tag, unb_elements, unb_size = segments[0]
    unz_tag, unz_elements, unz_size = segments[-1]
    if len(unb_elements) < 5 or len(unz_elements) < 2:
        raise EDIParseError("edi_envelope_invalid", "EDIFACT envelope fields are invalid")
    if unb_elements[0].split(separators[0], 1)[0] == "":
        raise EDIParseError("edi_envelope_invalid", "EDIFACT syntax identifier is invalid")
    control_reference = unb_elements[4]
    if unz_elements[1] != control_reference:
        raise EDIParseError("edi_control_reference_mismatch", "EDIFACT control references differ")
    if _integer(unz_elements[0]) != -1:
        message_count = _integer(unz_elements[0])
    else:
        raise EDIParseError("edi_count_invalid", "EDIFACT message count is invalid")

    segment_models: list[EDISegment] = []
    for tag, elements, size in segments:
        if tag in {"UNB", "UNZ"} or len(elements) <= MAX_EDI_ELEMENTS:
            segment_models.append(
                EDISegment.issue(
                    tag=tag,
                    element_lengths=tuple(len(element.encode("ascii")) for element in elements),
                    byte_length=size,
                )
            )
        else:
            raise EDIParseError("edi_too_many_elements", "EDIFACT segment has too many elements")

    messages: list[EDIMessage] = []
    seen_references: set[str] = set()
    cursor = 1
    while cursor < len(segments) - 1:
        if segments[cursor][0] != "UNH":
            raise EDIParseError("edi_message_unbalanced", "EDIFACT message must start with UNH")
        start = cursor
        cursor += 1
        while cursor < len(segments) - 1 and segments[cursor][0] != "UNT":
            if segments[cursor][0] == "UNH":
                raise EDIParseError("edi_nested_message", "EDIFACT message contains nested UNH")
            cursor += 1
        if cursor >= len(segments) - 1:
            raise EDIParseError("edi_truncated", "EDIFACT message has no UNT terminator")
        end = cursor
        unh_elements = segments[start][1]
        unt_elements = segments[end][1]
        if len(unh_elements) < 2 or len(unt_elements) < 2:
            raise EDIParseError(
                "edi_message_invalid", "EDIFACT message envelope fields are invalid"
            )
        if unh_elements[0] != unt_elements[1]:
            raise EDIParseError(
                "edi_message_reference_mismatch", "EDIFACT message references differ"
            )
        if unh_elements[0] in seen_references:
            raise EDIParseError(
                "edi_duplicate_reference", "EDIFACT message references are duplicated"
            )
        seen_references.add(unh_elements[0])
        if _integer(unt_elements[0]) != end - start + 1:
            raise EDIParseError(
                "edi_segment_count_mismatch", "EDIFACT message segment count differs"
            )
        message_segments = tuple(segment_models[start : end + 1])
        messages.append(
            EDIMessage.issue(
                message_reference=unh_elements[0],
                message_type=unh_elements[1].split(separators[0], 1)[0],
                segments=message_segments,
            )
        )
        cursor = end + 1
    if not messages:
        raise EDIParseError("edi_message_missing", "EDIFACT interchange contains no messages")
    if message_count != len(messages):
        raise EDIParseError("edi_message_count_mismatch", "EDIFACT message count differs")
    envelope = EDIEnvelope.issue(
        syntax_identifier=unb_elements[0],
        interchange_control_reference=control_reference,
        source_digest="sha256:" + hashlib.sha256(data).hexdigest(),
        messages=tuple(messages),
    )
    # Bind the returned metadata to the complete wire representation without
    # retaining that representation.  The metadata digest remains stable and
    # the input's wire digest is deliberately not exposed as a second payload.
    del unb_tag, unz_tag, unb_size, unz_size, segment_models
    return envelope


def _as_ascii_bytes(document: str | bytes) -> bytes:
    if isinstance(document, str):
        try:
            data = document.encode("ascii")
        except UnicodeEncodeError as exc:
            raise EDIParseError(
                "edi_charset_invalid", "EDIFACT interchange charset is invalid"
            ) from exc
    elif isinstance(document, bytes):
        data = document
    else:
        raise EDIParseError("edi_input_invalid", "EDIFACT input type is invalid")
    try:
        data.decode("ascii")
    except UnicodeDecodeError as exc:
        raise EDIParseError(
            "edi_charset_invalid", "EDIFACT interchange charset is invalid"
        ) from exc
    if any((byte < 0x20 and byte not in {0x0A, 0x0D}) or byte == 0x7F for byte in data):
        raise EDIParseError(
            "edi_charset_invalid", "EDIFACT interchange contains unsupported characters"
        )
    return data


def _separators(data: bytes) -> tuple[tuple[str, str, str, str, str], bytes]:
    if data.startswith(b"UNA"):
        if len(data) < 9:
            raise EDIParseError("edi_truncated", "EDIFACT UNA segment is truncated")
        component, element, decimal, release, reserved, terminator = data[3:9]
        separator_bytes = (component, element, decimal, release, terminator)
        if reserved != 0x20 or len(set(separator_bytes)) != len(separator_bytes):
            raise EDIParseError("edi_separator_invalid", "EDIFACT UNA separators are invalid")
        return (
            (chr(component), chr(element), chr(decimal), chr(release), chr(terminator)),
            data[9:],
        )
    return (":", "+", ".", "?", "'"), data


def _split_segments(
    data: bytes, separators: tuple[str, str, str, str, str]
) -> list[tuple[str, list[str], int]]:
    terminator = separators[4]
    release = separators[3]
    text = data.decode("ascii")
    if text.endswith(("\r", "\n")):
        text = text.rstrip("\r\n")
    if not text or not text.endswith(terminator):
        raise EDIParseError("edi_truncated", "EDIFACT interchange has no final segment terminator")
    raw_segments: list[str] = []
    current: list[str] = []
    escaped = False
    for char in text:
        if not current and char in "\r\n":
            continue
        current.append(char)
        if escaped:
            escaped = False
        elif char == release:
            escaped = True
        elif char == terminator:
            raw_segments.append("".join(current[:-1]))
            current = []
    if escaped or current:
        raise EDIParseError("edi_truncated", "EDIFACT release or segment is incomplete")
    result: list[tuple[str, list[str], int]] = []
    for raw in raw_segments:
        elements = _split_elements(raw, separators[1], release)
        if not elements:
            raise EDIParseError("edi_segment_invalid", "EDIFACT segment is empty")
        tag = elements[0]
        if not re.fullmatch(r"[A-Z][A-Z0-9]{1,9}", tag):
            raise EDIParseError("edi_segment_invalid", "EDIFACT segment tag is invalid")
        if tag in {"UNB", "UNH", "UNT", "UNZ"} or raw.startswith(("UNA",)):
            pass
        elif raw and tag.startswith("UN"):
            # Envelope/control segments are a closed vocabulary.
            raise EDIParseError(
                "edi_unknown_envelope_segment", "EDIFACT envelope segment is unknown"
            )
        element_values = elements[1:]
        if len(element_values) > MAX_EDI_ELEMENTS:
            raise EDIParseError("edi_too_many_elements", "EDIFACT segment has too many elements")
        if any(len(value.encode("ascii")) > MAX_EDI_ELEMENT_BYTES for value in element_values):
            raise EDIParseError("edi_element_too_large", "EDIFACT element exceeds size limit")
        result.append((tag, element_values, len(raw.encode("ascii")) + 1))
    return result


def _split_elements(raw: str, separator: str, release: str) -> list[str]:
    values: list[str] = []
    current: list[str] = []
    escaped = False
    for char in raw:
        if escaped:
            current.append(char)
            escaped = False
        elif char == release:
            escaped = True
        elif char == separator:
            values.append("".join(current))
            current = []
        else:
            current.append(char)
    if escaped:
        raise EDIParseError("edi_truncated", "EDIFACT release character is incomplete")
    values.append("".join(current))
    return values


def _integer(value: str) -> int:
    if not re.fullmatch(r"[0-9]{1,9}", value):
        raise EDIParseError("edi_count_invalid", "EDIFACT count is invalid")
    return int(value)


def _without_digest(value: BaseModel) -> dict[str, object]:
    return value.model_dump(mode="python", exclude={"digest"})


def _digest(value: object) -> str:
    encoded = json.dumps(
        _canonical(value), ensure_ascii=False, separators=(",", ":"), sort_keys=True
    )
    return "sha256:" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _canonical(value: object) -> object:
    if isinstance(value, BaseModel):
        return _canonical(value.model_dump(mode="python"))
    if isinstance(value, Mapping):
        return {str(key): _canonical(item) for key, item in value.items()}
    if isinstance(value, tuple | list):
        return [_canonical(item) for item in value]
    if isinstance(value, datetime):
        return value.astimezone(UTC).isoformat(timespec="microseconds")
    return value


parse_edi = parse_edifact


__all__ = [
    "MAX_EDI_BYTES",
    "MAX_EDI_ELEMENTS",
    "MAX_EDI_ELEMENT_BYTES",
    "MAX_EDI_SEGMENTS",
    "EDIEnvelope",
    "EDIMessage",
    "EDIParseError",
    "EDISegment",
    "EDITransport",
    "parse_edi",
    "parse_edifact",
]
