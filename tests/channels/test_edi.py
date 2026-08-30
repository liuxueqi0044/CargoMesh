from __future__ import annotations

import pytest
from pydantic import ValidationError

from cargomesh.channels.edi import (
    MAX_EDI_BYTES,
    EDIEnvelope,
    EDIParseError,
    parse_edifact,
)


def _document(*, second_reference: str | None = None, count: int = 1) -> str:
    second = ""
    if second_reference is not None:
        second = f"UNH+{second_reference}+IFTMIN:D:99B:UN'BGM+SECOND'UNT+3+{second_reference}'"
    return (
        "UNB+UNOC:3+SENDER+RECEIVER+260831:1200+IREF'"
        "UNH+M1+IFTMIN:D:99B:UN'BGM+FIRST'UNT+3+M1'"
        f"{second}UNZ+{count}+IREF'"
    )


def test_parse_returns_only_digest_bound_metadata() -> None:
    envelope = parse_edifact(_document())
    assert isinstance(envelope, EDIEnvelope)
    assert envelope.message_count == 1
    assert envelope.messages[0].message_type == "IFTMIN"
    assert "FIRST" not in repr(envelope)
    assert envelope.digest.startswith("sha256:")
    assert envelope.source_digest.startswith("sha256:")
    assert envelope.model_config["frozen"] is True
    with pytest.raises(ValidationError):
        envelope.message_count = 2  # type: ignore[misc]


def test_source_digest_distinguishes_equal_length_business_values() -> None:
    first = parse_edifact(_document())
    second = parse_edifact(_document().replace("FIRST", "OTHER"))

    assert first.messages[0].segments == second.messages[0].segments
    assert first.source_digest != second.source_digest
    assert first.digest != second.digest


def test_optional_una_and_multiple_messages_validate_counts_and_references() -> None:
    document = "UNA:+.? '" + _document(second_reference="M2", count=2)
    envelope = parse_edifact(document)
    assert len(envelope.messages) == 2
    assert envelope.messages[1].message_reference == "M2"


@pytest.mark.parametrize(
    ("document", "code"),
    [
        (_document().replace("UNT+3+M1", "UNT+2+M1"), "edi_segment_count_mismatch"),
        (_document().replace("UNT+3+M1", "UNT+3+M2"), "edi_message_reference_mismatch"),
        (_document().replace("UNZ+1+IREF", "UNZ+2+IREF"), "edi_message_count_mismatch"),
        (_document().replace("UNZ+1+IREF", "UNZ+1+OTHER"), "edi_control_reference_mismatch"),
        (_document().replace("BGM+FIRST", "UNB+NEST"), "edi_nested_envelope"),
        (_document(second_reference="M1", count=2), "edi_duplicate_reference"),
    ],
)
def test_rejects_unbalanced_or_inconsistent_envelopes(document: str, code: str) -> None:
    with pytest.raises(EDIParseError) as raised:
        parse_edifact(document)
    assert raised.value.code == code
    assert "FIRST" not in str(raised.value)


def test_rejects_truncation_charset_and_bounds() -> None:
    for document, code in [
        (_document()[:-1], "edi_truncated"),
        (_document().replace("FIRST", "FÍRST"), "edi_charset_invalid"),
        ("A" * (MAX_EDI_BYTES + 1), "edi_too_large"),
    ]:
        with pytest.raises(EDIParseError) as raised:
            parse_edifact(document)
        assert raised.value.code == code
