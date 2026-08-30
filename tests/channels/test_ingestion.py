from __future__ import annotations

import base64
from datetime import UTC, datetime

from cargomesh.channels.ingestion import (
    IngestionDisposition,
    IngestionPolicy,
    ingest_message,
)

NOW = datetime(2040, 1, 2, 3, 4, 5, tzinfo=UTC)


class CleanScanner:
    def scan(self, content: bytes, attachment) -> bool:
        assert content
        assert attachment.filename
        return True


def policy(**overrides: object) -> IngestionPolicy:
    values: dict[str, object] = {
        "max_total_bytes": 32 * 1024,
        "max_headers": 32,
        "max_header_bytes": 4096,
        "max_mime_depth": 4,
        "max_parts": 16,
        "max_attachments": 4,
        "max_attachment_bytes": 8 * 1024,
    }
    values.update(overrides)
    return IngestionPolicy.issue(**values)


def attachment_message(
    content: bytes,
    *,
    media_type: str = "application/octet-stream",
    filename: str = "report.bin",
) -> bytes:
    encoded = base64.b64encode(content)
    return (
        b"From: sender@example.test\r\n"
        b"To: recipient@example.test\r\n"
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: multipart/mixed; boundary=boundary\r\n"
        b"\r\n"
        b"--boundary\r\n"
        + f"Content-Type: {media_type}\r\n".encode()
        + b"Content-Transfer-Encoding: base64\r\n"
        + f'Content-Disposition: attachment; filename="{filename}"\r\n'.encode()
        + b"\r\n"
        + encoded
        + b"\r\n--boundary--\r\n"
    )


def test_attachment_returns_only_metadata_and_not_body() -> None:
    secret_body = b"customer business body must not escape"
    decision = ingest_message(
        attachment_message(secret_body, filename="../../customer-report.bin"),
        policy(),
        scanner=CleanScanner(),
        now=NOW,
    )

    assert decision.disposition is IngestionDisposition.ACCEPT
    assert decision.message is not None
    attachment = decision.message.attachments[0]
    assert attachment.filename == "customer-report.bin"
    assert attachment.media_type == "application.octet-stream"
    assert attachment.byte_length == len(secret_body)
    serialized = decision.model_dump_json()
    assert secret_body.decode() not in serialized
    assert "../../" not in serialized
    assert attachment.content_digest.startswith("sha256:")


def test_oversized_message_is_quarantined_without_parser_output() -> None:
    restricted = policy(max_total_bytes=256, max_attachment_bytes=128)
    raw = b"From: x@example.test\r\n\r\n" + b"x" * 300

    decision = ingest_message(raw, restricted, scanner=None, now=NOW)

    assert decision.disposition is IngestionDisposition.QUARANTINE
    assert decision.reason_code == "message_too_large"
    assert decision.message is None
    assert decision.quarantine is not None
    assert decision.quarantine.policy_digest == restricted.policy_digest


def test_active_or_encrypted_pdf_is_quarantined_before_scanner() -> None:
    active_pdf = b"%PDF-1.7\n1 0 obj << /JavaScript (app.alert(1)) >>\n%%EOF"
    decision = ingest_message(
        attachment_message(active_pdf, media_type="application/pdf", filename="safe.pdf"),
        policy(),
        scanner=CleanScanner(),
        now=NOW,
    )

    assert decision.disposition is IngestionDisposition.QUARANTINE
    assert decision.reason_code == "pdf_active_content"
    assert decision.message is None


def test_scanner_failure_or_absence_fails_closed() -> None:
    class BrokenScanner:
        def scan(self, content: bytes, attachment) -> bool:
            del content, attachment
            raise RuntimeError("scanner endpoint secret diagnostics")

    raw = attachment_message(b"benign")
    unavailable = ingest_message(raw, policy(), scanner=None, now=NOW)
    broken = ingest_message(raw, policy(), scanner=BrokenScanner(), now=NOW)

    assert unavailable.disposition is IngestionDisposition.QUARANTINE
    assert unavailable.reason_code == "scanner_unavailable"
    assert broken.disposition is IngestionDisposition.QUARANTINE
    assert broken.reason_code == "scanner_unavailable"
    assert "secret diagnostics" not in broken.model_dump_json()


def test_malformed_encoding_and_duplicate_critical_headers_are_quarantined() -> None:
    malformed = attachment_message(b"unused").replace(b"dW51c2Vk", b"not base64!!!")
    duplicate = (
        b"From: x@example.test\r\nContent-Type: text/plain\r\n"
        b"Content-Type: text/plain\r\n\r\nbody"
    )

    malformed_decision = ingest_message(malformed, policy(), scanner=CleanScanner(), now=NOW)
    duplicate_decision = ingest_message(duplicate, policy(), scanner=None, now=NOW)

    assert malformed_decision.reason_code == "transfer_encoding_invalid"
    assert duplicate_decision.reason_code == "header_duplicate_critical"
