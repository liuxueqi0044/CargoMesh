"""Bounded Private Runner artifact relay with an injected content sink."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import threading
from collections.abc import Mapping
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Protocol, cast

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

Identifier = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=256)]
MimeType = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=3,
        max_length=128,
        pattern=r"^[a-z0-9][a-z0-9.+-]*/[a-z0-9][a-z0-9.+-]*$",
    ),
]
Digest = Annotated[str, StringConstraints(pattern=r"^sha256:[0-9a-f]{64}$")]


class ArtifactModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class ArtifactType(StrEnum):
    SCREENSHOT = "SCREENSHOT"
    TEXT = "TEXT"
    EVIDENCE = "EVIDENCE"
    TRACE = "TRACE"


class ArtifactClassification(StrEnum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    RESTRICTED = "RESTRICTED"


_CLASSIFICATION_RANK = {
    ArtifactClassification.PUBLIC: 0,
    ArtifactClassification.INTERNAL: 1,
    ArtifactClassification.CONFIDENTIAL: 2,
    ArtifactClassification.RESTRICTED: 3,
}


class ArtifactRule(ArtifactModel):
    artifact_type: ArtifactType
    allowed_media_types: tuple[MimeType, ...] = Field(min_length=1, max_length=16)
    maximum_bytes: int = Field(ge=1, le=100 * 1024 * 1024)
    maximum_classification: ArtifactClassification

    @model_validator(mode="after")
    def validate_rule(self) -> ArtifactRule:
        if len(self.allowed_media_types) != len(set(self.allowed_media_types)):
            raise ValueError("artifact media types must be unique")
        return self


class ArtifactPolicy(ArtifactModel):
    policy_id: Identifier
    rules: tuple[ArtifactRule, ...] = Field(min_length=1, max_length=16)
    policy_digest: Digest

    @model_validator(mode="after")
    def validate_policy(self) -> ArtifactPolicy:
        types = tuple(rule.artifact_type for rule in self.rules)
        if len(types) != len(set(types)):
            raise ValueError("artifact policy types must be unique")
        if self.policy_digest != _digest(self.model_dump(exclude={"policy_digest"})):
            raise ValueError("artifact policy digest does not match")
        return self

    @classmethod
    def issue(cls, **values: object) -> ArtifactPolicy:
        return cast(ArtifactPolicy, _issue(cls, values, "policy_digest"))


class ArtifactCandidate(ArtifactModel):
    tenant_id: Identifier
    environment_id: Identifier
    task_id: Identifier
    artifact_type: ArtifactType
    media_type: MimeType
    classification: ArtifactClassification
    sanitized: bool = False
    contains_sensitive_content: bool = False


class ArtifactReceipt(ArtifactModel):
    tenant_id: Identifier
    environment_id: Identifier
    task_id: Identifier
    artifact_type: ArtifactType
    media_type: MimeType
    classification: ArtifactClassification
    size_bytes: int = Field(ge=1, le=100 * 1024 * 1024)
    content_digest: Digest
    storage_ref: Identifier
    policy_digest: Digest
    relayed_at: datetime
    receipt_digest: Digest

    @model_validator(mode="after")
    def validate_receipt(self) -> ArtifactReceipt:
        if self.relayed_at.tzinfo is None or self.relayed_at.utcoffset() is None:
            raise ValueError("artifact relay time must include a timezone")
        if self.receipt_digest != _digest(self.model_dump(exclude={"receipt_digest"})):
            raise ValueError("artifact receipt digest does not match")
        return self

    @classmethod
    def issue(cls, **values: object) -> ArtifactReceipt:
        return cast(ArtifactReceipt, _issue(cls, values, "receipt_digest"))


class ArtifactRelayError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class ArtifactSink(Protocol):
    def put(
        self,
        *,
        tenant_id: str,
        environment_id: str,
        task_id: str,
        content_digest: str,
        media_type: str,
        content: bytes,
    ) -> str: ...


class ArtifactReceiptStore(Protocol):
    def append(self, receipt: ArtifactReceipt) -> ArtifactReceipt: ...


class InMemoryArtifactSink:
    """Explicit local/test sink; content is addressable only by opaque reference."""

    def __init__(self) -> None:
        self._objects: dict[str, bytes] = {}

    def put(
        self,
        *,
        tenant_id: str,
        environment_id: str,
        task_id: str,
        content_digest: str,
        media_type: str,
        content: bytes,
    ) -> str:
        del tenant_id, environment_id, task_id, media_type
        if content_digest != "sha256:" + hashlib.sha256(content).hexdigest():
            raise ArtifactRelayError("artifact_digest_mismatch", "Artifact digest mismatch")
        storage_ref = "artifact." + content_digest.replace(":", ".")
        existing = self._objects.get(storage_ref)
        if existing is not None and existing != content:
            raise ArtifactRelayError("artifact_collision", "Artifact identity collision")
        self._objects[storage_ref] = bytes(content)
        return storage_ref

    def read(self, storage_ref: str) -> bytes:
        return bytes(self._objects[storage_ref])


class SQLiteArtifactReceiptStore:
    """Metadata-only receipt index. Artifact bytes stay in the injected sink."""

    def __init__(self, database: str | Path = ":memory:") -> None:
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(
            str(database), isolation_level=None, check_same_thread=False, timeout=10
        )
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA busy_timeout=10000")
        self._connection.execute(
            """CREATE TABLE IF NOT EXISTS runner_artifact_receipts (
                tenant_id TEXT NOT NULL,
                environment_id TEXT NOT NULL,
                task_id TEXT NOT NULL,
                content_digest TEXT NOT NULL,
                receipt_digest TEXT NOT NULL,
                receipt_json TEXT NOT NULL,
                PRIMARY KEY (tenant_id, environment_id, task_id, content_digest)
            )"""
        )

    def append(self, receipt: ArtifactReceipt) -> ArtifactReceipt:
        value = ArtifactReceipt.model_validate(receipt.model_dump())
        identity = (
            value.tenant_id,
            value.environment_id,
            value.task_id,
            value.content_digest,
        )
        with self._lock:
            row = self._connection.execute(
                "SELECT receipt_json FROM runner_artifact_receipts "
                "WHERE tenant_id=? AND environment_id=? AND task_id=? AND content_digest=?",
                identity,
            ).fetchone()
            if row is not None:
                current = ArtifactReceipt.model_validate_json(row["receipt_json"])
                stable_fields = {"relayed_at", "receipt_digest"}
                if current.model_dump(exclude=stable_fields) != value.model_dump(
                    exclude=stable_fields
                ):
                    raise ArtifactRelayError(
                        "artifact_receipt_conflict", "Artifact receipt conflicts"
                    )
                return current
            try:
                self._connection.execute(
                    "INSERT INTO runner_artifact_receipts VALUES (?,?,?,?,?,?)",
                    (*identity, value.receipt_digest, value.model_dump_json()),
                )
            except sqlite3.Error as exc:
                raise ArtifactRelayError(
                    "artifact_receipt_store_unavailable",
                    "Artifact receipt store is unavailable",
                ) from exc
            return value

    def close(self) -> None:
        self._connection.close()


class ArtifactRelay:
    def __init__(
        self,
        policy: ArtifactPolicy,
        sink: ArtifactSink,
        *,
        receipts: ArtifactReceiptStore | None = None,
    ) -> None:
        self._policy = policy
        self._rules = {rule.artifact_type: rule for rule in policy.rules}
        self._sink = sink
        self._receipts = receipts

    def relay(
        self,
        candidate: ArtifactCandidate,
        content: bytes | bytearray | memoryview,
        *,
        relayed_at: datetime | None = None,
    ) -> ArtifactReceipt:
        try:
            rule = self._rules[candidate.artifact_type]
        except KeyError as exc:
            raise ArtifactRelayError(
                "artifact_type_denied", "Artifact type is not allowed"
            ) from exc
        payload = bytes(content)
        if not payload or len(payload) > rule.maximum_bytes:
            raise ArtifactRelayError("artifact_size_denied", "Artifact size is not allowed")
        if candidate.media_type not in rule.allowed_media_types:
            raise ArtifactRelayError("artifact_media_denied", "Artifact media type is not allowed")
        if (
            _CLASSIFICATION_RANK[candidate.classification]
            > _CLASSIFICATION_RANK[rule.maximum_classification]
        ):
            raise ArtifactRelayError(
                "artifact_classification_denied",
                "Artifact classification is not allowed",
            )
        if candidate.contains_sensitive_content:
            raise ArtifactRelayError(
                "artifact_sensitive_content", "Artifact requires unavailable redaction"
            )
        if candidate.artifact_type in {ArtifactType.SCREENSHOT, ArtifactType.TEXT} and not (
            candidate.sanitized
        ):
            raise ArtifactRelayError(
                "artifact_sanitization_required", "Artifact sanitization is required"
            )
        content_digest = "sha256:" + hashlib.sha256(payload).hexdigest()
        try:
            storage_ref = self._sink.put(
                tenant_id=candidate.tenant_id,
                environment_id=candidate.environment_id,
                task_id=candidate.task_id,
                content_digest=content_digest,
                media_type=candidate.media_type,
                content=payload,
            )
        except ArtifactRelayError:
            raise
        except Exception as exc:
            raise ArtifactRelayError(
                "artifact_sink_unavailable", "Artifact sink is unavailable"
            ) from exc
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,255}", storage_ref):
            raise ArtifactRelayError(
                "artifact_storage_ref_invalid", "Artifact sink returned an invalid reference"
            )
        timestamp = (relayed_at or datetime.now(UTC)).astimezone(UTC)
        receipt = ArtifactReceipt.issue(
            tenant_id=candidate.tenant_id,
            environment_id=candidate.environment_id,
            task_id=candidate.task_id,
            artifact_type=candidate.artifact_type,
            media_type=candidate.media_type,
            classification=candidate.classification,
            size_bytes=len(payload),
            content_digest=content_digest,
            storage_ref=storage_ref,
            policy_digest=self._policy.policy_digest,
            relayed_at=timestamp,
        )
        if self._receipts is not None:
            return self._receipts.append(receipt)
        return receipt


def _issue(model_type: type[BaseModel], values: Mapping[str, object], field: str) -> BaseModel:
    payload = dict(values)
    unsigned = model_type.model_construct(_fields_set=set(payload), **payload)
    payload[field] = _digest(unsigned.model_dump(exclude={field}))
    return model_type.model_validate(payload)


def _digest(value: object) -> str:
    def canonical(item: object) -> object:
        if isinstance(item, datetime):
            return item.astimezone(UTC).isoformat(timespec="microseconds")
        if isinstance(item, StrEnum):
            return item.value
        if isinstance(item, Mapping):
            return {str(key): canonical(inner) for key, inner in item.items()}
        if isinstance(item, (tuple, list)):
            return [canonical(inner) for inner in item]
        return item

    encoded = json.dumps(
        canonical(value), ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode()
    return "sha256:" + hashlib.sha256(encoded).hexdigest()
