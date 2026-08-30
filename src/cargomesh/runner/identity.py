"""One-time enrollment and immutable metadata-only Private Runner identities."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from enum import Enum, StrEnum
from typing import Annotated, Literal, Never, cast

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

RUNNER_IDENTITY_SCHEMA_VERSION: Literal["cargomesh.runner-identity/v1"] = (
    "cargomesh.runner-identity/v1"
)
RUNNER_RECORD_SCHEMA_VERSION: Literal["cargomesh.runner-record/v1"] = (
    "cargomesh.runner-record/v1"
)
ENROLLMENT_CHALLENGE_SCHEMA_VERSION: Literal["cargomesh.runner-enrollment/v1"] = (
    "cargomesh.runner-enrollment/v1"
)

RunnerIdentifier = Annotated[
    str, StringConstraints(strip_whitespace=True, min_length=1, max_length=256)
]
RunnerName = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=128,
        pattern=r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$",
    ),
]
RunnerVersion = Annotated[
    str,
    StringConstraints(
        pattern=r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$"
    ),
]
Sha256Digest = Annotated[str, StringConstraints(pattern=r"^sha256:[0-9a-f]{64}$")]
QueueId = Annotated[
    str,
    StringConstraints(pattern=r"^queue_[A-Za-z0-9_-]{32,96}$"),
]
ChallengeId = Annotated[
    str,
    StringConstraints(pattern=r"^enroll_[A-Za-z0-9_-]{32,96}$"),
]
RunnerId = Annotated[
    str,
    StringConstraints(pattern=r"^runner_[A-Za-z0-9_-]{32,96}$"),
]


class RunnerIdentityModel(BaseModel):
    """Strict immutable metadata.  Private-key fields are not representable."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class RunnerHealth(StrEnum):
    ONLINE = "ONLINE"
    OFFLINE = "OFFLINE"
    REVOKED = "REVOKED"


class EnrollmentChallenge(RunnerIdentityModel):
    """Safe enrollment metadata; it deliberately does not contain its token."""

    schema_version: Literal["cargomesh.runner-enrollment/v1"] = (
        ENROLLMENT_CHALLENGE_SCHEMA_VERSION
    )
    challenge_id: ChallengeId
    tenant_id: RunnerIdentifier
    environment_id: RunnerIdentifier
    runner_pool: RunnerName
    issued_at: datetime
    expires_at: datetime

    @field_validator("issued_at", "expires_at")
    @classmethod
    def require_utc(cls, value: datetime) -> datetime:
        return _utc(value, "enrollment timestamps")

    @model_validator(mode="after")
    def validate_lifetime(self) -> EnrollmentChallenge:
        if self.expires_at <= self.issued_at:
            raise ValueError("enrollment expiry must be after issue time")
        return self


class EnrollmentToken:
    """A plaintext bootstrap token that can be extracted exactly once.

    The object has no Pydantic/JSON representation, redacts both ``str`` and
    ``repr``, and clears its mutable backing buffer after extraction.  The
    extracted string is intentionally the caller's transport responsibility.
    """

    __slots__ = ("_buffer",)

    def __init__(self, token: str) -> None:
        if not isinstance(token, str) or not token:
            raise ValueError("Enrollment token is invalid")
        self._buffer = bytearray(token.encode("ascii"))

    def take(self) -> str:
        if not self._buffer:
            raise ValueError("Enrollment token is no longer available")
        try:
            return bytes(self._buffer).decode("ascii")
        finally:
            self._buffer[:] = b"\0" * len(self._buffer)
            self._buffer.clear()

    reveal_once = take

    def __str__(self) -> str:
        return "EnrollmentToken(redacted)"

    def __repr__(self) -> str:
        return "EnrollmentToken(redacted)"

    def __reduce__(self) -> Never:
        raise TypeError("Enrollment token cannot be serialized")


class EnrollmentChallengeIssue:
    """The one-time token delivery envelope; only ``challenge`` is serializable."""

    __slots__ = ("challenge", "token")

    def __init__(self, challenge: EnrollmentChallenge, token: EnrollmentToken) -> None:
        self.challenge = challenge
        self.token = token

    def __repr__(self) -> str:
        return f"EnrollmentChallengeIssue(challenge={self.challenge!r}, token=redacted)"

    def __reduce__(self) -> Never:
        raise TypeError("Enrollment challenge token cannot be serialized")


class RunnerIdentity(RunnerIdentityModel):
    """Pinned runner identity that contains a public-key digest, never key bytes."""

    schema_version: Literal["cargomesh.runner-identity/v1"] = RUNNER_IDENTITY_SCHEMA_VERSION
    runner_id: RunnerId
    tenant_id: RunnerIdentifier
    environment_id: RunnerIdentifier
    runner_pool: RunnerName
    task_queue_id: QueueId
    public_key_digest: Sha256Digest
    capabilities: tuple[RunnerName, ...] = Field(min_length=1, max_length=64)
    platform: RunnerName
    version: RunnerVersion
    enrolled_at: datetime
    identity_digest: Sha256Digest

    def __init__(self, **data: object) -> None:
        try:
            super().__init__(**data)
        except Exception:
            raise ValueError("Runner identity is invalid") from None

    @field_validator("enrolled_at")
    @classmethod
    def require_utc(cls, value: datetime) -> datetime:
        return _utc(value, "runner enrollment time")

    @model_validator(mode="after")
    def validate_identity(self) -> RunnerIdentity:
        if len(self.capabilities) != len(set(self.capabilities)):
            raise ValueError("runner capabilities must be unique")
        if self.identity_digest != model_digest(self, exclude={"identity_digest"}):
            raise ValueError("runner identity digest does not match")
        return self

    @classmethod
    def issue(cls, **values: object) -> RunnerIdentity:
        return cast(
            RunnerIdentity,
            issue_model(
                cls,
                values,
                digest_field="identity_digest",
                schema_version=RUNNER_IDENTITY_SCHEMA_VERSION,
            ),
        )


class RunnerRecord(RunnerIdentityModel):
    """Current metadata-only runner state, emitted as an immutable snapshot."""

    schema_version: Literal["cargomesh.runner-record/v1"] = RUNNER_RECORD_SCHEMA_VERSION
    identity: RunnerIdentity
    health: RunnerHealth
    last_heartbeat_at: datetime | None = None
    revoked_at: datetime | None = None
    record_digest: Sha256Digest

    @field_validator("last_heartbeat_at", "revoked_at")
    @classmethod
    def require_utc(cls, value: datetime | None) -> datetime | None:
        return None if value is None else _utc(value, "runner record timestamps")

    @model_validator(mode="after")
    def validate_record(self) -> RunnerRecord:
        if self.health is RunnerHealth.REVOKED and self.revoked_at is None:
            raise ValueError("revoked runner requires revocation time")
        if self.health is not RunnerHealth.REVOKED and self.revoked_at is not None:
            raise ValueError("only revoked runners carry revocation time")
        if (
            self.last_heartbeat_at is not None
            and self.last_heartbeat_at < self.identity.enrolled_at
        ):
            raise ValueError("runner heartbeat cannot precede enrollment")
        if self.record_digest != model_digest(self, exclude={"record_digest"}):
            raise ValueError("runner record digest does not match")
        return self

    @classmethod
    def issue(cls, **values: object) -> RunnerRecord:
        return cast(
            RunnerRecord,
            issue_model(
                cls,
                values,
                digest_field="record_digest",
                schema_version=RUNNER_RECORD_SCHEMA_VERSION,
            ),
        )


def sha256_digest(value: str) -> str:
    """Return the safe SHA-256 representation used for challenge and key identity."""

    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def model_digest(model: BaseModel, *, exclude: set[str]) -> str:
    return value_digest(model.model_dump(mode="python", exclude=exclude, warnings=False))


def value_digest(value: object) -> str:
    canonical = json.dumps(
        canonical_value(value),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def canonical_value(value: object) -> object:
    if isinstance(value, BaseModel):
        return canonical_value(value.model_dump(mode="python"))
    if isinstance(value, datetime):
        return _utc(value, "canonical timestamps").isoformat(timespec="microseconds")
    if isinstance(value, Enum):
        return canonical_value(value.value)
    if isinstance(value, Mapping):
        return {str(key): canonical_value(item) for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        return [canonical_value(item) for item in value]
    return value


def issue_model(
    model_type: type[RunnerIdentity] | type[RunnerRecord],
    values: Mapping[str, object],
    *,
    digest_field: str,
    schema_version: str,
) -> RunnerIdentity | RunnerRecord:
    payload = dict(values)
    payload.setdefault("schema_version", schema_version)
    unsigned = model_type.model_construct(_fields_set=set(payload), **payload)
    payload[digest_field] = model_digest(unsigned, exclude={digest_field})
    return model_type.model_validate(payload)


def _utc(value: datetime, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must include a timezone")
    return value.astimezone(UTC)


__all__ = [
    "ENROLLMENT_CHALLENGE_SCHEMA_VERSION",
    "RUNNER_IDENTITY_SCHEMA_VERSION",
    "RUNNER_RECORD_SCHEMA_VERSION",
    "ChallengeId",
    "EnrollmentChallenge",
    "EnrollmentChallengeIssue",
    "EnrollmentToken",
    "RunnerHealth",
    "RunnerIdentity",
    "RunnerRecord",
    "sha256_digest",
]
