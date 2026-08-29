"""Deterministic serialization and business digests for Transaction IR."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from datetime import UTC, date, datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel

from .models import TransactionCommand

_DIGEST_EXCLUDED_FIELDS = {"transaction_id", "requested_at"}


def _normalize(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return _normalize(value.model_dump(mode="python", exclude_none=True))
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("canonical datetimes must include a timezone")
        utc_value = value.astimezone(UTC)
        rendered = utc_value.isoformat(timespec="microseconds")
        return rendered.removesuffix("+00:00") + "Z"
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Mapping):
        return {str(key): _normalize(value[key]) for key in sorted(value, key=str)}
    if isinstance(value, tuple | list):
        return [_normalize(item) for item in value]
    if isinstance(value, set | frozenset):
        normalized = [_normalize(item) for item in value]
        return sorted(normalized, key=lambda item: json.dumps(item, sort_keys=True))
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        return [_normalize(item) for item in value]
    return value


def canonical_business_dict(command: TransactionCommand) -> dict[str, Any]:
    """Return the canonicalizable business payload used for idempotency digests."""

    payload = command.model_dump(
        mode="python",
        exclude_none=True,
        exclude=_DIGEST_EXCLUDED_FIELDS,
    )
    normalized = _normalize(payload)
    if not isinstance(normalized, dict):
        raise TypeError("canonical transaction payload must be an object")
    return normalized


def canonical_business_json(command: TransactionCommand) -> str:
    """Serialize a command's business meaning into stable compact JSON."""

    return json.dumps(
        canonical_business_dict(command),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    )


def business_digest(command: TransactionCommand) -> str:
    """Return a content-addressed SHA-256 digest of the canonical business payload."""

    canonical = canonical_business_json(command).encode("utf-8")
    return f"sha256:{hashlib.sha256(canonical).hexdigest()}"
