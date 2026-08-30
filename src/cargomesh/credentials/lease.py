"""Short-lived, deliberately non-serializable secret leases."""

from __future__ import annotations

from builtins import bytes as Bytes
from collections.abc import Callable, Mapping
from contextlib import suppress
from datetime import UTC, datetime
from typing import Any


class SecretLeaseError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class SecretLeaseExpired(SecretLeaseError):
    def __init__(self) -> None:
        super().__init__("secret_lease_expired", "Secret lease has expired")


class SecretLeaseClosed(SecretLeaseError):
    def __init__(self) -> None:
        super().__init__("secret_lease_closed", "Secret lease is closed")


class SecretLease:
    """An ephemeral view over mutable buffers.

    The object intentionally is not a Pydantic model and has no serializable
    representation. Values are copied into bytearrays and wiped on close.
    """

    __slots__ = ("_buffers", "_clock", "_closed", "_default_name", "_expires_at")

    def __init__(
        self,
        value: bytes | bytearray | memoryview | Mapping[str, bytes | bytearray | memoryview],
        expires_at: datetime,
        *,
        name: str = "value",
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if expires_at.tzinfo is None or expires_at.utcoffset() is None:
            raise ValueError("lease expiry must include a timezone")
        if expires_at <= datetime.now(UTC) and clock is None:
            raise ValueError("lease expiry must be in the future")
        self._expires_at = expires_at.astimezone(UTC)
        self._clock = clock or (lambda: datetime.now(UTC))
        self._closed = False
        if isinstance(value, Mapping):
            if not value:
                raise ValueError("lease must contain a value")
            self._buffers = {str(key): bytearray(item) for key, item in value.items()}
            self._default_name = name if name in self._buffers else next(iter(self._buffers))
        else:
            self._buffers = {name: bytearray(value)}
            self._default_name = name

    @property
    def expires_at(self) -> datetime:
        return self._expires_at

    @property
    def expiry(self) -> datetime:
        return self._expires_at

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def is_closed(self) -> bool:
        return self._closed

    @property
    def expired(self) -> bool:
        return self._now() >= self._expires_at

    @property
    def is_expired(self) -> bool:
        return self.expired

    def read(self, name: str | None = None) -> Bytes:
        self._check_open()
        selected = self._default_name if name is None else name
        try:
            return bytes(self._buffers[selected])
        except KeyError as exc:
            raise SecretLeaseError("secret_name_unavailable", "Secret name is unavailable") from exc

    @property
    def value(self) -> Bytes:
        return self.read()

    @property
    def bytes(self) -> Bytes:
        return self.read()

    @property
    def secret(self) -> Bytes:
        return self.read()

    def get(self, name: str, default: Bytes | None = None) -> Bytes | None:
        self._check_open()
        if name not in self._buffers:
            return default
        return bytes(self._buffers[name])

    @property
    def values(self) -> dict[str, Bytes]:
        self._check_open()
        return {name: bytes(value) for name, value in self._buffers.items()}

    def __getitem__(self, name: str) -> Bytes:
        return self.read(name)

    def close(self) -> None:
        if not self._closed:
            for buffer in self._buffers.values():
                buffer[:] = b"\x00" * len(buffer)
            self._closed = True

    def __enter__(self) -> SecretLease:
        self._check_open()
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

    def __del__(self) -> None:
        with suppress(Exception):
            self.close()

    def __repr__(self) -> str:
        return f"<SecretLease closed={self._closed} expired={self.expired}>"

    def _now(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None or value.utcoffset() is None:
            return datetime.now(UTC)
        return value.astimezone(UTC)

    def _check_open(self) -> None:
        if self._closed:
            raise SecretLeaseClosed()
        if self._now() >= self._expires_at:
            self.close()
            raise SecretLeaseExpired()


__all__ = ["SecretLease", "SecretLeaseClosed", "SecretLeaseError", "SecretLeaseExpired"]
