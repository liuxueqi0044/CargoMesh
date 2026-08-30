"""Small, explicit secret-provider boundaries for local execution and tests."""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import Protocol

from .lease import SecretLease
from .models import ResolveContext, SecretRef


class SecretProviderError(RuntimeError):
    """A bounded provider error that deliberately omits reference material."""

    def __init__(self, code: str, message: str = "Secret provider operation failed") -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class SecretProvider(Protocol):
    def resolve(self, ref: SecretRef, context: ResolveContext) -> SecretLease:
        """Resolve one opaque reference into a short-lived lease."""
        ...


_ENV_NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")


class EnvironmentSecretProvider:
    """Resolve only keys explicitly mapped to environment variable names."""

    provider_names = frozenset(("env", "environment"))

    def __init__(
        self,
        allowlist: Mapping[str, str],
        *,
        lease_ttl_seconds: float = 60.0,
        enabled: bool = True,
        environ: Mapping[str, str] | None = None,
    ) -> None:
        if not enabled:
            raise SecretProviderError("provider_disabled", "Environment provider is disabled")
        if not allowlist:
            raise ValueError("environment provider requires a non-empty allowlist")
        if lease_ttl_seconds <= 0 or lease_ttl_seconds > 3600:
            raise ValueError("lease_ttl_seconds is out of bounds")
        normalized: dict[str, str] = {}
        for key, env_name in allowlist.items():
            if not isinstance(key, str) or not isinstance(env_name, str):
                raise ValueError("environment allowlist is invalid")
            # Keys are validated as SecretRef keys without exposing bad input.
            try:
                parsed = SecretRef(provider="env", key=key)
            except Exception as exc:
                raise ValueError("environment allowlist is invalid") from exc
            if not _ENV_NAME_RE.fullmatch(env_name):
                raise ValueError("environment allowlist is invalid")
            normalized[parsed.key] = env_name
        self._allowlist = normalized
        self._ttl = lease_ttl_seconds
        self._environ = os.environ if environ is None else environ

    def resolve(self, ref: SecretRef, context: ResolveContext) -> SecretLease:
        del context
        if ref.provider not in self.provider_names:
            raise SecretProviderError("provider_mismatch")
        env_name = self._allowlist.get(ref.key)
        if env_name is None:
            raise SecretProviderError(
                "secret_not_allowlisted", "Secret reference is not allowlisted"
            )
        value = self._environ.get(env_name)
        if value is None:
            raise SecretProviderError("secret_unavailable", "Secret is unavailable")
        return SecretLease(
            value.encode("utf-8"), datetime.now(UTC) + timedelta(seconds=self._ttl), name=ref.key
        )


class InMemorySecretProvider:
    """Explicitly local/test-only provider; never intended as a production default."""

    provider_names = frozenset(("memory", "in_memory", "test"))

    def __init__(
        self,
        secrets: Mapping[str, bytes | bytearray | str],
        *,
        lease_ttl_seconds: float = 60.0,
    ) -> None:
        if lease_ttl_seconds <= 0 or lease_ttl_seconds > 3600:
            raise ValueError("lease_ttl_seconds is out of bounds")
        self._secrets: dict[str, bytes] = {}
        for key, value in secrets.items():
            if not isinstance(key, str):
                raise ValueError("in-memory secret map is invalid")
            try:
                parsed = SecretRef(provider="memory", key=key)
            except Exception as exc:
                raise ValueError("in-memory secret map is invalid") from exc
            if isinstance(value, str):
                value = value.encode("utf-8")
            self._secrets[parsed.key] = bytes(value)
        self._ttl = lease_ttl_seconds

    def resolve(self, ref: SecretRef, context: ResolveContext) -> SecretLease:
        del context
        if ref.provider not in self.provider_names:
            raise SecretProviderError("provider_mismatch")
        value = self._secrets.get(ref.key)
        if value is None:
            raise SecretProviderError("secret_not_found", "Secret is unavailable")
        return SecretLease(
            value, datetime.now(UTC) + timedelta(seconds=self._ttl), name=ref.key
        )


__all__ = [
    "EnvironmentSecretProvider",
    "InMemorySecretProvider",
    "SecretProvider",
    "SecretProviderError",
]
