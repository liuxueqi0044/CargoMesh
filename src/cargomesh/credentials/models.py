"""Opaque credential references and resolution context contracts."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from datetime import UTC, datetime
from enum import Enum
from typing import Annotated, Literal

from pydantic import (
    AliasChoices,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

SECRET_REF_SCHEMA_VERSION: Literal["cargomesh.secret-ref/v1"] = "cargomesh.secret-ref/v1"
CREDENTIAL_BINDING_SCHEMA_VERSION: Literal[
    "cargomesh.credential-binding/v1"
] = "cargomesh.credential-binding/v1"

_IDENTIFIER = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=1, max_length=256),
]
_NAME = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=128,
        pattern=r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$",
    ),
]
_OPAQUE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$")
_SECRET_NAME_RE = re.compile(
    r"(?:^|[._-])(authorization|cookie|credential|password|secret|token|api[_-]?key)"
    r"(?:$|[._-])",
    re.IGNORECASE,
)


class CredentialModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


def _canonical(value: object) -> object:
    if isinstance(value, BaseModel):
        return _canonical(value.model_dump(mode="python"))
    if isinstance(value, datetime):
        return value.astimezone(UTC).isoformat(timespec="microseconds")
    if isinstance(value, Enum):
        return _canonical(value.value)
    if isinstance(value, Mapping):
        return {str(k): _canonical(v) for k, v in value.items()}
    if isinstance(value, (tuple, list)):
        return [_canonical(item) for item in value]
    return value


def _digest(value: object) -> str:
    payload = json.dumps(
        _canonical(value), ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _reject_opaque(value: str, label: str) -> str:
    # A deliberately narrow grammar makes URI credentials, paths, inline values,
    # and whitespace impossible rather than attempting to blacklist every form.
    if not _OPAQUE_RE.fullmatch(value) or ".." in value:
        raise ValueError(f"invalid {label}")
    if _SECRET_NAME_RE.search(value):
        raise ValueError(f"invalid {label}")
    return value


class SecretRef(CredentialModel):
    """A provider-qualified opaque handle; it never contains secret bytes."""

    schema_version: Literal["cargomesh.secret-ref/v1"] = SECRET_REF_SCHEMA_VERSION
    provider: _NAME
    key: _IDENTIFIER
    version: _IDENTIFIER | None = None

    def __init__(self, **data: object) -> None:
        # Pydantic's normal ValidationError includes input_value in its text.
        # References are security-boundary inputs, so do not echo rejected data.
        try:
            super().__init__(**data)
        except Exception:
            raise ValueError("Secret reference is invalid") from None

    @field_validator("provider")
    @classmethod
    def validate_provider(cls, value: str) -> str:
        return _reject_opaque(value, "secret provider")

    @field_validator("key")
    @classmethod
    def validate_key(cls, value: str) -> str:
        return _reject_opaque(value, "secret reference")

    @field_validator("version")
    @classmethod
    def validate_version(cls, value: str | None) -> str | None:
        return None if value is None else _reject_opaque(value, "secret version")

    @property
    def ref_digest(self) -> str:
        return _digest(self.model_dump())

    @property
    def digest(self) -> str:
        return self.ref_digest


class ResolveContext(CredentialModel):
    """The exact scope in which a reference may be resolved."""

    tenant_id: _IDENTIFIER
    environment_id: _IDENTIFIER
    adapter: _NAME
    capability: _NAME


# Descriptive alias retained for callers that prefer the longer name.
SecretResolutionContext = ResolveContext


class CredentialBinding(CredentialModel):
    """Metadata mapping an adapter capability to named opaque references."""

    schema_version: Literal[
        "cargomesh.credential-binding/v1"
    ] = CREDENTIAL_BINDING_SCHEMA_VERSION
    tenant_id: _IDENTIFIER
    environment_id: _IDENTIFIER
    adapter: _NAME
    capability: _NAME
    # ``references`` and ``secret_refs`` are accepted as input aliases for
    # callers using either wording; ``secrets`` is the canonical persisted name.
    secrets: dict[_NAME, SecretRef] = Field(
        validation_alias=AliasChoices("secrets", "references", "secret_refs"),
        min_length=1,
        max_length=32,
    )
    revision: int = Field(ge=1, le=2**63 - 1)
    binding_digest: str

    @field_validator("secrets")
    @classmethod
    def validate_names(cls, value: dict[str, SecretRef]) -> dict[str, SecretRef]:
        if len(value) != len(set(value)):
            raise ValueError("credential binding names must be unique")
        return value

    @model_validator(mode="after")
    def validate_digest(self) -> CredentialBinding:
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", self.binding_digest):
            raise ValueError("credential binding digest is invalid")
        if self.binding_digest != _digest(self.model_dump(exclude={"binding_digest"})):
            raise ValueError("credential binding digest does not match")
        return self

    @property
    def references(self) -> dict[str, SecretRef]:
        return self.secrets

    @property
    def secret_refs(self) -> dict[str, SecretRef]:
        return self.secrets

    @property
    def identity(self) -> tuple[str, str, str, str]:
        return (self.tenant_id, self.environment_id, self.adapter, self.capability)

    @property
    def digest(self) -> str:
        return self.binding_digest

    @classmethod
    def issue(cls, **values: object) -> CredentialBinding:
        payload = dict(values)
        payload.setdefault("schema_version", CREDENTIAL_BINDING_SCHEMA_VERSION)
        if "secrets" not in payload:
            for alias in ("references", "secret_refs"):
                if alias in payload:
                    payload["secrets"] = payload.pop(alias)
                    break
        unsigned = cls.model_construct(_fields_set=set(payload), **payload)
        payload["binding_digest"] = _digest(unsigned.model_dump(exclude={"binding_digest"}))
        return cls.model_validate(payload)


def validate_binding(value: CredentialBinding) -> CredentialBinding:
    """Re-run validation at provider/storage boundaries."""

    try:
        return CredentialBinding.model_validate(value.model_dump())
    except Exception as exc:
        raise ValueError("credential binding is invalid") from exc


__all__ = [
    "CREDENTIAL_BINDING_SCHEMA_VERSION",
    "SECRET_REF_SCHEMA_VERSION",
    "CredentialBinding",
    "CredentialModel",
    "ResolveContext",
    "SecretRef",
    "SecretResolutionContext",
    "validate_binding",
]
