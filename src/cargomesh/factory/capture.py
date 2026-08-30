"""Deterministic, metadata-only demonstration capture contracts."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from typing import Annotated, Literal
from urllib.parse import unquote, urlsplit

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

CaptureName = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=128,
        pattern=r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$",
    ),
]
CaptureText = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=256)]
Sha256Digest = Annotated[str, StringConstraints(pattern=r"^sha256:[0-9a-f]{64}$")]
MAX_CAPTURE_ACTIONS = 100
MAX_CAPTURE_JSON_BYTES = 65_536
MAX_CAPTURE_JSON_DEPTH = 8
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class FactoryCaptureError(ValueError):
    """Bounded factory input error which never includes captured values."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class CaptureModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        populate_by_name=True,
        str_strip_whitespace=True,
    )


class SemanticLocator(CaptureModel):
    """An allowlisted semantic locator; CSS/XPath/JS are not representable."""

    kind: Literal["role", "label", "test_id", "text", "placeholder"]
    value: CaptureText
    exact: bool = True


class ClickAction(CaptureModel):
    kind: Literal["click"] = "click"
    locator: SemanticLocator


class FillAction(CaptureModel):
    kind: Literal["fill"] = "fill"
    locator: SemanticLocator
    parameter: CaptureName


class SelectAction(CaptureModel):
    kind: Literal["select"] = "select"
    locator: SemanticLocator
    parameter: CaptureName


class AssertAction(CaptureModel):
    kind: Literal["assert"] = "assert"
    locator: SemanticLocator
    expectation_digest: Sha256Digest


CaptureAction = Annotated[
    ClickAction | FillAction | SelectAction | AssertAction,
    Field(discriminator="kind"),
]


class DemonstrationCapture(CaptureModel):
    """Digest-bound page/action metadata with no screenshot, HTML, or values."""

    page_signature: Sha256Digest
    url_path: CaptureText
    actions: tuple[CaptureAction, ...] = Field(min_length=1, max_length=MAX_CAPTURE_ACTIONS)
    capture_digest: Sha256Digest

    @model_validator(mode="after")
    def validate_capture(self) -> DemonstrationCapture:
        _validate_relative_path(self.url_path)
        _validate_metadata(self.model_dump(mode="python", exclude={"capture_digest"}))
        if self.capture_digest != _digest(
            self.model_dump(mode="python", exclude={"capture_digest"})
        ):
            raise ValueError("capture digest does not match metadata")
        return self

    @classmethod
    def issue(
        cls,
        *,
        page_signature: str,
        url_path: str,
        actions: Sequence[CaptureAction],
    ) -> DemonstrationCapture:
        values: dict[str, object] = {
            "page_signature": page_signature,
            "url_path": url_path,
            "actions": tuple(actions),
        }
        values["capture_digest"] = _digest(values)
        return cls.model_validate(values)

    @property
    def digest(self) -> str:
        return self.capture_digest


def _validate_relative_path(path: str) -> None:
    parsed = urlsplit(path)
    decoded_segments = unquote(parsed.path).replace("\\", "/").split("/")
    if (
        not path.startswith("/")
        or path.startswith("//")
        or parsed.scheme
        or parsed.netloc
        or parsed.query
        or parsed.fragment
        or ".." in decoded_segments
        or "\\" in path
    ):
        raise ValueError("capture URL must be a query-free same-origin relative path")


def _validate_metadata(value: object, depth: int = 0) -> None:
    if depth > MAX_CAPTURE_JSON_DEPTH:
        raise ValueError("capture metadata exceeds maximum nesting depth")
    if isinstance(value, Mapping):
        for key, item in value.items():
            key_text = str(key).lower()
            if any(
                token in key_text
                for token in ("secret", "token", "password", "cookie", "authorization")
            ):
                raise ValueError("capture metadata contains a secret-like key")
            if any(token in key_text for token in ("screenshot", "html", "body", "payload", "raw")):
                raise ValueError("capture metadata contains raw document data")
            _validate_metadata(item, depth + 1)
    elif isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        for item in value:
            _validate_metadata(item, depth + 1)
    elif isinstance(value, bytes | bytearray):
        raise ValueError("capture metadata must be JSON")
    try:
        encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("capture metadata must be bounded JSON") from exc
    if len(encoded) > MAX_CAPTURE_JSON_BYTES:
        raise ValueError("capture metadata exceeds size limit")


def _canonical(value: object) -> object:
    if isinstance(value, BaseModel):
        return _canonical(value.model_dump(mode="python"))
    if isinstance(value, Mapping):
        return {str(key): _canonical(item) for key, item in value.items()}
    if isinstance(value, tuple | list):
        return [_canonical(item) for item in value]
    return value


def _digest(value: object) -> str:
    encoded = json.dumps(
        _canonical(value), ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


__all__ = [
    "MAX_CAPTURE_ACTIONS",
    "MAX_CAPTURE_JSON_BYTES",
    "MAX_CAPTURE_JSON_DEPTH",
    "AssertAction",
    "CaptureAction",
    "CaptureName",
    "ClickAction",
    "DemonstrationCapture",
    "FactoryCaptureError",
    "FillAction",
    "SelectAction",
    "SemanticLocator",
    "Sha256Digest",
]
