"""Opaque, bounded storage boundary for sensitive browser debug artifacts."""

from __future__ import annotations

import asyncio
import hashlib
import uuid
from pathlib import Path
from typing import Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field


class ArtifactDescriptor(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    artifact_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    kind: Literal["playwright_trace"]
    content_type: Literal["application/zip"] = "application/zip"
    size_bytes: int = Field(ge=1)
    sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")


class ArtifactSink(Protocol):
    async def store(
        self, *, kind: Literal["playwright_trace"], content: bytes
    ) -> ArtifactDescriptor:
        """Store sensitive bytes and return metadata without a filesystem path."""


class ArtifactTooLarge(ValueError):
    pass


class InMemoryArtifactSink:
    """Test-only sink retaining bytes by opaque id."""

    def __init__(self, *, max_bytes: int = 25 * 1024 * 1024) -> None:
        self._max_bytes = max_bytes
        self.items: dict[str, bytes] = {}

    async def store(
        self, *, kind: Literal["playwright_trace"], content: bytes
    ) -> ArtifactDescriptor:
        descriptor = _descriptor(kind, content, max_bytes=self._max_bytes)
        self.items[descriptor.artifact_id] = bytes(content)
        return descriptor


class FileArtifactSink:
    """Explicit local sink; artifact paths never cross the adapter boundary."""

    def __init__(self, root: Path, *, max_bytes: int = 25 * 1024 * 1024) -> None:
        if max_bytes <= 0:
            raise ValueError("max_bytes must be positive")
        self._root = root.resolve()
        self._root.mkdir(parents=True, exist_ok=True)
        if not self._root.is_dir():
            raise ValueError("artifact root must be a directory")
        self._max_bytes = max_bytes

    async def store(
        self, *, kind: Literal["playwright_trace"], content: bytes
    ) -> ArtifactDescriptor:
        descriptor = _descriptor(kind, content, max_bytes=self._max_bytes)
        await asyncio.to_thread(self._write, descriptor.artifact_id, content)
        return descriptor

    def _write(self, artifact_id: str, content: bytes) -> None:
        target = self._root / f"{artifact_id}.trace.zip"
        with target.open("xb") as stream:
            stream.write(content)


def _descriptor(
    kind: Literal["playwright_trace"], content: bytes, *, max_bytes: int
) -> ArtifactDescriptor:
    if not content:
        raise ValueError("artifact content must not be empty")
    if len(content) > max_bytes:
        raise ArtifactTooLarge("artifact exceeds configured size limit")
    return ArtifactDescriptor(
        artifact_id=uuid.uuid4().hex,
        kind=kind,
        size_bytes=len(content),
        sha256="sha256:" + hashlib.sha256(content).hexdigest(),
    )
