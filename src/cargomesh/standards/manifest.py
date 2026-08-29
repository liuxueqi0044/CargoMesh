"""Offline verification and explicit synchronization of pinned source files."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path, PurePosixPath
from tempfile import NamedTemporaryFile
from typing import Literal, Protocol

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator


class SourceManifestEntry(BaseModel):
    """One immutable upstream file and its vendored location."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    path: str = Field(description="Path relative to the local vendor root")
    source_path: str = Field(description="Path in the upstream repository")
    url: str
    sha256: str
    repository: str
    commit: str
    license: str

    @field_validator("path", "source_path")
    @classmethod
    def _relative_posix_path(cls, value: str) -> str:
        if "\\" in value:
            raise ValueError("must use POSIX path separators")
        candidate = PurePosixPath(value)
        if candidate.is_absolute() or ".." in candidate.parts or value.strip() == "":
            raise ValueError("must be a non-empty relative path without '..'")
        return candidate.as_posix()

    @field_validator("sha256")
    @classmethod
    def _sha256_digest(cls, value: str) -> str:
        normalized = value.lower()
        if len(normalized) != 64 or any(char not in "0123456789abcdef" for char in normalized):
            raise ValueError("must be a 64-character lowercase hexadecimal SHA-256 digest")
        return normalized

    @field_validator("commit")
    @classmethod
    def _commit_hash(cls, value: str) -> str:
        if len(value) != 40 or any(char not in "0123456789abcdef" for char in value.lower()):
            raise ValueError("must be a full 40-character git commit hash")
        return value.lower()


class SourceManifest(BaseModel):
    """A collection of fully specified, reproducible third-party sources."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["cargomesh.sources/v1"] = "cargomesh.sources/v1"
    sources: tuple[SourceManifestEntry, ...]

    @field_validator("sources")
    @classmethod
    def _unique_paths(
        cls, entries: tuple[SourceManifestEntry, ...]
    ) -> tuple[SourceManifestEntry, ...]:
        paths = [entry.path for entry in entries]
        if not entries:
            raise ValueError("must contain at least one source")
        if len(paths) != len(set(paths)):
            raise ValueError("contains duplicate local paths")
        return entries


@dataclass(frozen=True, slots=True)
class SourceVerification:
    """The digest check result for one vendored source."""

    source: SourceManifestEntry
    exists: bool
    actual_sha256: str | None
    matches: bool


@dataclass(frozen=True, slots=True)
class VerificationReport:
    """Results of checking every source in a manifest without networking."""

    checks: tuple[SourceVerification, ...]

    @property
    def ok(self) -> bool:
        return all(check.matches for check in self.checks)


@dataclass(frozen=True, slots=True)
class SourceSync:
    """Result for one explicitly downloaded source."""

    source: SourceManifestEntry
    written_to: Path
    sha256: str


@dataclass(frozen=True, slots=True)
class SyncReport:
    """Successful synchronization results."""

    sources: tuple[SourceSync, ...]


class SourceDownloadError(RuntimeError):
    """Raised when downloaded bytes do not agree with the pinned manifest."""


class Downloader(Protocol):
    """Injectable transport boundary used by :func:`sync_sources`."""

    def download(self, url: str) -> bytes:
        """Return the raw bytes at *url* or raise a transport-specific error."""


def load_source_manifest(path: Path | str) -> SourceManifest:
    """Load and validate a YAML source manifest.

    Loading a manifest never accesses the network.  YAML is limited to plain
    data by ``safe_load`` and Pydantic validates paths and digests afterwards.
    """

    manifest_path = Path(path)
    document = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError(f"source manifest {manifest_path} must contain a mapping")
    return SourceManifest.model_validate(document)


def verify_sources(manifest: SourceManifest, root: Path | str) -> VerificationReport:
    """Check vendored bytes against their pinned SHA-256 values, offline."""

    vendor_root = Path(root)
    checks: list[SourceVerification] = []
    for source in manifest.sources:
        candidate = _resolve_vendor_path(vendor_root, source.path)
        if not candidate.is_file():
            checks.append(SourceVerification(source, False, None, False))
            continue
        actual = _digest_file(candidate)
        checks.append(SourceVerification(source, True, actual, actual == source.sha256))
    return VerificationReport(tuple(checks))


def sync_sources(manifest: SourceManifest, root: Path | str, downloader: Downloader) -> SyncReport:
    """Download, verify, then atomically place every source in *manifest*.

    The caller chooses the downloader, making synchronization explicit and
    allowing tests to use a fully offline fixture transport.  No file is
    replaced until every downloaded digest matches the pinned manifest.
    """

    vendor_root = Path(root)
    verified_payloads: list[tuple[SourceManifestEntry, bytes, str]] = []
    for source in manifest.sources:
        payload = downloader.download(source.url)
        actual = sha256(payload).hexdigest()
        if actual != source.sha256:
            raise SourceDownloadError(
                f"digest mismatch for {source.url}: expected {source.sha256}, got {actual}"
            )
        verified_payloads.append((source, payload, actual))

    synced: list[SourceSync] = []
    for source, payload, actual in verified_payloads:
        destination = _resolve_vendor_path(vendor_root, source.path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        with NamedTemporaryFile("wb", dir=destination.parent, delete=False) as temporary:
            temporary.write(payload)
            temporary_path = Path(temporary.name)
        temporary_path.replace(destination)
        synced.append(SourceSync(source, destination, actual))
    return SyncReport(tuple(synced))


def _resolve_vendor_path(root: Path, relative_path: str) -> Path:
    """Resolve an already validated manifest path while resisting root escapes."""

    resolved_root = root.resolve()
    resolved_path = (resolved_root / Path(relative_path)).resolve()
    if resolved_root not in resolved_path.parents and resolved_path != resolved_root:
        raise ValueError(f"vendor path escapes root: {relative_path}")
    return resolved_path


def _digest_file(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as source_file:
        for chunk in iter(lambda: source_file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
