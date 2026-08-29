"""Structured provenance and license views for pinned standard sources."""

from __future__ import annotations

from dataclasses import dataclass

from .manifest import SourceManifest, SourceManifestEntry


@dataclass(frozen=True, slots=True)
class ProvenanceRecord:
    """Audit metadata identifying the exact origin of a vendored file."""

    path: str
    source_path: str
    repository: str
    commit: str
    sha256: str
    license: str


@dataclass(frozen=True, slots=True)
class LicenseMetadata:
    """License attribution attached to a specific vendored source."""

    path: str
    license: str
    repository: str
    commit: str


def provenance_records(manifest: SourceManifest) -> tuple[ProvenanceRecord, ...]:
    """Return audit-ready provenance for every entry in a manifest."""

    return tuple(_to_provenance(entry) for entry in manifest.sources)


def license_metadata(manifest: SourceManifest) -> tuple[LicenseMetadata, ...]:
    """Return license attribution for every entry in a manifest."""

    return tuple(
        LicenseMetadata(entry.path, entry.license, entry.repository, entry.commit)
        for entry in manifest.sources
    )


def _to_provenance(entry: SourceManifestEntry) -> ProvenanceRecord:
    return ProvenanceRecord(
        path=entry.path,
        source_path=entry.source_path,
        repository=entry.repository,
        commit=entry.commit,
        sha256=entry.sha256,
        license=entry.license,
    )
