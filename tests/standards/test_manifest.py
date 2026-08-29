from __future__ import annotations

from hashlib import sha256
from pathlib import Path

import pytest

from cargomesh.standards import (
    SourceManifest,
    load_source_manifest,
    sync_sources,
    verify_sources,
)
from cargomesh.standards.manifest import SourceDownloadError
from cargomesh.standards.provenance import license_metadata, provenance_records

PROJECT_ROOT = Path(__file__).resolve().parents[2]
MANIFEST_PATH = PROJECT_ROOT / "third_party" / "dcsa" / "SOURCES.yaml"


class FixtureDownloader:
    def __init__(self, payloads: dict[str, bytes]) -> None:
        self.payloads = payloads

    def download(self, url: str) -> bytes:
        return self.payloads[url]


def test_pinned_dcsa_sources_verify_offline() -> None:
    manifest = load_source_manifest(MANIFEST_PATH)

    report = verify_sources(manifest, MANIFEST_PATH.parent)

    assert report.ok
    assert {check.source.source_path for check in report.checks} == {
        "LICENSE",
        "domain/dcsa/dcsa_domain_v2.0.0.yaml",
        "domain/error/error_domain_v1.0.0.yaml",
        "domain/event/event_domain_v2.0.0.yaml",
        "tnt/v2/tnt_v2.3.0.yaml",
    }
    assert all(check.actual_sha256 == check.source.sha256 for check in report.checks)


def test_tampered_vendor_file_fails_digest_verification(tmp_path: Path) -> None:
    manifest = load_source_manifest(MANIFEST_PATH)
    entry = manifest.sources[0]
    tampered_path = tmp_path / entry.path
    tampered_path.parent.mkdir(parents=True)
    tampered_path.write_bytes(b"not the pinned DCSA source")

    report = verify_sources(manifest, tmp_path)

    tampered_check = next(check for check in report.checks if check.source.path == entry.path)
    assert not report.ok
    assert tampered_check.exists
    assert not tampered_check.matches
    assert tampered_check.actual_sha256 != entry.sha256


def test_sync_uses_injected_downloader_and_checks_digest_before_write(tmp_path: Path) -> None:
    content = b"pinned fixture content\n"
    manifest = SourceManifest.model_validate(
        {
            "sources": [
                {
                    "path": "fixture.txt",
                    "source_path": "fixture.txt",
                    "url": "https://fixture.invalid/fixture.txt",
                    "sha256": sha256(content).hexdigest(),
                    "repository": "https://example.invalid/source.git",
                    "commit": "a" * 40,
                    "license": "Apache-2.0",
                }
            ]
        }
    )
    downloader = FixtureDownloader({"https://fixture.invalid/fixture.txt": content})

    result = sync_sources(manifest, tmp_path, downloader)

    assert result.sources[0].written_to.read_bytes() == content
    assert verify_sources(manifest, tmp_path).ok


def test_sync_rejects_tampered_download_without_replacing_existing_file(tmp_path: Path) -> None:
    expected = b"expected"
    manifest = SourceManifest.model_validate(
        {
            "sources": [
                {
                    "path": "fixture.txt",
                    "source_path": "fixture.txt",
                    "url": "https://fixture.invalid/fixture.txt",
                    "sha256": sha256(expected).hexdigest(),
                    "repository": "https://example.invalid/source.git",
                    "commit": "b" * 40,
                    "license": "Apache-2.0",
                }
            ]
        }
    )
    existing = tmp_path / "fixture.txt"
    existing.write_bytes(b"keep me")

    with pytest.raises(SourceDownloadError):
        sync_sources(manifest, tmp_path, FixtureDownloader({manifest.sources[0].url: b"tampered"}))

    assert existing.read_bytes() == b"keep me"


def test_sync_verifies_whole_batch_before_replacing_any_file(tmp_path: Path) -> None:
    first_expected = b"first expected"
    second_expected = b"second expected"
    manifest = SourceManifest.model_validate(
        {
            "sources": [
                {
                    "path": "first.txt",
                    "source_path": "first.txt",
                    "url": "https://fixture.invalid/first.txt",
                    "sha256": sha256(first_expected).hexdigest(),
                    "repository": "https://example.invalid/source.git",
                    "commit": "d" * 40,
                    "license": "Apache-2.0",
                },
                {
                    "path": "second.txt",
                    "source_path": "second.txt",
                    "url": "https://fixture.invalid/second.txt",
                    "sha256": sha256(second_expected).hexdigest(),
                    "repository": "https://example.invalid/source.git",
                    "commit": "d" * 40,
                    "license": "Apache-2.0",
                },
            ]
        }
    )
    first_existing = tmp_path / "first.txt"
    first_existing.write_bytes(b"keep original")
    downloader = FixtureDownloader(
        {
            "https://fixture.invalid/first.txt": first_expected,
            "https://fixture.invalid/second.txt": b"tampered",
        }
    )

    with pytest.raises(SourceDownloadError):
        sync_sources(manifest, tmp_path, downloader)

    assert first_existing.read_bytes() == b"keep original"
    assert not (tmp_path / "second.txt").exists()


def test_manifest_exposes_per_file_provenance_and_license_metadata() -> None:
    manifest = load_source_manifest(MANIFEST_PATH)

    provenance = provenance_records(manifest)
    licenses = license_metadata(manifest)

    assert {record.commit for record in provenance} == {
        "7767437e7a752437538786e64f2734c95b513d52"
    }
    assert {record.license for record in licenses} == {"Apache-2.0"}


def test_manifest_rejects_local_path_escapes() -> None:
    with pytest.raises(ValueError, match="relative path"):
        SourceManifest.model_validate(
            {
                "sources": [
                    {
                        "path": "../outside.txt",
                        "source_path": "fixture.txt",
                        "url": "https://fixture.invalid/fixture.txt",
                        "sha256": "0" * 64,
                        "repository": "https://example.invalid/source.git",
                        "commit": "c" * 40,
                        "license": "Apache-2.0",
                    }
                ]
            }
        )
