"""Command line entry point for explicit DCSA source checks and synchronization."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from urllib.request import urlopen

from .compatibility import compare_contract_files
from .manifest import SourceManifest, load_source_manifest, sync_sources, verify_sources


class UrlLibDownloader:
    """The opt-in HTTP downloader used only by the ``sync`` CLI command."""

    def download(self, url: str) -> bytes:
        with urlopen(url, timeout=30) as response:
            return bytes(response.read())


def main(argv: list[str] | None = None) -> int:
    """Run ``cargomesh-dcsa check`` or ``cargomesh-dcsa sync``."""

    parser = argparse.ArgumentParser(description="Check or synchronize pinned DCSA files")
    parser.add_argument("command", choices=("check", "sync", "diff"))
    parser.add_argument(
        "--manifest",
        type=Path,
        default=_default_manifest_path(),
        help="path to SOURCES.yaml (defaults to CargoMesh's vendored DCSA manifest)",
    )
    parser.add_argument("--baseline", type=Path, help="baseline OpenAPI/YAML for diff")
    parser.add_argument("--candidate", type=Path, help="candidate OpenAPI/YAML for diff")
    arguments = parser.parse_args(argv)
    if arguments.command == "diff":
        if arguments.baseline is None or arguments.candidate is None:
            parser.error("diff requires --baseline and --candidate")
        report = compare_contract_files(arguments.baseline, arguments.candidate)
        print(json.dumps(report.model_dump(mode="json"), indent=2, sort_keys=True))
        return 2 if report.breaking else 0
    manifest = load_source_manifest(arguments.manifest)
    vendor_root = arguments.manifest.parent
    if arguments.command == "check":
        return _check(manifest, vendor_root)
    sync_sources(manifest, vendor_root, UrlLibDownloader())
    return _check(manifest, vendor_root)


def _check(manifest: SourceManifest, vendor_root: Path) -> int:
    report = verify_sources(manifest, vendor_root)
    for check in report.checks:
        status = "ok" if check.matches else "FAILED"
        actual = check.actual_sha256 or "missing"
        print(f"{status:6} {check.source.path} expected={check.source.sha256} actual={actual}")
    return 0 if report.ok else 1


def _default_manifest_path() -> Path:
    source_checkout = Path(__file__).resolve().parents[3] / "third_party" / "dcsa" / "SOURCES.yaml"
    if source_checkout.is_file():
        return source_checkout
    return Path(__file__).resolve().with_name("vendor") / "dcsa" / "SOURCES.yaml"


if __name__ == "__main__":
    raise SystemExit(main())
