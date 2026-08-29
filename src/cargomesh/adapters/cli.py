"""CLI integrity check for checksum-pinned adapter packages."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .package import AdapterPackageError, load_adapter_package, load_builtin_synthetic_package


def main(argv: list[str] | None = None) -> int:
    """Run ``cargomesh-adapter check [--path PATH]``."""

    parser = argparse.ArgumentParser(description="Verify a CargoMesh adapter package")
    parser.add_argument("command", choices=("check",))
    parser.add_argument("--path", type=Path, help="filesystem adapter package directory")
    arguments = parser.parse_args(argv)
    try:
        package = (
            load_builtin_synthetic_package()
            if arguments.path is None
            else load_adapter_package(arguments.path)
        )
    except AdapterPackageError as error:
        _emit({"code": error.code, "message": error.message, "status": "error"})
        return 1

    _emit(
        {
            "capabilities": sorted(package.manifest.capabilities),
            "name": package.manifest.name,
            "operations": sorted(package.recipes),
            "portal_version": package.manifest.portal_version,
            "status": "ok",
            "version": package.manifest.version,
        }
    )
    return 0


def _emit(summary: dict[str, object]) -> None:
    print(json.dumps(summary, ensure_ascii=True, separators=(",", ":"), sort_keys=True))


if __name__ == "__main__":
    raise SystemExit(main())
