from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path

import pytest

from cargomesh.adapters.package import (
    AdapterPackageError,
    load_adapter_package,
    load_builtin_synthetic_package,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
BUILTIN_ROOT = PROJECT_ROOT / "src" / "cargomesh" / "adapters" / "data"


def _copy_valid_package(tmp_path: Path, name: str = "adapter") -> Path:
    package_root = tmp_path / name
    package_root.mkdir()
    recipe = (BUILTIN_ROOT / "fetch.recipe.json").read_bytes()
    (package_root / "fetch.recipe.json").write_bytes(recipe)
    _write_manifest(package_root, recipe)
    return package_root


def _write_manifest(
    package_root: Path, recipe: bytes, *, minimum_version: str = "0.3.0"
) -> None:
    manifest = {
        "schema_version": "cargomesh.adapter-manifest/v1",
        "name": "synthetic.browser.track",
        "version": "0.1.0",
        "portal_version": "synthetic-portal/v1",
        "minimum_cargomesh_version": minimum_version,
        "capabilities": ["shipment.track.read"],
        "operations": {
            "fetch": {
                "file": "fetch.recipe.json",
                "sha256": f"sha256:{sha256(recipe).hexdigest()}",
            }
        },
    }
    (package_root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")


def test_loads_builtin_synthetic_package_with_pinned_recipe() -> None:
    package = load_builtin_synthetic_package()

    assert package.manifest.name == "synthetic.browser.track"
    assert package.manifest.version == "0.1.0"
    assert package.manifest.portal_version == "synthetic-portal/v1"
    assert package.manifest.minimum_cargomesh_version == "0.3.0"
    assert package.manifest.capabilities == ("shipment.track.read",)
    assert package.recipes["fetch"].operation == "fetch"
    assert package.recipes["fetch"].actions[0].kind == "navigate"
    signatures = {
        (probe.key, probe.locator.kind) for probe in package.recipes["fetch"].portal_signatures
    }
    assert ("booking-field", "label") in signatures


def test_filesystem_load_rejects_raw_byte_tampering(tmp_path: Path) -> None:
    package_root = _copy_valid_package(tmp_path, "extra")
    (package_root / "fetch.recipe.json").write_bytes(b"{}")

    with pytest.raises(AdapterPackageError) as error:
        load_adapter_package(package_root)

    assert error.value.code == "digest_mismatch"


def test_rejects_package_that_requires_a_newer_runtime(tmp_path: Path) -> None:
    package_root = _copy_valid_package(tmp_path)
    recipe = (package_root / "fetch.recipe.json").read_bytes()
    _write_manifest(package_root, recipe, minimum_version="99.0.0")

    with pytest.raises(AdapterPackageError) as error:
        load_adapter_package(package_root)

    assert error.value.code == "incompatible_runtime"


def test_rejects_missing_recipe_and_unreferenced_recipe(tmp_path: Path) -> None:
    package_root = _copy_valid_package(tmp_path)
    (package_root / "fetch.recipe.json").unlink()

    with pytest.raises(AdapterPackageError) as missing:
        load_adapter_package(package_root)
    assert missing.value.code == "missing_file"

    package_root = _copy_valid_package(tmp_path, "extra")
    (package_root / "orphan.recipe.json").write_bytes(b"{}")
    with pytest.raises(AdapterPackageError) as extra:
        load_adapter_package(package_root)
    assert extra.value.code == "extra_recipe"


def test_rejects_symlink_recipe_path_escape(tmp_path: Path) -> None:
    package_root = _copy_valid_package(tmp_path)
    outside = tmp_path / "outside.recipe.json"
    outside.write_bytes((package_root / "fetch.recipe.json").read_bytes())
    (package_root / "fetch.recipe.json").unlink()
    try:
        (package_root / "fetch.recipe.json").symlink_to(outside)
    except OSError:
        pytest.skip("symlinks are unavailable on this platform")

    with pytest.raises(AdapterPackageError) as error:
        load_adapter_package(package_root)
    assert error.value.code == "unsafe_path"


@pytest.mark.parametrize(
    ("field", "value", "code"),
    [
        ("operation", "not-fetch", "operation_mismatch"),
        ("capability", "shipment.write", "undeclared_capability"),
    ],
)
def test_rejects_recipe_manifest_contract_mismatches(
    tmp_path: Path, field: str, value: str, code: str
) -> None:
    package_root = _copy_valid_package(tmp_path)
    recipe_path = package_root / "fetch.recipe.json"
    recipe = json.loads(recipe_path.read_text(encoding="utf-8"))
    recipe[field] = value
    raw = json.dumps(recipe, separators=(",", ":")).encode("utf-8")
    recipe_path.write_bytes(raw)
    _write_manifest(package_root, raw)

    with pytest.raises(AdapterPackageError) as error:
        load_adapter_package(package_root)
    assert error.value.code == code
