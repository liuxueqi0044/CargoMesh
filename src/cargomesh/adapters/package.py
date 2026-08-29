"""Integrity-checked loading for versioned browser adapter packages."""

from __future__ import annotations

import json
from collections.abc import Callable, Iterable
from hashlib import sha256
from importlib import resources
from importlib.resources.abc import Traversable
from pathlib import Path

from pydantic import ValidationError

from cargomesh import __version__

from .contracts import AdapterManifest, BrowserRecipe, LoadedAdapterPackage

_MAX_FILE_BYTES = 1024 * 1024


class AdapterPackageError(ValueError):
    """A safe, stable failure emitted while loading an adapter package."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def load_adapter_package(path: Path | str) -> LoadedAdapterPackage:
    """Load a package from a safe filesystem directory without networking."""

    root = Path(path)
    if root.is_symlink():
        raise AdapterPackageError("unsafe_path", "adapter package root must not be a symlink")
    if not root.is_dir():
        raise AdapterPackageError("invalid_path", "adapter package path must be a directory")
    try:
        resolved_root = root.resolve(strict=True)
    except OSError as error:
        raise AdapterPackageError("invalid_path", "adapter package path is not readable") from error

    def read_file(name: str) -> bytes:
        return _read_filesystem_file(resolved_root, name)

    return _load_package(read_file, _filesystem_recipe_files(resolved_root))


def load_builtin_synthetic_package() -> LoadedAdapterPackage:
    """Load CargoMesh's checksum-pinned synthetic browser adapter package."""

    root = resources.files("cargomesh.adapters.data")

    def read_file(name: str) -> bytes:
        return _read_resource_file(root, name)

    recipe_files = {
        item.name
        for item in root.iterdir()
        if item.is_file() and item.name.endswith(".recipe.json")
    }
    return _load_package(read_file, recipe_files)


def _load_package(
    read_file: Callable[[str], bytes], recipe_files: Iterable[str]
) -> LoadedAdapterPackage:
    manifest_data = _parse_json(read_file("manifest.json"), "manifest")
    try:
        manifest = AdapterManifest.model_validate(manifest_data)
    except ValidationError:
        raise AdapterPackageError(
            "invalid_manifest", "adapter manifest does not match its contract"
        ) from None
    if _semver_key(manifest.minimum_cargomesh_version) > _semver_key(__version__):
        raise AdapterPackageError(
            "incompatible_runtime",
            "adapter package requires a newer CargoMesh runtime",
        )

    declared_files = {reference.file for reference in manifest.operations.values()}
    extras = set(recipe_files) - declared_files
    if extras:
        raise AdapterPackageError("extra_recipe", "adapter package contains an unreferenced recipe")

    recipes: dict[str, BrowserRecipe] = {}
    for operation, reference in manifest.operations.items():
        raw_recipe = read_file(reference.file)
        actual_digest = f"sha256:{sha256(raw_recipe).hexdigest()}"
        if actual_digest != reference.sha256:
            raise AdapterPackageError(
                "digest_mismatch", "recipe digest does not match the manifest"
            )
        recipe_data = _parse_json(raw_recipe, "recipe")
        try:
            recipe = BrowserRecipe.model_validate(recipe_data)
        except ValidationError:
            raise AdapterPackageError(
                "invalid_recipe", "browser recipe does not match its contract"
            ) from None
        if recipe.operation != operation:
            raise AdapterPackageError(
                "operation_mismatch", "browser recipe operation does not match the manifest"
            )
        if recipe.capability not in manifest.capabilities:
            raise AdapterPackageError(
                "undeclared_capability", "browser recipe capability is not declared by the manifest"
            )
        recipes[operation] = recipe

    try:
        return LoadedAdapterPackage(manifest=manifest, recipes=recipes)
    except ValidationError:
        raise AdapterPackageError(
            "invalid_package", "adapter package entries are inconsistent"
        ) from None


def _read_filesystem_file(root: Path, name: str) -> bytes:
    candidate = root / name
    if candidate.is_symlink():
        raise AdapterPackageError("unsafe_path", "adapter package files must not be symlinks")
    try:
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError:
        raise AdapterPackageError("missing_file", "adapter package file is missing") from None
    except OSError:
        raise AdapterPackageError(
            "unsafe_path", "adapter package file cannot be safely resolved"
        ) from None
    if root not in resolved.parents or not resolved.is_file():
        raise AdapterPackageError("unsafe_path", "adapter package file escapes its package root")
    try:
        raw = resolved.read_bytes()
    except OSError:
        raise AdapterPackageError(
            "unreadable_file", "adapter package file cannot be read"
        ) from None
    return _limit_file_size(raw)


def _read_resource_file(root: Traversable, name: str) -> bytes:
    candidate = root.joinpath(name)
    if not candidate.is_file():
        raise AdapterPackageError("missing_file", "adapter package file is missing")
    try:
        raw = candidate.read_bytes()
    except OSError:
        raise AdapterPackageError(
            "unreadable_file", "adapter package file cannot be read"
        ) from None
    return _limit_file_size(raw)


def _filesystem_recipe_files(root: Path) -> set[str]:
    recipe_files: set[str] = set()
    try:
        candidates = root.rglob("*.recipe.json")
        for candidate in candidates:
            if candidate.is_symlink():
                raise AdapterPackageError(
                    "unsafe_path", "adapter package files must not be symlinks"
                )
            if candidate.is_file():
                recipe_files.add(candidate.relative_to(root).as_posix())
    except OSError:
        raise AdapterPackageError(
            "unreadable_file", "adapter package files cannot be listed"
        ) from None
    return recipe_files


def _limit_file_size(raw: bytes) -> bytes:
    if len(raw) > _MAX_FILE_BYTES:
        raise AdapterPackageError("file_too_large", "adapter package files must not exceed 1 MiB")
    return raw


def _parse_json(raw: bytes, document_type: str) -> dict[str, object]:
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise AdapterPackageError(
            "invalid_json", f"{document_type} must be strict UTF-8 JSON"
        ) from None
    try:
        parsed = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_non_standard_constant,
        )
    except (TypeError, ValueError, json.JSONDecodeError):
        raise AdapterPackageError(
            "invalid_json", f"{document_type} must be strict UTF-8 JSON"
        ) from None
    if not isinstance(parsed, dict):
        raise AdapterPackageError("invalid_json", f"{document_type} must be a JSON object")
    return parsed


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _reject_non_standard_constant(value: str) -> object:
    raise ValueError(f"non-standard JSON constant: {value}")


def _semver_key(value: str) -> tuple[int, int, int]:
    major, minor, patch = value.split(".")
    return int(major), int(minor), int(patch)
