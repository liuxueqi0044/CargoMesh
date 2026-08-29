"""Resolve supported SwaggerHub domain references to pinned local files."""

from __future__ import annotations

from copy import deepcopy
from os.path import relpath
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlsplit

_SWAGGERHUB_PREFIX = "/domains/dcsaorg/"
_DOMAIN_FILES = {
    ("EVENT_DOMAIN", "2.0.0"): "domain/event/event_domain_v2.0.0.yaml",
    ("DCSA_DOMAIN", "2.0.0"): "domain/dcsa/dcsa_domain_v2.0.0.yaml",
    ("ERROR_DOMAIN", "1.0.0"): "domain/error/error_domain_v1.0.0.yaml",
}


class UnsupportedReferenceError(ValueError):
    """A remote contract reference is not present in the supported snapshot."""


def normalize_dcsa_references(
    document: dict[str, Any],
    *,
    document_path: Path | str,
    vendor_root: Path | str,
) -> dict[str, Any]:
    """Return a copy with supported SwaggerHub refs replaced by local refs.

    Unknown remote DCSA domains fail closed. Other HTTPS references are retained
    because CargoMesh does not claim ownership of their resolution.
    """

    source_path = Path(document_path).resolve()
    root = Path(vendor_root).resolve()
    if root not in source_path.parents:
        raise ValueError("document_path must be inside vendor_root")
    normalized = deepcopy(document)
    _rewrite_node(normalized, source_path.parent, root)
    return normalized


def _rewrite_node(node: Any, source_directory: Path, vendor_root: Path) -> None:
    if isinstance(node, dict):
        reference = node.get("$ref")
        if isinstance(reference, str):
            node["$ref"] = _local_reference(reference, source_directory, vendor_root)
        for value in node.values():
            _rewrite_node(value, source_directory, vendor_root)
    elif isinstance(node, list):
        for value in node:
            _rewrite_node(value, source_directory, vendor_root)


def _local_reference(reference: str, source_directory: Path, vendor_root: Path) -> str:
    parsed = urlsplit(reference)
    if parsed.netloc != "api.swaggerhub.com" or not parsed.path.startswith(_SWAGGERHUB_PREFIX):
        return reference
    parts = parsed.path.removeprefix(_SWAGGERHUB_PREFIX).strip("/").split("/")
    if len(parts) != 2:
        raise UnsupportedReferenceError(f"unsupported SwaggerHub reference: {reference}")
    try:
        target_relative = _DOMAIN_FILES[(parts[0], parts[1])]
    except KeyError as exc:
        raise UnsupportedReferenceError(
            f"DCSA domain is not in the supported offline snapshot: {parts[0]}/{parts[1]}"
        ) from exc
    target = (vendor_root / Path(target_relative)).resolve()
    if not target.is_file():
        raise UnsupportedReferenceError(f"pinned reference file is missing: {target_relative}")
    relative = PurePosixPath(*Path(relpath(target, start=source_directory)).parts).as_posix()
    fragment = f"#{parsed.fragment}" if parsed.fragment else ""
    return f"{relative}{fragment}"
