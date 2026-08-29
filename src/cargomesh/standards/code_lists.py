"""Import versioned code-list records from pinned OpenAPI schema enums."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from .reference_data import ReferenceDataRecord


class OpenAPICodeListImporter:
    """Small importer for enum-backed DCSA code lists.

    The pinned standard remains the authority. Display names may be supplied as
    curated presentation metadata, but cannot add or remove codes.
    """

    def import_schema_enum(
        self,
        document_path: Path | str,
        *,
        schema_name: str,
        namespace: str,
        source_version: str,
        display_names: dict[str, str] | None = None,
    ) -> tuple[ReferenceDataRecord, ...]:
        document = yaml.safe_load(Path(document_path).read_text(encoding="utf-8"))
        schema = _schema(document, schema_name)
        values = schema.get("enum")
        if not isinstance(values, list) or not values:
            raise ValueError(f"schema {schema_name!r} does not define a non-empty enum")
        if not all(isinstance(value, str) and value for value in values):
            raise ValueError(f"schema {schema_name!r} enum must contain non-empty strings")
        enum_values = tuple(str(value) for value in values)
        if len(enum_values) != len(set(enum_values)):
            raise ValueError(f"schema {schema_name!r} enum contains duplicates")
        names = display_names or {}
        unknown_names = names.keys() - set(enum_values)
        if unknown_names:
            raise ValueError("display names contain codes outside the enum")
        return tuple(
            ReferenceDataRecord(
                namespace=namespace,
                code=value,
                name=names.get(value, value),
                version=source_version,
            )
            for value in enum_values
        )


def _schema(document: Any, name: str) -> dict[str, Any]:
    try:
        schema = document["components"]["schemas"][name]
    except (KeyError, TypeError) as exc:
        raise ValueError(f"document does not contain schema {name!r}") from exc
    if not isinstance(schema, dict):
        raise ValueError(f"schema {name!r} must be a mapping")
    return schema
