"""Conservative structural compatibility reports for OpenAPI/YAML contracts."""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, computed_field

_IGNORED_METADATA = frozenset({"description", "example", "examples", "title"})
_CONSTRAINT_KEYS = frozenset(
    {"type", "format", "pattern", "minimum", "maximum", "minLength", "maxLength", "$ref"}
)


class ChangeKind(StrEnum):
    ADDED = "ADDED"
    REMOVED = "REMOVED"
    CONSTRAINT_CHANGED = "CONSTRAINT_CHANGED"
    REQUIRED_ADDED = "REQUIRED_ADDED"
    REQUIRED_REMOVED = "REQUIRED_REMOVED"
    ENUM_VALUE_ADDED = "ENUM_VALUE_ADDED"
    ENUM_VALUE_REMOVED = "ENUM_VALUE_REMOVED"


class CompatibilityChange(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    path: str
    kind: ChangeKind
    breaking: bool
    before: Any = None
    after: Any = None


class CompatibilityReport(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    changes: tuple[CompatibilityChange, ...]

    @computed_field  # type: ignore[prop-decorator]
    @property
    def breaking(self) -> bool:
        return any(change.breaking for change in self.changes)


def load_yaml_document(path: Path | str) -> dict[str, Any]:
    document = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError("contract document must contain a mapping")
    return document


def compare_contracts(
    baseline: dict[str, Any],
    candidate: dict[str, Any],
) -> CompatibilityReport:
    """Return a stable, conservative change list without mutating either input."""

    changes: list[CompatibilityChange] = []
    _compare_node(baseline, candidate, "", changes)
    return CompatibilityReport(changes=tuple(sorted(changes, key=_change_sort_key)))


def compare_contract_files(
    baseline: Path | str,
    candidate: Path | str,
) -> CompatibilityReport:
    return compare_contracts(load_yaml_document(baseline), load_yaml_document(candidate))


def _compare_node(
    before: Any,
    after: Any,
    path: str,
    changes: list[CompatibilityChange],
) -> None:
    if isinstance(before, dict) and isinstance(after, dict):
        for key in sorted(before.keys() | after.keys(), key=str):
            if key in _IGNORED_METADATA:
                continue
            child_path = f"{path}/{_escape_pointer(str(key))}"
            if key not in after:
                changes.append(
                    CompatibilityChange(
                        path=child_path,
                        kind=ChangeKind.REMOVED,
                        breaking=True,
                        before=before[key],
                    )
                )
            elif key not in before:
                changes.append(
                    CompatibilityChange(
                        path=child_path,
                        kind=ChangeKind.ADDED,
                        breaking=_new_node_is_required(after, key),
                        after=after[key],
                    )
                )
            else:
                _compare_node(before[key], after[key], child_path, changes)
        return

    key = path.rsplit("/", 1)[-1]
    if key in {"required", "enum"} and isinstance(before, list) and isinstance(after, list):
        removed = sorted(set(before) - set(after), key=str)
        added = sorted(set(after) - set(before), key=str)
        if key == "required":
            _append_set_changes(
                changes,
                path,
                removed,
                added,
                ChangeKind.REQUIRED_REMOVED,
                ChangeKind.REQUIRED_ADDED,
                removed_breaking=False,
                added_breaking=True,
            )
        else:
            _append_set_changes(
                changes,
                path,
                removed,
                added,
                ChangeKind.ENUM_VALUE_REMOVED,
                ChangeKind.ENUM_VALUE_ADDED,
                removed_breaking=True,
                added_breaking=False,
            )
        return

    if before != after and key in _CONSTRAINT_KEYS:
        changes.append(
            CompatibilityChange(
                path=path,
                kind=ChangeKind.CONSTRAINT_CHANGED,
                breaking=True,
                before=before,
                after=after,
            )
        )


def _append_set_changes(
    changes: list[CompatibilityChange],
    path: str,
    removed: list[Any],
    added: list[Any],
    removed_kind: ChangeKind,
    added_kind: ChangeKind,
    *,
    removed_breaking: bool,
    added_breaking: bool,
) -> None:
    for value in removed:
        changes.append(
            CompatibilityChange(
                path=path,
                kind=removed_kind,
                breaking=removed_breaking,
                before=value,
            )
        )
    for value in added:
        changes.append(
            CompatibilityChange(
                path=path,
                kind=added_kind,
                breaking=added_breaking,
                after=value,
            )
        )


def _new_node_is_required(parent: dict[str, Any], key: object) -> bool:
    required = parent.get("required", ())
    return isinstance(required, list) and key in required


def _escape_pointer(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


def _change_sort_key(change: CompatibilityChange) -> tuple[str, str, str, str]:
    return (change.path, change.kind.value, repr(change.before), repr(change.after))
