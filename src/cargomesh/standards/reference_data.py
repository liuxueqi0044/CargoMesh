"""Versioned reference data with explicit exact and alias lookup semantics."""

from __future__ import annotations

import csv
from collections.abc import Iterable
from datetime import date
from itertools import pairwise
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, field_validator, model_validator


class ReferenceDataRecord(BaseModel):
    """One versioned, temporally valid reference-data value."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    namespace: str
    code: str
    name: str
    aliases: tuple[str, ...] = ()
    version: str
    status: Literal["active", "deprecated"] = "active"
    valid_from: date | None = None
    valid_to: date | None = None

    @field_validator("namespace", "code", "name", "version")
    @classmethod
    def _required_text(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("must not be blank")
        return value

    @field_validator("aliases", mode="before")
    @classmethod
    def _parse_aliases(cls, value: object) -> tuple[str, ...]:
        if value is None or value == "":
            return ()
        if isinstance(value, str):
            return tuple(alias.strip() for alias in value.split("|") if alias.strip())
        if isinstance(value, (list, tuple)) and all(isinstance(alias, str) for alias in value):
            return tuple(alias.strip() for alias in value if alias.strip())
        raise ValueError("must be a '|' delimited string or a sequence of strings")

    @field_validator("valid_from", "valid_to", mode="before")
    @classmethod
    def _empty_date_is_none(cls, value: object) -> object:
        return None if value == "" else value

    @model_validator(mode="after")
    def _valid_date_range(self) -> ReferenceDataRecord:
        if (
            self.valid_from is not None
            and self.valid_to is not None
            and self.valid_to < self.valid_from
        ):
            raise ValueError("valid_to must be on or after valid_from")
        return self

    def valid_at(self, when: date | None) -> bool:
        """Return whether this record is valid on *when* (inclusive bounds)."""

        if when is None:
            return True
        return (self.valid_from is None or self.valid_from <= when) and (
            self.valid_to is None or when <= self.valid_to
        )


class ReferenceDataCatalog:
    """An immutable in-memory catalog assembled from versioned CSV records.

    CSV inputs use columns
    ``namespace,code,name,aliases,version,status,valid_from,valid_to``.
    ``aliases`` is a pipe-delimited list.  Exact lookup is intentionally case
    sensitive and never falls back to aliases; aliases are offered separately
    through :meth:`suggest`.
    """

    def __init__(self, records: Iterable[ReferenceDataRecord]) -> None:
        ordered = tuple(sorted(records, key=_record_sort_key))
        _validate_non_overlapping_codes(ordered)
        self._records = ordered

    @classmethod
    def from_csv_files(cls, paths: Iterable[Path | str]) -> ReferenceDataCatalog:
        """Load catalog records from local CSV files without accessing a network."""

        records: list[ReferenceDataRecord] = []
        required = {"namespace", "code", "name", "version"}
        for path_value in paths:
            path = Path(path_value)
            with path.open("r", encoding="utf-8", newline="") as csv_file:
                reader = csv.DictReader(csv_file)
                fieldnames = set(reader.fieldnames or ())
                missing = required - fieldnames
                if missing:
                    missing_columns = ", ".join(sorted(missing))
                    raise ValueError(f"{path} is missing required columns: {missing_columns}")
                for row in reader:
                    records.append(ReferenceDataRecord.model_validate(row))
        return cls(records)

    def list(self, namespace: str, at: date | None = None) -> tuple[ReferenceDataRecord, ...]:
        """Return all records in a namespace that are valid at *at*."""

        return tuple(
            record
            for record in self._records
            if record.namespace == namespace and record.valid_at(at)
        )

    def get(
        self, namespace: str, code: str, at: date | None = None
    ) -> ReferenceDataRecord | None:
        """Return an exact-code record, or ``None`` when no matching record exists."""

        candidates = [
            record
            for record in self._records
            if record.namespace == namespace and record.code == code and record.valid_at(at)
        ]
        if not candidates:
            return None
        return max(candidates, key=_record_sort_key)

    def suggest(
        self, namespace: str, alias: str, at: date | None = None
    ) -> tuple[ReferenceDataRecord, ...]:
        """Return the newest record per code whose declared alias matches.

        Without ``at``, historical versions can share the same alias.  Those
        are collapsed to the latest version so one alias suggestion does not
        present duplicate codes to a caller.
        """

        normalized = _normalize_alias(alias)
        if not normalized:
            return ()
        matches: dict[str, ReferenceDataRecord] = {}
        for record in self.list(namespace, at):
            if normalized not in {_normalize_alias(candidate) for candidate in record.aliases}:
                continue
            current = matches.get(record.code)
            if current is None or _record_sort_key(record) > _record_sort_key(current):
                matches[record.code] = record
        return tuple(sorted(matches.values(), key=_record_sort_key))


def default_reference_data_catalog() -> ReferenceDataCatalog:
    """Load CargoMesh's packaged DCSA reference-data baseline."""

    data_directory = Path(__file__).with_name("data")
    return ReferenceDataCatalog.from_csv_files(sorted(data_directory.glob("*.csv")))


def _record_sort_key(record: ReferenceDataRecord) -> tuple[str, str, date, str]:
    return (record.namespace, record.code, record.valid_from or date.min, record.version)


def _validate_non_overlapping_codes(records: tuple[ReferenceDataRecord, ...]) -> None:
    grouped: dict[tuple[str, str], list[ReferenceDataRecord]] = {}
    for record in records:
        grouped.setdefault((record.namespace, record.code), []).append(record)
    for (namespace, code), versions in grouped.items():
        for earlier, later in pairwise(versions):
            earlier_end = earlier.valid_to or date.max
            later_start = later.valid_from or date.min
            if later_start <= earlier_end:
                raise ValueError(
                    "overlapping validity for "
                    f"namespace={namespace!r}, code={code!r}: "
                    f"{earlier.version!r} and {later.version!r}"
                )


def _normalize_alias(value: str) -> str:
    return " ".join(value.casefold().split())
