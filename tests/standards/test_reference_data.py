from __future__ import annotations

from datetime import date
from pathlib import Path

import pytest

from cargomesh.standards import ReferenceDataCatalog, ReferenceDataRecord


def test_exact_lookup_alias_suggestions_and_historical_validity(tmp_path: Path) -> None:
    source = tmp_path / "countries.csv"
    source.write_text(
        "namespace,code,name,aliases,version,valid_from,valid_to\n"
        "country,GB,United Kingdom,UK|Great Britain,2020,2020-01-01,2023-12-31\n"
        "country,GB,United Kingdom,UK|Great Britain,2024,2024-01-01,\n"
        "country,DE,Germany,Deutschland,2024,2024-01-01,\n",
        encoding="utf-8",
    )
    catalog = ReferenceDataCatalog.from_csv_files([source])

    historical = catalog.get("country", "GB", at=date(2022, 6, 1))
    current = catalog.get("country", "GB", at=date(2025, 1, 1))

    assert historical is not None and historical.version == "2020"
    assert current is not None and current.version == "2024"
    assert catalog.get("country", "UK", at=date(2025, 1, 1)) is None
    assert [record.code for record in catalog.suggest("country", "  great BRITAIN ")] == ["GB"]
    assert [record.code for record in catalog.list("country", at=date(2022, 6, 1))] == ["GB"]


def test_catalog_rejects_overlapping_versions_for_one_exact_code() -> None:
    first = ReferenceDataRecord(
        namespace="event", code="LOAD", name="Loaded", version="v1", valid_from=date(2020, 1, 1)
    )
    second = ReferenceDataRecord(
        namespace="event", code="LOAD", name="Loaded", version="v2", valid_from=date(2021, 1, 1)
    )

    with pytest.raises(ValueError, match="overlapping validity"):
        ReferenceDataCatalog([first, second])


def test_csv_requires_stable_versioned_schema(tmp_path: Path) -> None:
    source = tmp_path / "invalid.csv"
    source.write_text("namespace,code,name\ncountry,GB,United Kingdom\n", encoding="utf-8")

    with pytest.raises(ValueError, match="missing required columns: version"):
        ReferenceDataCatalog.from_csv_files([source])
