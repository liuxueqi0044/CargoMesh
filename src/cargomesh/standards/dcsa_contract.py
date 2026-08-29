"""Offline guards tying handwritten narrow models to the pinned DCSA contract."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml


@dataclass(frozen=True, slots=True)
class ContractGuardReport:
    upstream_query_parameters: frozenset[str]
    model_query_parameters: frozenset[str]
    missing_from_model: frozenset[str]
    unknown_to_upstream: frozenset[str]

    @property
    def ok(self) -> bool:
        return not self.missing_from_model and not self.unknown_to_upstream


def tnt_events_query_parameters(spec_path: Path | str) -> frozenset[str]:
    """Extract the GET /v2/events query surface without resolving remote refs."""

    document = yaml.safe_load(Path(spec_path).read_text(encoding="utf-8"))
    try:
        parameters = document["paths"]["/v2/events"]["get"]["parameters"]
    except (KeyError, TypeError) as exc:
        raise ValueError("document does not contain DCSA GET /v2/events") from exc
    names: set[str] = set()
    for parameter in parameters:
        if not isinstance(parameter, dict):
            raise ValueError("DCSA parameter entry must be a mapping")
        name = parameter.get("name")
        if isinstance(name, str) and parameter.get("in") == "query":
            names.add(name)
            continue
        reference = parameter.get("$ref")
        if isinstance(reference, str) and "/components/parameters/" in reference:
            referenced_name = reference.rsplit("/", 1)[-1]
            if referenced_name != "Api-Version-Major":
                names.add(referenced_name)
    return frozenset(names)


def guard_tnt_query_model(spec_path: Path | str) -> ContractGuardReport:
    """Verify that our supported model surface matches the pinned DCSA query."""

    from cargomesh.mapping import DCSATNTQueryV2

    upstream = tnt_events_query_parameters(spec_path)
    aliases = {
        (field.alias or name).split(":", 1)[0]
        for name, field in DCSATNTQueryV2.model_fields.items()
    }
    model = frozenset(aliases)
    return ContractGuardReport(
        upstream_query_parameters=upstream,
        model_query_parameters=model,
        missing_from_model=upstream - model,
        unknown_to_upstream=model - upstream,
    )
