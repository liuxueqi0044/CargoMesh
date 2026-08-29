"""Reference-data application boundary.

The standards implementation owns storage, manifests, and temporal semantics.
This module only adapts its public provider to HTTP and keeps the provider
replaceable in offline tests.
"""

from __future__ import annotations

from datetime import date
from typing import Any, Protocol


class ReferenceDataProvider(Protocol):
    def get_namespace(self, namespace: str, *, as_of: str | None = None) -> Any: ...


class EmptyReferenceDataProvider:
    """Safe default for a process with no standards repository configured."""

    def get_namespace(self, namespace: str, *, as_of: str | None = None) -> dict[str, Any]:
        return {"namespace": namespace, "records": []}


class ReferenceDataService:
    def __init__(self, provider: ReferenceDataProvider | Any | None = None) -> None:
        self.provider = provider or EmptyReferenceDataProvider()

    def get_namespace(self, namespace: str, *, as_of: str | None = None) -> Any:
        provider = self.provider
        if hasattr(provider, "get_namespace"):
            return provider.get_namespace(namespace, as_of=as_of)
        if hasattr(provider, "list_records"):
            return provider.list_records(namespace, as_of=as_of)
        if hasattr(provider, "list"):
            at = date.fromisoformat(as_of) if as_of is not None else None
            records = provider.list(namespace, at)
            return {
                "namespace": namespace,
                "as_of": as_of,
                "records": [
                    record.model_dump(mode="json", by_alias=True, exclude_none=True)
                    if hasattr(record, "model_dump")
                    else record
                    for record in records
                ],
            }
        if callable(provider):
            return provider(namespace, as_of=as_of)
        raise TypeError("Reference-data provider does not implement get_namespace")
