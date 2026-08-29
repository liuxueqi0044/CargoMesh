"""Collector boundary kept separate from transaction execution adapters."""

from __future__ import annotations

from typing import Protocol

from .models import EvidenceCollectionInvocation, EvidenceObservation


class EvidenceCollectionError(RuntimeError):
    def __init__(self, code: str, message: str, *, retryable: bool) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.retryable = retryable


class EvidenceCollector(Protocol):
    async def collect(
        self, invocation: EvidenceCollectionInvocation
    ) -> EvidenceObservation: ...


class EvidenceCollectorRegistry:
    def __init__(self) -> None:
        self._collectors: dict[str, EvidenceCollector] = {}

    def register(self, name: str, collector: EvidenceCollector) -> None:
        if name in self._collectors:
            raise ValueError(f"evidence collector {name} is already registered")
        self._collectors[name] = collector

    async def collect(
        self, invocation: EvidenceCollectionInvocation
    ) -> EvidenceObservation:
        try:
            collector = self._collectors[invocation.collector_id]
        except KeyError as exc:
            raise EvidenceCollectionError(
                "evidence_collector_not_found",
                "Requested evidence collector is not registered",
                retryable=False,
            ) from exc
        try:
            observation = await collector.collect(invocation)
        except EvidenceCollectionError:
            raise
        except Exception as exc:
            raise EvidenceCollectionError(
                "evidence_collector_internal",
                "Evidence collector failed without a safe diagnostic",
                retryable=False,
            ) from exc
        if not isinstance(observation, EvidenceObservation):
            raise EvidenceCollectionError(
                "invalid_evidence_observation",
                "Evidence collector returned an invalid observation",
                retryable=False,
            )
        return observation
