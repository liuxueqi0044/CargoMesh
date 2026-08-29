"""Temporal Activity boundary for collection, receipts, and verification."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime

from temporalio import activity
from temporalio.exceptions import ApplicationError

from .collectors import EvidenceCollectionError, EvidenceCollectorRegistry
from .engine import evaluate_verification
from .models import (
    EvidenceCollectionInvocation,
    VerificationInvocation,
    VerificationReport,
)
from .store import EvidenceConflict, EvidenceStore, EvidenceStoreError

VERIFY_TRANSACTION_ACTIVITY = "cargomesh.verify-transaction"


class VerificationActivities:
    def __init__(
        self,
        collectors: EvidenceCollectorRegistry,
        receipts: EvidenceStore,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._collectors = collectors
        self._receipts = receipts
        self._clock = clock or (lambda: datetime.now(UTC))

    @activity.defn(name=VERIFY_TRANSACTION_ACTIVITY)
    async def verify(self, invocation: VerificationInvocation) -> VerificationReport:
        observations = []
        try:
            for spec in invocation.plan.collectors:
                observation = await self._collectors.collect(
                    EvidenceCollectionInvocation(
                        tenant_id=invocation.tenant_id,
                        transaction_id=invocation.transaction_id,
                        step_id=spec.step_id,
                        collector_id=spec.collector_id,
                        operation=spec.operation,
                        input=spec.input,
                    )
                )
                if (
                    observation.tenant_id != invocation.tenant_id
                    or observation.transaction_id != invocation.transaction_id
                ):
                    raise EvidenceCollectionError(
                        "evidence_identity_mismatch",
                        "Collected evidence does not belong to this transaction",
                        retryable=False,
                    )
                self._receipts.append(observation)
                observations.append(observation)
        except EvidenceCollectionError as exc:
            raise ApplicationError(
                exc.message,
                type=exc.code,
                non_retryable=not exc.retryable,
            ) from exc
        except EvidenceConflict as exc:
            raise ApplicationError(
                exc.message,
                type=exc.code,
                non_retryable=True,
            ) from exc
        except EvidenceStoreError as exc:
            raise ApplicationError(
                exc.message,
                type=exc.code,
                non_retryable=True,
            ) from exc
        return evaluate_verification(
            invocation,
            tuple(observations),
            evaluated_at=self._clock(),
        )
