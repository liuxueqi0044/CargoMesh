"""Fail-closed execution status transitions used by every runtime backend."""

from __future__ import annotations

from .models import ExecutionStatus

_ALLOWED_TRANSITIONS: dict[ExecutionStatus, frozenset[ExecutionStatus]] = {
    ExecutionStatus.ACCEPTED: frozenset(
        {ExecutionStatus.RUNNING, ExecutionStatus.CANCELLED, ExecutionStatus.HALTED}
    ),
    ExecutionStatus.RUNNING: frozenset(
        {
            ExecutionStatus.WAITING_APPROVAL,
            ExecutionStatus.COMPENSATING,
            ExecutionStatus.EXECUTED_UNVERIFIED,
            ExecutionStatus.CANCELLED,
            ExecutionStatus.HALTED,
        }
    ),
    ExecutionStatus.WAITING_APPROVAL: frozenset(
        {
            ExecutionStatus.RUNNING,
            ExecutionStatus.COMPENSATING,
            ExecutionStatus.REJECTED,
            ExecutionStatus.CANCELLED,
            ExecutionStatus.HALTED,
        }
    ),
    ExecutionStatus.COMPENSATING: frozenset(
        {
            ExecutionStatus.COMPENSATED,
            ExecutionStatus.REJECTED,
            ExecutionStatus.HALTED,
            ExecutionStatus.CANCELLED,
        }
    ),
    ExecutionStatus.EXECUTED_UNVERIFIED: frozenset(),
    ExecutionStatus.COMPENSATED: frozenset(),
    ExecutionStatus.REJECTED: frozenset(),
    ExecutionStatus.HALTED: frozenset(),
    ExecutionStatus.CANCELLED: frozenset(),
}


class InvalidExecutionTransition(ValueError):
    """Raised when workflow code attempts an undeclared state transition."""

    def __init__(self, current: ExecutionStatus, target: ExecutionStatus) -> None:
        super().__init__(f"execution transition {current} -> {target} is not allowed")
        self.current = current
        self.target = target


def transition(current: ExecutionStatus, target: ExecutionStatus) -> ExecutionStatus:
    """Return ``target`` when the transition is legal, otherwise fail closed."""

    if target not in _ALLOWED_TRANSITIONS[current]:
        raise InvalidExecutionTransition(current, target)
    return target
