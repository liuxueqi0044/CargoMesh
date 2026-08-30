"""Pure deterministic first-match policy evaluation."""

from __future__ import annotations

from .models import PolicyDecision, PolicyEffect, PolicyInput, PolicyRule, PolicySet


class EmbeddedPolicyEvaluator:
    """Evaluate reviewed rules without clocks, I/O, or mutable state."""

    def evaluate(self, policy_set: PolicySet, policy_input: PolicyInput) -> PolicyDecision:
        for rule in sorted(policy_set.rules, key=lambda item: (item.priority, item.rule_id)):
            if _matches(rule, policy_input):
                return PolicyDecision.issue(
                    input=policy_input,
                    policy_id=policy_set.policy_id,
                    policy_version=policy_set.version,
                    policy_digest=policy_set.policy_digest,
                    effect=rule.effect,
                    matched_rule_id=rule.rule_id,
                    matched_rule_digest=rule.rule_digest,
                    approval_requirement=rule.approval_requirement,
                    reason_code=rule.reason_code,
                    evaluated_at=policy_input.evaluated_at,
                )
        return PolicyDecision.issue(
            input=policy_input,
            policy_id=policy_set.policy_id,
            policy_version=policy_set.version,
            policy_digest=policy_set.policy_digest,
            effect=PolicyEffect.DENY,
            reason_code="policy_no_matching_rule",
            evaluated_at=policy_input.evaluated_at,
        )

    __call__ = evaluate


def evaluate_policy(policy_set: PolicySet, policy_input: PolicyInput) -> PolicyDecision:
    """Functional convenience wrapper for the embedded evaluator."""

    return EmbeddedPolicyEvaluator().evaluate(policy_set, policy_input)


def _matches(rule: PolicyRule, policy_input: PolicyInput) -> bool:
    return (
        _in_or_any(policy_input.tenant_id, rule.tenant_ids)
        and _in_or_any(policy_input.environment_id, rule.environment_ids)
        and _in_or_any(policy_input.principal_ref, rule.principal_refs)
        and _in_or_any(policy_input.capability, rule.capabilities)
        and _in_or_any(policy_input.risk_class, rule.risk_classes)
        and _in_or_any(policy_input.data_classification, rule.data_classifications)
        and _in_or_any(
            policy_input.requested_verification_level, rule.requested_verification_levels
        )
        and _in_or_any(policy_input.route, rule.routes)
        and _in_or_any(policy_input.channel, rule.channels)
        and _in_or_any(policy_input.adapter, rule.adapters)
    )


def _in_or_any(value: object, selected: tuple[object, ...]) -> bool:
    return not selected or value in selected
