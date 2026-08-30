from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime

import httpx2
import pytest

from cargomesh.ir.enums import RiskClass, VerificationLevel
from cargomesh.policy import (
    DataClassification,
    ExecutionChannel,
    OpaPolicyProvider,
    PolicyEffect,
    PolicyInput,
    PolicyRule,
    PolicySet,
)

NOW = datetime(2040, 1, 2, tzinfo=UTC)


def policy_input() -> PolicyInput:
    return PolicyInput.issue(
        tenant_id="tenant-a",
        environment_id="production",
        principal_ref="principal-a",
        capability="shipment.track.read",
        risk_class=RiskClass.READ_ONLY,
        data_classification=DataClassification.INTERNAL,
        requested_verification_level=VerificationLevel.L1,
        route="shipment.track",
        channel=ExecutionChannel.API,
        adapter="synthetic.api.track",
        evaluated_at=NOW,
    )


def policy_set() -> tuple[PolicySet, PolicyRule]:
    item = PolicyRule.issue(
        rule_id="allow-read",
        priority=1,
        effect=PolicyEffect.ALLOW,
        reason_code="allowed",
    )
    return PolicySet.issue(policy_id="tenant-policy", version="1.0.0", rules=(item,)), item


def result_for(request: PolicyInput, policies: PolicySet, item: PolicyRule) -> dict[str, object]:
    return {
        "policy_id": policies.policy_id,
        "policy_version": policies.version,
        "policy_digest": policies.policy_digest,
        "input_digest": request.input_digest,
        "effect": "ALLOW",
        "matched_rule_id": item.rule_id,
        "matched_rule_digest": item.rule_digest,
        "approval_requirement": None,
        "reason_code": "allowed",
    }


def patch_client(monkeypatch: pytest.MonkeyPatch, handler):
    original = httpx2.AsyncClient
    observed: dict[str, object] = {}

    def factory(**kwargs: object) -> httpx2.AsyncClient:
        observed.update(kwargs)
        return original(transport=httpx2.MockTransport(handler), **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr("cargomesh.policy.providers.httpx2.AsyncClient", factory)
    return observed


def test_opa_client_posts_canonical_payload_and_builds_local_digest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = policy_input()
    policies, item = policy_set()

    def handler(message: httpx2.Request) -> httpx2.Response:
        assert message.method == "POST"
        assert str(message.url) == "https://opa.example.test/v1/data/cargomesh/decision"
        assert message.headers["content-type"] == "application/json"
        assert json.loads(message.content) == {"input": request.model_dump(mode="json")}
        return httpx2.Response(
            200,
            headers={"content-type": "application/json"},
            json={"result": result_for(request, policies, item)},
            request=message,
        )

    observed = patch_client(monkeypatch, handler)
    result = asyncio.run(
        OpaPolicyProvider("https://opa.example.test/v1/data/cargomesh/decision", policies).evaluate(
            request
        )
    )

    assert result.effect is PolicyEffect.ALLOW
    assert result.decision_digest.startswith("sha256:")
    assert observed["trust_env"] is False
    assert observed["follow_redirects"] is False


@pytest.mark.parametrize(
    ("status", "headers", "body", "code"),
    [
        pytest.param(
            302, {"content-type": "application/json"}, b"{}", "opa_redirect_rejected", id="redirect"
        ),
        pytest.param(
            200,
            {"content-type": "text/plain"},
            b"{}",
            "opa_content_type_invalid",
            id="content-type",
        ),
        pytest.param(
            200,
            {"content-type": "application/json"},
            b"x" * 65_537,
            "opa_response_too_large",
            id="oversize",
        ),
        pytest.param(
            200,
            {"content-type": "application/json"},
            b'{"result":{}}',
            "opa_response_invalid",
            id="schema",
        ),
    ],
)
def test_opa_untrusted_responses_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
    status: int,
    headers: dict[str, str],
    body: bytes,
    code: str,
) -> None:
    request = policy_input()
    policies, _ = policy_set()

    def handler(message: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(status, headers=headers, content=body, request=message)

    patch_client(monkeypatch, handler)
    provider = OpaPolicyProvider("https://opa.example.test/decision", policies)
    decision = asyncio.run(provider.evaluate(request))
    assert decision.effect is PolicyEffect.DENY
    assert decision.reason_code == code


def test_opa_identity_or_schema_mismatch_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    request = policy_input()
    policies, item = policy_set()
    result = result_for(request, policies, item)
    result["input_digest"] = "sha256:" + "0" * 64

    def handler(message: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(
            200,
            headers={"content-type": "application/json"},
            json={"result": result},
            request=message,
        )

    patch_client(monkeypatch, handler)
    provider = OpaPolicyProvider("https://opa.example.test/decision", policies)
    decision = asyncio.run(provider.evaluate(request))
    assert decision.effect is PolicyEffect.DENY
    assert decision.reason_code == "opa_response_invalid"


def test_opa_transport_fault_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    request = policy_input()
    policies, _ = policy_set()

    def handler(message: httpx2.Request) -> httpx2.Response:
        raise httpx2.ConnectError("untrusted detail", request=message)

    patch_client(monkeypatch, handler)
    provider = OpaPolicyProvider("https://opa.example.test/decision", policies)
    decision = asyncio.run(provider.evaluate(request))

    assert decision.effect is PolicyEffect.DENY
    assert decision.reason_code == "opa_transport_error"
    assert "untrusted detail" not in decision.model_dump_json()


@pytest.mark.parametrize(
    "url",
    [
        "http://opa.example.test/decision",
        "https://user:pass@opa.example.test/decision",
        "https://opa.example.test/decision?x=1",
        "https://opa.example.test/decision#x",
    ],
)
def test_opa_requires_exact_https_url(url: str) -> None:
    policies, _ = policy_set()
    with pytest.raises(ValueError):
        OpaPolicyProvider(url, policies)
