"""Fail-closed providers for embedded and OPA-compatible policy evaluation."""

from __future__ import annotations

import json
import math
from typing import Final, Protocol, cast
from urllib.parse import urlsplit

import httpx2
from pydantic import ValidationError

from .evaluator import EmbeddedPolicyEvaluator
from .models import (
    PolicyDecision,
    PolicyEffect,
    PolicyInput,
    PolicySet,
    SemVer,
    Sha256Digest,
)

MAX_OPA_RESPONSE_BYTES: Final[int] = 65_536


class PolicyProvider(Protocol):
    """An async boundary that always returns a fail-closed decision."""

    async def evaluate(self, policy_input: PolicyInput) -> PolicyDecision: ...


class PolicyProviderError(RuntimeError):
    """A safe provider fault.  Its text intentionally contains no remote detail."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


class EmbeddedPolicyProvider:
    """Offline/default provider backed by the reviewed deterministic evaluator."""

    def __init__(
        self, policy_set: PolicySet, *, evaluator: EmbeddedPolicyEvaluator | None = None
    ) -> None:
        self.policy_set = policy_set
        self._evaluator = evaluator or EmbeddedPolicyEvaluator()

    async def evaluate(self, policy_input: PolicyInput) -> PolicyDecision:
        try:
            return self._evaluator.evaluate(self.policy_set, policy_input)
        except Exception:
            return _provider_deny(self.policy_set, policy_input, "policy_provider_error")


class StaticPolicyProvider(EmbeddedPolicyProvider):
    """Explicit static-policy alias for local and deterministic test wiring."""


class OpaPolicyProvider:
    """Exact-URL HTTPS client for an OPA-shaped policy decision endpoint.

    The remote result is a strict metadata-only object.  This client owns the
    resulting CargoMesh digest and never accepts a remote digest as authoritative.
    """

    def __init__(
        self,
        url: str,
        policy_set: PolicySet,
        *,
        timeout: float = 5.0,
        max_response_bytes: int = MAX_OPA_RESPONSE_BYTES,
    ) -> None:
        self.url = _validate_https_url(url)
        self.policy_set = policy_set
        self.timeout = _validate_timeout(timeout)
        self.max_response_bytes = _validate_max_response_bytes(max_response_bytes)

    async def evaluate(self, policy_input: PolicyInput) -> PolicyDecision:
        try:
            response = await self._request(policy_input)
            return self._decode(policy_input, response)
        except PolicyProviderError as exc:
            return _provider_deny(self.policy_set, policy_input, exc.code)
        except Exception:
            return _provider_deny(self.policy_set, policy_input, "policy_provider_error")

    async def _request(self, policy_input: PolicyInput) -> bytes:
        # The input is already payload-free.  Canonical JSON avoids accidental
        # reformatting differences in test doubles and policy logs.
        request_payload = json.dumps(
            {"input": policy_input.model_dump(mode="json")},
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
            allow_nan=False,
        )
        try:
            async with httpx2.AsyncClient(
                timeout=self.timeout,
                trust_env=False,
                follow_redirects=False,
            ) as client, client.stream(
                "POST",
                self.url,
                content=request_payload.encode("utf-8"),
                headers={"content-type": "application/json", "accept": "application/json"},
            ) as response:
                _check_response_headers(response, self.max_response_bytes)
                body = bytearray()
                async for chunk in response.aiter_bytes():
                    body.extend(chunk)
                    if len(body) > self.max_response_bytes:
                        raise PolicyProviderError(
                            "opa_response_too_large", "Policy response exceeds size limit"
                        )
                return bytes(body)
        except PolicyProviderError:
            raise
        except httpx2.TimeoutException:
            raise PolicyProviderError("opa_timeout", "Policy request timed out") from None
        except httpx2.HTTPError:
            raise PolicyProviderError("opa_transport_error", "Policy request failed") from None

    def _decode(self, policy_input: PolicyInput, body: bytes) -> PolicyDecision:
        try:
            decoded = json.loads(body)
            if not isinstance(decoded, dict) or set(decoded) != {"result"}:
                raise ValueError("OPA envelope is invalid")
            result = decoded["result"]
            if not isinstance(result, dict) or set(result) != _RESULT_FIELDS:
                raise ValueError("OPA result schema is invalid")
            if result["input_digest"] != policy_input.input_digest:
                raise ValueError("OPA input identity does not match")
            if (
                result["policy_id"] != self.policy_set.policy_id
                or result["policy_version"] != self.policy_set.version
                or result["policy_digest"] != self.policy_set.policy_digest
            ):
                raise ValueError("OPA policy identity does not match")
            effect = PolicyEffect(result["effect"])
            matched_rule_id = result["matched_rule_id"]
            matched_rule_digest = result["matched_rule_digest"]
            approval_requirement = result["approval_requirement"]
            reason_code = result["reason_code"]
            # Validate bounded scalar types before constructing a model.  The
            # remote response cannot smuggle arbitrary JSON into a decision.
            if not all(
                value is None or isinstance(value, str)
                for value in (matched_rule_id, matched_rule_digest, approval_requirement)
            ) or not isinstance(reason_code, str):
                raise ValueError("OPA result values are invalid")
            return PolicyDecision.issue(
                input=policy_input,
                policy_id=self.policy_set.policy_id,
                policy_version=cast(SemVer, result["policy_version"]),
                policy_digest=cast(Sha256Digest, result["policy_digest"]),
                effect=effect,
                matched_rule_id=matched_rule_id,
                matched_rule_digest=matched_rule_digest,
                approval_requirement=approval_requirement,
                reason_code=reason_code,
                evaluated_at=policy_input.evaluated_at,
            )
        except (KeyError, TypeError, ValueError, ValidationError, json.JSONDecodeError):
            raise PolicyProviderError(
                "opa_response_invalid", "Policy response is invalid"
            ) from None


_RESULT_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "policy_id",
        "policy_version",
        "policy_digest",
        "input_digest",
        "effect",
        "matched_rule_id",
        "matched_rule_digest",
        "approval_requirement",
        "reason_code",
    }
)


def _provider_deny(
    policy_set: PolicySet, policy_input: PolicyInput, reason_code: str
) -> PolicyDecision:
    return PolicyDecision.issue(
        input=policy_input,
        policy_id=policy_set.policy_id,
        policy_version=policy_set.version,
        policy_digest=policy_set.policy_digest,
        effect=PolicyEffect.DENY,
        reason_code=reason_code,
        evaluated_at=policy_input.evaluated_at,
    )


def _validate_https_url(url: str) -> str:
    if not isinstance(url, str) or not url or len(url) > 2048:
        raise ValueError("OPA URL must be a non-empty bounded string")
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("OPA URL must use HTTPS")
    try:
        _ = parsed.port
    except ValueError as exc:
        raise ValueError("OPA URL must contain a valid port") from exc
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("OPA URL must not include credentials, query, or fragment")
    return url


def _validate_timeout(timeout: float) -> float:
    if (
        not isinstance(timeout, int | float)
        or isinstance(timeout, bool)
        or not math.isfinite(timeout)
        or not 0.1 <= timeout <= 30.0
    ):
        raise ValueError("timeout must be between 0.1 and 30 seconds")
    return float(timeout)


def _validate_max_response_bytes(max_response_bytes: int) -> int:
    if not isinstance(max_response_bytes, int) or isinstance(max_response_bytes, bool):
        raise ValueError("max_response_bytes must be an integer")
    if not 1 <= max_response_bytes <= MAX_OPA_RESPONSE_BYTES:
        raise ValueError("max_response_bytes must be between 1 and 65536")
    return max_response_bytes


def _check_response_headers(response: httpx2.Response, maximum: int) -> None:
    if 300 <= response.status_code < 400:
        raise PolicyProviderError("opa_redirect_rejected", "Policy redirect was rejected")
    if response.status_code < 200 or response.status_code >= 300:
        raise PolicyProviderError("opa_http_error", "Policy endpoint returned an error")
    media_type = response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if media_type not in {"application/json", "application/opa+json"}:
        raise PolicyProviderError("opa_content_type_invalid", "Policy response is not JSON")
    content_length = response.headers.get("content-length")
    if content_length is None:
        return
    try:
        declared = int(content_length)
    except ValueError:
        raise PolicyProviderError(
            "opa_content_length_invalid", "Policy response has invalid content length"
        ) from None
    if declared < 0:
        raise PolicyProviderError(
            "opa_content_length_invalid", "Policy response has invalid content length"
        )
    if declared > maximum:
        raise PolicyProviderError("opa_response_too_large", "Policy response exceeds size limit")
