from __future__ import annotations

import asyncio
import base64
import hashlib
from datetime import UTC, datetime, timedelta

import httpx2
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from cargomesh.controlplane.authentication import (
    AuthenticationError,
    HttpJwksProvider,
    OIDCAuthenticator,
    StaticJwksProvider,
)
from cargomesh.controlplane.models import PrincipalType

ISSUER = "https://identity.example.test/realms/cargomesh"
AUDIENCE = "cargomesh-controlplane"
KID = "test-rsa-key"


@pytest.fixture
def private_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def authenticator(private_key: rsa.RSAPrivateKey) -> OIDCAuthenticator:
    return OIDCAuthenticator(
        issuer=ISSUER,
        audience=AUDIENCE,
        jwks_provider=StaticJwksProvider({"keys": [_public_jwk(private_key, KID)]}),
    )


def token(
    private_key: rsa.RSAPrivateKey,
    *,
    claims: dict[str, object] | None = None,
    headers: dict[str, object] | None = None,
    algorithm: str = "RS256",
    include_jti: bool = True,
) -> str:
    now = datetime.now(UTC)
    values: dict[str, object] = {
        "iss": ISSUER,
        "sub": "operator-123",
        "aud": AUDIENCE,
        "iat": now,
        "exp": now + timedelta(minutes=5),
    }
    if include_jti:
        values["jti"] = "opaque-token-id"
    if claims:
        values.update(claims)
    token_headers = {"kid": KID, **(headers or {})}
    return jwt.encode(values, private_key, algorithm=algorithm, headers=token_headers)


def _public_jwk(private_key: rsa.RSAPrivateKey, kid: str) -> dict[str, str]:
    numbers = private_key.public_key().public_numbers()
    return {
        "kty": "RSA",
        "kid": kid,
        "use": "sig",
        "alg": "RS256",
        "n": _base64_uint(numbers.n),
        "e": _base64_uint(numbers.e),
    }


def _base64_uint(value: int) -> str:
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def authenticate(
    authenticator: OIDCAuthenticator, raw_token: str, *, now: datetime | None = None
):
    return asyncio.run(authenticator.authenticate(raw_token, now=now))


def test_authenticates_valid_token_and_ignores_authorization_claims(
    authenticator: OIDCAuthenticator, private_key: rsa.RSAPrivateKey
) -> None:
    raw_token = token(
        private_key,
        claims={
            "tenant_id": "attacker-tenant",
            "role": "tenant_admin",
            "token_use": "client_credentials",
            "client_id": "automation-client",
        },
    )

    principal = authenticate(authenticator, raw_token)

    assert principal.issuer == ISSUER
    assert principal.subject == "operator-123"
    assert principal.audiences == (AUDIENCE,)
    assert principal.client_id == "automation-client"
    assert principal.principal_type is PrincipalType.SERVICE_ACCOUNT
    assert principal.token_id_digest == "sha256:" + hashlib.sha256(b"opaque-token-id").hexdigest()
    assert raw_token not in principal.model_dump_json()
    assert "attacker-tenant" not in principal.model_dump_json()


@pytest.mark.parametrize(
    ("claims", "headers", "expected_code"),
    [
        ({"iss": "https://other.example.test"}, {}, "invalid_token"),
        ({"aud": "other-audience"}, {}, "invalid_token"),
        ({"exp": datetime.now(UTC) - timedelta(minutes=1)}, {}, "invalid_token"),
        ({"nbf": datetime.now(UTC) + timedelta(minutes=1)}, {}, "invalid_token"),
        ({"iat": datetime.now(UTC) + timedelta(minutes=1)}, {}, "invalid_token"),
        ({"sub": ""}, {}, "invalid_claims"),
        ({}, {"kid": ""}, "missing_key_id"),
        ({}, {"kid": "missing-key"}, "unknown_key"),
        ({}, {"crit": ["custom"]}, "unsupported_critical_header"),
    ],
)
def test_rejects_required_fail_closed_paths(
    authenticator: OIDCAuthenticator,
    private_key: rsa.RSAPrivateKey,
    claims: dict[str, object],
    headers: dict[str, object],
    expected_code: str,
) -> None:
    raw_token = token(private_key, claims=claims, headers=headers)

    with pytest.raises(AuthenticationError) as caught:
        authenticate(authenticator, raw_token)

    assert caught.value.code == expected_code
    assert raw_token not in str(caught.value)
    assert "opaque-token-id" not in str(caught.value)


def test_rejects_bad_signature_symmetric_and_oversized_tokens(
    authenticator: OIDCAuthenticator, private_key: rsa.RSAPrivateKey
) -> None:
    bad_signature = token(rsa.generate_private_key(public_exponent=65537, key_size=2048))
    symmetric = jwt.encode(
        {"iss": ISSUER, "sub": "operator", "aud": AUDIENCE, "iat": 1, "exp": 2},
        "shared-secret",
        algorithm="HS256",
        headers={"kid": KID},
    )

    for raw_token, code in ((bad_signature, "invalid_token"), (symmetric, "unsupported_algorithm")):
        with pytest.raises(AuthenticationError) as caught:
            authenticate(authenticator, raw_token)
        assert caught.value.code == code
        assert raw_token not in str(caught.value)

    with pytest.raises(AuthenticationError) as oversized:
        authenticate(authenticator, "x" * 16_385)
    assert oversized.value.code == "invalid_token"


def test_missing_jti_hashes_token_not_a_claim_value(
    authenticator: OIDCAuthenticator, private_key: rsa.RSAPrivateKey
) -> None:
    raw_token = token(private_key, include_jti=False)

    principal = authenticate(authenticator, raw_token)

    expected_digest = "sha256:" + hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    assert principal.token_id_digest == expected_digest


def test_authentication_accepts_a_fixed_request_time(
    private_key: rsa.RSAPrivateKey,
) -> None:
    fixed_now = datetime(2040, 1, 1, tzinfo=UTC)
    raw_token = token(
        private_key,
        claims={
            "iat": fixed_now - timedelta(minutes=1),
            "exp": fixed_now + timedelta(minutes=1),
        },
    )
    auth = OIDCAuthenticator(
        issuer=ISSUER,
        audience=AUDIENCE,
        jwks_provider=StaticJwksProvider({"keys": [_public_jwk(private_key, KID)]}),
    )

    principal = authenticate(auth, raw_token, now=fixed_now)

    assert principal.authenticated_at == fixed_now


def test_static_provider_refreshes_at_most_once_for_unknown_key(
    private_key: rsa.RSAPrivateKey,
) -> None:
    class CountingProvider:
        def __init__(self) -> None:
            self.calls: list[bool] = []

        async def get_key(self, kid: str, *, refresh: bool = False):
            self.calls.append(refresh)
            del kid
            return None

    provider = CountingProvider()
    auth = OIDCAuthenticator(issuer=ISSUER, audience=AUDIENCE, jwks_provider=provider)
    raw_token = token(private_key, headers={"kid": "rotated-key"})

    with pytest.raises(AuthenticationError) as caught:
        authenticate(auth, raw_token)

    assert caught.value.code == "unknown_key"
    assert provider.calls == [False, True]


@pytest.mark.parametrize(
    "url",
    [
        "http://identity.example.test/jwks",
        "https://user:pass@identity.example.test/jwks",
        "https://identity.example.test/jwks?redirect=elsewhere",
        "https://identity.example.test/jwks#fragment",
    ],
)
def test_http_provider_requires_exact_https_url(url: str) -> None:
    with pytest.raises(ValueError):
        HttpJwksProvider(url)


def test_http_provider_uses_bounded_exact_request_and_caches_a_key(
    monkeypatch: pytest.MonkeyPatch, private_key: rsa.RSAPrivateKey
) -> None:
    observed: dict[str, object] = {}
    response_count = 0
    original_client = httpx2.AsyncClient

    def handler(request: httpx2.Request) -> httpx2.Response:
        nonlocal response_count
        response_count += 1
        assert request.method == "GET"
        assert str(request.url) == "https://identity.example.test/keys"
        return httpx2.Response(
            200,
            headers={"content-type": "application/jwk-set+json"},
            json={"keys": [_public_jwk(private_key, KID)]},
            request=request,
        )

    def client_factory(**kwargs: object) -> httpx2.AsyncClient:
        observed.update(kwargs)
        return original_client(transport=httpx2.MockTransport(handler), **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(
        "cargomesh.controlplane.authentication.httpx2.AsyncClient", client_factory
    )
    provider = HttpJwksProvider("https://identity.example.test/keys", timeout=2.0)

    assert asyncio.run(provider.get_key(KID)) is not None
    assert asyncio.run(provider.get_key(KID)) is not None

    assert observed["trust_env"] is False
    assert observed["follow_redirects"] is False
    assert observed["timeout"] == 2.0
    assert response_count == 1


@pytest.mark.parametrize(
    ("status_code", "content_type", "body", "expected_code"),
    [
        pytest.param(302, "application/json", b"{}", "jwks_redirect_rejected", id="redirect"),
        pytest.param(200, "text/plain", b"{}", "invalid_jwks_content_type", id="content-type"),
        pytest.param(
            200,
            "application/json",
            b"x" * 65_537,
            "jwks_response_too_large",
            id="response-too-large",
        ),
    ],
)
def test_http_provider_rejects_untrusted_responses(
    monkeypatch: pytest.MonkeyPatch,
    status_code: int,
    content_type: str,
    body: bytes,
    expected_code: str,
) -> None:
    original_client = httpx2.AsyncClient

    def handler(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(
            status_code,
            headers={"content-type": content_type},
            content=body,
            request=request,
        )

    def client_factory(**kwargs: object) -> httpx2.AsyncClient:
        return original_client(transport=httpx2.MockTransport(handler), **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(
        "cargomesh.controlplane.authentication.httpx2.AsyncClient", client_factory
    )

    with pytest.raises(AuthenticationError) as caught:
        asyncio.run(HttpJwksProvider("https://identity.example.test/keys").get_key(KID))

    assert caught.value.code == expected_code
