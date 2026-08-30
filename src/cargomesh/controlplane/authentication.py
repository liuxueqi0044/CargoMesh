"""Fail-closed OIDC authentication with bounded JWKS retrieval."""

from __future__ import annotations

import base64
import hashlib
import json
import math
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from typing import Any, Final, Protocol, cast
from urllib.parse import urlsplit

import httpx2
import jwt

from cargomesh.controlplane.models import Principal, PrincipalType

MAX_TOKEN_BYTES: Final[int] = 16_384
MAX_JWKS_RESPONSE_BYTES: Final[int] = 65_536
MAX_KID_LENGTH: Final[int] = 256
DEFAULT_ALLOWED_ALGORITHMS: Final[frozenset[str]] = frozenset({"RS256"})
SUPPORTED_ALGORITHMS: Final[frozenset[str]] = frozenset(
    {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"}
)


class AuthenticationError(RuntimeError):
    """A public-safe authentication failure.

    Error text is deliberately selected from constants below: it must never
    incorporate a bearer token, claim value, provider response, or exception.
    """

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(message)


class JwksProvider(Protocol):
    """A bounded provider of public JWKs keyed by ``kid``."""

    async def get_key(self, kid: str, *, refresh: bool = False) -> jwt.PyJWK | None:
        """Return the requested public key, or ``None`` when it is unknown."""


class StaticJwksProvider:
    """Offline JWK provider intended for deterministic tests and local wiring."""

    def __init__(self, jwks: Mapping[str, object]) -> None:
        self._keys = _parse_jwks(jwks)

    async def get_key(self, kid: str, *, refresh: bool = False) -> jwt.PyJWK | None:
        del refresh
        return self._keys.get(kid)


class HttpJwksProvider:
    """Retrieve public keys from one configured HTTPS JWKS endpoint only."""

    def __init__(
        self,
        url: str,
        *,
        timeout: float = 5.0,
        max_response_bytes: int = MAX_JWKS_RESPONSE_BYTES,
    ) -> None:
        self.url = _validate_jwks_url(url)
        self.timeout = _validate_timeout(timeout)
        self.max_response_bytes = _validate_max_response_bytes(max_response_bytes)
        self._keys: dict[str, jwt.PyJWK] = {}
        self._loaded = False

    async def get_key(self, kid: str, *, refresh: bool = False) -> jwt.PyJWK | None:
        if refresh or not self._loaded:
            self._keys = await self._fetch_keys()
            self._loaded = True
        return self._keys.get(kid)

    async def _fetch_keys(self) -> dict[str, jwt.PyJWK]:
        try:
            async with httpx2.AsyncClient(
                timeout=self.timeout,
                trust_env=False,
                follow_redirects=False,
            ) as client, client.stream("GET", self.url) as response:
                _check_jwks_response_headers(response, self.max_response_bytes)
                body = bytearray()
                async for chunk in response.aiter_bytes():
                    body.extend(chunk)
                    if len(body) > self.max_response_bytes:
                        raise AuthenticationError(
                            "jwks_response_too_large", "Identity key response exceeds size limit"
                        )
        except AuthenticationError:
            raise
        except httpx2.TimeoutException:
            raise AuthenticationError("jwks_timeout", "Identity key request timed out") from None
        except httpx2.HTTPError:
            raise AuthenticationError(
                "jwks_transport_error", "Identity key request failed"
            ) from None

        try:
            decoded = json.loads(bytes(body))
            if not isinstance(decoded, dict):
                raise ValueError("JWKS must be an object")
            return _parse_jwks(decoded)
        except (TypeError, ValueError, json.JSONDecodeError):
            raise AuthenticationError("invalid_jwks", "Identity key response is invalid") from None


class OIDCAuthenticator:
    """Validate signed OIDC access tokens into minimal CargoMesh principals."""

    def __init__(
        self,
        *,
        issuer: str,
        audience: str,
        jwks_provider: JwksProvider,
        allowed_algorithms: frozenset[str] = DEFAULT_ALLOWED_ALGORITHMS,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.issuer = _validate_issuer(issuer)
        self.audience = _validate_identifier(audience, "audience")
        self.jwks_provider = jwks_provider
        self.allowed_algorithms = _validate_algorithms(allowed_algorithms)
        self._clock = clock or (lambda: datetime.now(UTC))

    async def authenticate(self, token: str, *, now: datetime | None = None) -> Principal:
        """Verify one raw bearer token and return its bounded principal view."""
        _validate_token(token)
        authenticated_at = _authenticated_at(now if now is not None else self._clock())
        header = _unverified_header(token)
        algorithm = _header_algorithm(header, self.allowed_algorithms)
        kid = _header_kid(header)
        key = await self._key_for(kid)
        if key is None:
            raise AuthenticationError("unknown_key", "Identity signing key is unknown")
        if key.algorithm_name != algorithm:
            raise AuthenticationError("invalid_key", "Identity signing key is invalid")

        claims = _decode_claims(token, key, algorithm, self.issuer, self.audience)
        try:
            issuer = claims["iss"]
            subject = _validate_identifier(claims["sub"], "subject")
            audiences = _claim_audiences(claims["aud"])
            issued_at = _claim_timestamp(claims["iat"])
            expires_at = _claim_timestamp(claims["exp"])
            _validate_time_claims(claims, authenticated_at, issued_at, expires_at)
            return Principal(
                issuer=_validate_issuer(issuer),
                subject=subject,
                principal_type=_principal_type(claims),
                audiences=audiences,
                client_id=_optional_client_id(claims),
                token_id_digest=_token_id_digest(token, claims.get("jti")),
                issued_at=issued_at,
                expires_at=expires_at,
                authenticated_at=authenticated_at,
            )
        except (KeyError, TypeError, ValueError, OverflowError, OSError):
            raise AuthenticationError(
                "invalid_claims", "Identity token claims are invalid"
            ) from None

    async def _key_for(self, kid: str) -> jwt.PyJWK | None:
        try:
            key = await self.jwks_provider.get_key(kid)
            if key is None:
                key = await self.jwks_provider.get_key(kid, refresh=True)
            return key
        except AuthenticationError:
            raise
        except Exception:
            raise AuthenticationError(
                "jwks_unavailable", "Identity key provider is unavailable"
            ) from None


def _validate_jwks_url(url: str) -> str:
    if not isinstance(url, str) or not url or len(url) > 2048:
        raise ValueError("JWKS URL must be a non-empty bounded string")
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("JWKS URL must use HTTPS")
    try:
        _ = parsed.port
    except ValueError as exc:
        raise ValueError("JWKS URL must contain a valid port") from exc
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("JWKS URL must not include credentials, query, or fragment")
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
    if not 1 <= max_response_bytes <= MAX_JWKS_RESPONSE_BYTES:
        raise ValueError("max_response_bytes must be between 1 and 65536")
    return max_response_bytes


def _check_jwks_response_headers(response: httpx2.Response, maximum: int) -> None:
    if 300 <= response.status_code < 400:
        raise AuthenticationError("jwks_redirect_rejected", "Identity key redirect was rejected")
    if response.status_code < 200 or response.status_code >= 300:
        raise AuthenticationError("jwks_http_error", "Identity key endpoint returned an error")
    media_type = response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if media_type not in {"application/json", "application/jwk-set+json"}:
        raise AuthenticationError("invalid_jwks_content_type", "Identity key response is not JSON")
    content_length = response.headers.get("content-length")
    if content_length is None:
        return
    try:
        declared_length = int(content_length)
    except ValueError:
        raise AuthenticationError(
            "invalid_jwks_content_length", "Identity key response has invalid content length"
        ) from None
    if declared_length < 0:
        raise AuthenticationError(
            "invalid_jwks_content_length", "Identity key response has invalid content length"
        )
    if declared_length > maximum:
        raise AuthenticationError(
            "jwks_response_too_large", "Identity key response exceeds size limit"
        )


def _parse_jwks(jwks: Mapping[str, object]) -> dict[str, jwt.PyJWK]:
    raw_keys = jwks.get("keys")
    if not isinstance(raw_keys, list) or not raw_keys:
        raise ValueError("JWKS keys must be a non-empty list")
    parsed: dict[str, jwt.PyJWK] = {}
    for raw_key in raw_keys:
        if not isinstance(raw_key, dict):
            raise ValueError("JWKS key must be an object")
        kid = raw_key.get("kid")
        if not isinstance(kid, str) or not kid or len(kid) > MAX_KID_LENGTH or kid in parsed:
            raise ValueError("JWKS key id is invalid")
        use = raw_key.get("use")
        if use is not None and use != "sig":
            continue
        key = jwt.PyJWK.from_dict(cast(dict[str, Any], raw_key))
        if key.algorithm_name not in SUPPORTED_ALGORITHMS:
            continue
        parsed[kid] = key
    if not parsed:
        raise ValueError("JWKS contains no supported signing keys")
    return parsed


def _validate_issuer(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 2048:
        raise ValueError("issuer must be a non-empty bounded string")
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("issuer must be an HTTPS URL")
    try:
        _ = parsed.port
    except ValueError as exc:
        raise ValueError("issuer must contain a valid port") from exc
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("issuer must not include credentials, query, or fragment")
    return value


def _validate_identifier(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value.strip()) > 256:
        raise ValueError(f"{label} must be a non-empty bounded string")
    return value.strip()


def _validate_algorithms(algorithms: frozenset[str]) -> frozenset[str]:
    if not algorithms or not algorithms <= SUPPORTED_ALGORITHMS:
        raise ValueError("allowed algorithms must be a non-empty supported allowlist")
    return algorithms


def _validate_token(token: str) -> None:
    if not isinstance(token, str) or not token or len(token.encode("utf-8")) > MAX_TOKEN_BYTES:
        raise AuthenticationError("invalid_token", "Bearer token is invalid")


def _unverified_header(token: str) -> Mapping[str, object]:
    try:
        encoded_header, _, _ = token.split(".")
        padded_header = encoded_header + "=" * (-len(encoded_header) % 4)
        header = json.loads(base64.urlsafe_b64decode(padded_header))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
        raise AuthenticationError("invalid_token", "Bearer token is invalid") from None
    if not isinstance(header, dict):
        raise AuthenticationError("invalid_header", "Bearer token header is invalid")
    return cast(Mapping[str, object], header)


def _header_algorithm(header: Mapping[str, object], allowed_algorithms: frozenset[str]) -> str:
    algorithm = header.get("alg")
    if not isinstance(algorithm, str) or algorithm not in allowed_algorithms:
        raise AuthenticationError("unsupported_algorithm", "Bearer token algorithm is not allowed")
    if "crit" in header:
        raise AuthenticationError(
            "unsupported_critical_header", "Bearer token header is not supported"
        )
    return algorithm


def _header_kid(header: Mapping[str, object]) -> str:
    kid = header.get("kid")
    if not isinstance(kid, str) or not kid or len(kid) > MAX_KID_LENGTH:
        raise AuthenticationError("missing_key_id", "Bearer token has no valid key identifier")
    return kid


def _decode_claims(
    token: str, key: jwt.PyJWK, algorithm: str, issuer: str, audience: str
) -> Mapping[str, object]:
    try:
        decoded = jwt.decode(
            token,
            key.key,
            algorithms=[algorithm],
            audience=audience,
            issuer=issuer,
            options={
                "require": ["iss", "sub", "aud", "iat", "exp"],
                "verify_exp": False,
                "verify_iat": False,
                "verify_nbf": False,
            },
        )
    except jwt.PyJWTError:
        raise AuthenticationError("invalid_token", "Bearer token is invalid") from None
    if not isinstance(decoded, dict):
        raise AuthenticationError("invalid_claims", "Identity token claims are invalid")
    return cast(Mapping[str, object], decoded)


def _claim_audiences(value: object) -> tuple[str, ...]:
    raw_audiences: Sequence[object]
    if isinstance(value, str):
        raw_audiences = (value,)
    elif isinstance(value, list):
        raw_audiences = value
    else:
        raise ValueError("audience is invalid")
    audiences = tuple(_validate_identifier(item, "audience") for item in raw_audiences)
    if not audiences or len(audiences) > 8 or len(audiences) != len(set(audiences)):
        raise ValueError("audience is invalid")
    return audiences


def _claim_timestamp(value: object) -> datetime:
    if not isinstance(value, int | float) or isinstance(value, bool) or not math.isfinite(value):
        raise ValueError("timestamp is invalid")
    return datetime.fromtimestamp(value, UTC)


def _authenticated_at(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("clock must return an aware timestamp")
    return value.astimezone(UTC)


def _validate_time_claims(
    claims: Mapping[str, object],
    authenticated_at: datetime,
    issued_at: datetime,
    expires_at: datetime,
) -> None:
    not_before = claims.get("nbf")
    if not_before is not None and _claim_timestamp(not_before) > authenticated_at:
        raise AuthenticationError("invalid_token", "Bearer token is invalid")
    if issued_at > authenticated_at or expires_at <= authenticated_at:
        raise AuthenticationError("invalid_token", "Bearer token is invalid")


def _optional_client_id(claims: Mapping[str, object]) -> str | None:
    value = claims.get("client_id")
    if value is None:
        value = claims.get("azp")
    if value is None:
        return None
    return _validate_identifier(value, "client id")


def _principal_type(claims: Mapping[str, object]) -> PrincipalType:
    if (
        claims.get("token_use") == "client_credentials"
        or claims.get("grant_type") == "client_credentials"
    ):
        return PrincipalType.SERVICE_ACCOUNT
    return PrincipalType.HUMAN


def _token_id_digest(token: str, raw_jti: object) -> str:
    source = raw_jti if isinstance(raw_jti, str) and raw_jti else token
    return "sha256:" + hashlib.sha256(source.encode("utf-8")).hexdigest()
