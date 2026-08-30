from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from cargomesh.api.main import create_app
from cargomesh.application.compile import CompilationResult
from cargomesh.controlplane import (
    AccessController,
    MembershipAuthorizer,
    MembershipRole,
    OIDCAuthenticator,
    PrincipalType,
    SQLiteAuditStore,
    SQLiteMembershipStore,
    StaticJwksProvider,
    TenantMembership,
)

ISSUER = "https://identity.example.test/realms/cargomesh"
AUDIENCE = "cargomesh-controlplane"
KID = "integration-key"


class Compiler:
    def compile(self, source: str, payload: Any, *, context: Any = None) -> CompilationResult:
        del source, payload
        tenant_id = context["tenant_id"]
        return CompilationResult(
            command={"schema_version": "cargomesh.transaction/v1", "tenant_id": tenant_id},
            canonical_json='{"schema_version":"cargomesh.transaction/v1"}',
            digest="sha256:" + "b" * 64,
            diagnostics=[],
            source_schema_version="cargomesh.transaction/v1",
        )


class Runtime:
    def __init__(self) -> None:
        self.submissions = 0

    async def submit(self, compilation: Any, idempotency_key: str) -> dict[str, Any]:
        del compilation, idempotency_key
        self.submissions += 1
        return {"tenant_id": "tenant-a", "transaction_id": "tx-1", "created": True}

    async def get(self, transaction_id: str) -> dict[str, Any]:
        return {"tenant_id": "tenant-a", "transaction_id": transaction_id}

    async def approve(self, transaction_id: str, decision: Any) -> dict[str, Any]:
        del decision
        return {"tenant_id": "tenant-a", "transaction_id": transaction_id}

    async def cancel(self, transaction_id: str) -> dict[str, Any]:
        return {"tenant_id": "tenant-a", "transaction_id": transaction_id}


def test_signed_token_server_membership_api_and_audit_work_together(tmp_path: Path) -> None:
    now = datetime.now(UTC)
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    raw_token = jwt.encode(
        {
            "iss": ISSUER,
            "sub": "operator-123",
            "aud": AUDIENCE,
            "iat": now,
            "exp": now + timedelta(minutes=5),
            "tenant_id": "attacker-tenant",
            "role": "tenant_admin",
        },
        private_key,
        algorithm="RS256",
        headers={"kid": KID},
    )
    runtime = Runtime()
    with (
        SQLiteMembershipStore(tmp_path / "memberships.sqlite3") as memberships,
        SQLiteAuditStore(tmp_path / "audit.sqlite3") as audit,
    ):
        memberships.provision(
            TenantMembership.issue(
                membership_id="operator-tenant-a",
                issuer=ISSUER,
                subject="operator-123",
                principal_type=PrincipalType.HUMAN,
                tenant_id="tenant-a",
                environment_id="production",
                role=MembershipRole.OPERATOR,
                revision=1,
                created_at=now,
                updated_at=now,
            )
        )
        controller = AccessController(
            authenticator=OIDCAuthenticator(
                issuer=ISSUER,
                audience=AUDIENCE,
                jwks_provider=StaticJwksProvider(
                    {"keys": [_public_jwk(private_key, KID)]}
                ),
            ),
            authorizer=MembershipAuthorizer(memberships),
            audit=audit,
            environment_id="production",
        )
        client = TestClient(
            create_app(
                compile_service=Compiler(),
                transaction_service=runtime,
                access_controller=controller,
            )
        )

        response = client.post(
            "/v1/transactions",
            headers={
                "Authorization": f"Bearer {raw_token}",
                "Idempotency-Key": "request-1",
            },
            json={
                "sourceSchemaVersion": "cargomesh.transaction/v1",
                "payload": {},
                "context": {"tenant_id": "tenant-a"},
            },
        )

        assert response.status_code == 202
        assert runtime.submissions == 1
        records = audit.list("tenant-a")
        assert [record.event.details["phase"] for record in records] == [
            "authorization",
            "outcome",
        ]
        serialized = "".join(record.model_dump_json() for record in records)
        assert raw_token not in serialized
        assert "attacker-tenant" not in serialized
        assert audit.verify_chain("tenant-a").valid


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
