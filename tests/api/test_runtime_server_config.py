from __future__ import annotations

import argparse
import asyncio
from pathlib import Path
from typing import Any

import pytest

from cargomesh.api import runtime_server


def _binding_args(*extra: str) -> list[str]:
    return ["--enable-synthetic-adapter-binding", *extra]


def test_enforcement_requires_complete_configuration() -> None:
    with pytest.raises(SystemExit) as captured:
        runtime_server.main(_binding_args("--enforce-access-control"))

    assert captured.value.code == 2


def test_partial_configuration_requires_explicit_enforcement() -> None:
    with pytest.raises(SystemExit) as captured:
        runtime_server.main(_binding_args("--oidc-issuer", "https://identity.example"))

    assert captured.value.code == 2


def test_invalid_security_url_fails_before_runtime_start(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    started = False

    async def unexpected_start(args: argparse.Namespace) -> None:
        del args
        nonlocal started
        started = True

    monkeypatch.setattr(runtime_server, "serve", unexpected_start)
    with pytest.raises(SystemExit) as captured:
        runtime_server.main(
            _binding_args(
                "--enforce-access-control",
                "--oidc-issuer",
                "http://identity.example",
                "--oidc-audience",
                "cargomesh",
                "--oidc-jwks-url",
                "https://identity.example/jwks",
                "--environment-id",
                "production",
                "--membership-database",
                "memberships.sqlite3",
                "--audit-database",
                "audit.sqlite3",
            )
        )

    assert captured.value.code == 2
    assert not started


def test_complete_configuration_reaches_runtime_start(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    captured: list[argparse.Namespace] = []

    async def capture_start(args: argparse.Namespace) -> None:
        captured.append(args)

    monkeypatch.setattr(runtime_server, "serve", capture_start)
    runtime_server.main(
        _binding_args(
            "--enforce-access-control",
            "--oidc-issuer",
            "https://identity.example",
            "--oidc-audience",
            "cargomesh",
            "--oidc-jwks-url",
            "https://identity.example/jwks",
            "--environment-id",
            "production",
            "--membership-database",
            str(tmp_path / "memberships.sqlite3"),
            "--audit-database",
            str(tmp_path / "audit.sqlite3"),
        )
    )

    assert len(captured) == 1
    assert captured[0].enforce_access_control is True


def test_serve_wires_real_access_control_components(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    applications: list[Any] = []

    async def connect(target: str, *, namespace: str) -> object:
        del target, namespace
        return object()

    class Server:
        def __init__(self, config: Any) -> None:
            applications.append(config.app)

        async def serve(self) -> None:
            return None

    monkeypatch.setattr(runtime_server, "connect_temporal", connect)
    monkeypatch.setattr(runtime_server.uvicorn, "Server", Server)
    args = runtime_server._parser().parse_args(
        _binding_args(
            "--database",
            str(tmp_path / "submissions.sqlite3"),
            "--enforce-access-control",
            "--oidc-issuer",
            "https://identity.example",
            "--oidc-audience",
            "cargomesh",
            "--oidc-jwks-url",
            "https://identity.example/jwks",
            "--environment-id",
            "production",
            "--membership-database",
            str(tmp_path / "memberships.sqlite3"),
            "--audit-database",
            str(tmp_path / "audit.sqlite3"),
        )
    )

    asyncio.run(runtime_server.serve(args))

    assert len(applications) == 1
    assert applications[0].state.access_controller is not None
    assert (tmp_path / "memberships.sqlite3").exists()
    assert (tmp_path / "audit.sqlite3").exists()
