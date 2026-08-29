from __future__ import annotations

import json
from pathlib import Path

import pytest

from cargomesh.adapters.cli import main


def test_check_builtin_emits_deterministic_json(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["check"]) == 0

    summary = json.loads(capsys.readouterr().out)

    assert summary == {
        "capabilities": ["shipment.track.read"],
        "name": "synthetic.browser.track",
        "operations": ["fetch"],
        "portal_version": "synthetic-portal/v1",
        "source_system": "synthetic.portal",
        "status": "ok",
        "version": "0.1.0",
    }


def test_check_invalid_path_returns_safe_json_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["check", "--path", str(tmp_path / "missing")]) == 1

    error = json.loads(capsys.readouterr().out)

    assert error == {
        "code": "invalid_path",
        "message": "adapter package path must be a directory",
        "status": "error",
    }
