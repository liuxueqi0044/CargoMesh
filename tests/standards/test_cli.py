from __future__ import annotations

from pathlib import Path

import pytest

from cargomesh.standards.cli import main


def test_check_command_runs_without_network(capsys: pytest.CaptureFixture[str]) -> None:
    project_root = Path(__file__).resolve().parents[2]
    manifest = project_root / "third_party" / "dcsa" / "SOURCES.yaml"

    assert main(["check", "--manifest", str(manifest)]) == 0
    assert "ok" in capsys.readouterr().out


def test_diff_command_uses_machine_readable_exit_status(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    baseline = tmp_path / "baseline.yaml"
    candidate = tmp_path / "candidate.yaml"
    baseline.write_text(
        "components:\n  schemas:\n    Event:\n      type: object\n",
        encoding="utf-8",
    )
    candidate.write_text("components:\n  schemas: {}\n", encoding="utf-8")

    assert main(["diff", "--baseline", str(baseline), "--candidate", str(candidate)]) == 2
    assert '"breaking": true' in capsys.readouterr().out
