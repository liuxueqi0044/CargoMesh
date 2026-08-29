from __future__ import annotations

import sys
import types

import pytest

from cargomesh.application.compile import CompilationError, CompileService


class FakeCommand:
    @classmethod
    def model_validate(cls, payload: object) -> dict[str, object]:
        assert isinstance(payload, dict)
        return payload


@pytest.fixture
def fake_ir(monkeypatch: pytest.MonkeyPatch) -> types.ModuleType:
    module = types.ModuleType("cargomesh.ir")
    module.TransactionCommand = FakeCommand  # type: ignore[attr-defined]
    module.canonical_business_json = lambda value: '{"ok":true}'  # type: ignore[attr-defined]
    module.business_digest = lambda value: "sha256:" + "a" * 64  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "cargomesh.ir", module)
    return module


def test_ir_compile_returns_deterministic_contract_result(fake_ir: types.ModuleType) -> None:
    result = CompileService().compile(
        "cargomesh.transaction/v1", {"schema_version": "cargomesh.transaction/v1"}
    )

    assert result.target_schema_version == "cargomesh.transaction/v1"
    assert result.canonical_json == '{"ok":true}'
    assert result.digest == "sha256:" + "a" * 64
    assert result.diagnostics == []


def test_compile_rejects_unknown_source_without_importing_contracts() -> None:
    with pytest.raises(CompilationError, match="Unsupported source schema"):
        CompileService().compile("unknown/v9", {})
