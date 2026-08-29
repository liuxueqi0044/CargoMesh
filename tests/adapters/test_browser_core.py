from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from pydantic import ValidationError

from cargomesh.adapters.artifacts import ArtifactTooLarge, FileArtifactSink, InMemoryArtifactSink
from cargomesh.adapters.browser import (
    BrowserAdapterConfig,
    InputBindingError,
    OriginPolicy,
    resolve_json_pointer,
)


def test_origin_policy_is_exact_and_resolves_only_same_origin() -> None:
    policy = OriginPolicy("https://portal.example:8443")
    assert policy.allows("https://portal.example:8443/track?reference=1")
    assert policy.resolve("/track") == "https://portal.example:8443/track"
    assert not policy.allows("https://portal.example/track")
    assert not policy.allows("https://sub.portal.example:8443/track")
    assert not policy.allows("http://portal.example:8443/track")
    assert not policy.allows("https://user:pass@portal.example:8443/track")


@pytest.mark.parametrize(
    "url",
    [
        "file:///tmp/portal",
        "https://user:pass@portal.example",
        "https://portal.example/path",
        "https://portal.example?token=x",
    ],
)
def test_browser_config_requires_an_origin_without_credentials(url: str) -> None:
    with pytest.raises(ValidationError):
        BrowserAdapterConfig(base_url=url)


def test_json_pointer_supports_escaping_and_rejects_lossy_values() -> None:
    document = {"a/b": {"~key": ["first", 42]}}
    assert resolve_json_pointer(document, "/a~1b/~0key/1") == 42
    with pytest.raises(InputBindingError):
        resolve_json_pointer(document, "/a~1b/~0key/01")
    with pytest.raises(InputBindingError):
        resolve_json_pointer(document, "/missing")


def test_artifact_sinks_return_only_opaque_integrity_metadata(tmp_path: Path) -> None:
    memory = InMemoryArtifactSink(max_bytes=10)
    descriptor = asyncio.run(memory.store(kind="playwright_trace", content=b"trace"))
    assert descriptor.artifact_id in memory.items
    assert descriptor.sha256.startswith("sha256:")
    assert "path" not in descriptor.model_dump()

    file_sink = FileArtifactSink(tmp_path, max_bytes=10)
    stored = asyncio.run(file_sink.store(kind="playwright_trace", content=b"trace"))
    assert (tmp_path / f"{stored.artifact_id}.trace.zip").read_bytes() == b"trace"

    with pytest.raises(ArtifactTooLarge):
        asyncio.run(memory.store(kind="playwright_trace", content=b"too-large!!"))
