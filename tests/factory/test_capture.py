from __future__ import annotations

import pytest
from pydantic import ValidationError

from cargomesh.factory.capture import (
    ClickAction,
    DemonstrationCapture,
    FillAction,
    SemanticLocator,
)
from cargomesh.factory.spec import (
    AdapterFactoryCompiler,
    ParameterEvidence,
    Resolution,
    ReviewedSOP,
)

PAGE_DIGEST = "sha256:" + "a" * 64
VALUE_DIGEST = "sha256:" + "b" * 64


def _capture(*, locator: SemanticLocator | None = None) -> DemonstrationCapture:
    target = locator or SemanticLocator(kind="label", value="Booking reference")
    return DemonstrationCapture.issue(
        page_signature=PAGE_DIGEST,
        url_path="/booking",
        actions=(
            ClickAction(locator=SemanticLocator(kind="role", value="Submit")),
            FillAction(locator=target, parameter="booking.reference"),
        ),
    )


def _sop(*, locator: SemanticLocator | None = None) -> ReviewedSOP:
    target = locator or SemanticLocator(kind="label", value="Booking reference")
    return ReviewedSOP.issue(
        sop_id="booking-sop",
        supported_parameters=("booking.reference",),
        steps=(
            ClickAction(locator=SemanticLocator(kind="role", value="Submit")),
            FillAction(locator=target, parameter="booking.reference"),
        ),
    )


def test_capture_digest_is_deterministic_and_contains_no_business_value() -> None:
    first = _capture()
    second = _capture()
    assert first.capture_digest == second.capture_digest
    assert first.digest.startswith("sha256:")
    assert "ABC123" not in repr(first)
    assert "screenshot" not in first.model_dump()
    with pytest.raises(ValidationError):
        DemonstrationCapture.model_validate(
            {
                "page_signature": PAGE_DIGEST,
                "url_path": "/booking",
                "actions": [],
                "screenshot": "ABC123",
                "capture_digest": first.capture_digest,
            }
        )


def test_capture_rejects_external_paths_css_xpath_and_secret_metadata() -> None:
    with pytest.raises(ValueError):
        DemonstrationCapture.issue(
            page_signature=PAGE_DIGEST,
            url_path="https://evil.example/booking",
            actions=(ClickAction(locator=SemanticLocator(kind="role", value="Submit")),),
        )
    with pytest.raises(ValidationError):
        DemonstrationCapture.model_validate(
            {
                "page_signature": PAGE_DIGEST,
                "url_path": "/booking",
                "actions": [{"kind": "click", "locator": {"kind": "css", "value": "#x"}}],
                "capture_digest": PAGE_DIGEST,
            }
        )
    with pytest.raises(ValueError, match="query-free"):
        DemonstrationCapture.issue(
            page_signature=PAGE_DIGEST,
            url_path="/booking?reference=customer-value",
            actions=(ClickAction(locator=SemanticLocator(kind="role", value="Submit")),),
        )
    with pytest.raises(ValidationError):
        DemonstrationCapture.model_validate(
            {
                "page_signature": PAGE_DIGEST,
                "url_path": "/booking",
                "actions": [
                    {
                        "kind": "fill",
                        "locator": {"kind": "label", "value": "Token"},
                        "parameter": "api.token",
                        "secret": "DO_NOT_ECHO",
                    }
                ],
                "capture_digest": PAGE_DIGEST,
            }
        )


def test_factory_blocks_missing_or_conflicting_evidence_until_resolution() -> None:
    capture = _capture()
    sop = _sop()
    compiler = AdapterFactoryCompiler()
    missing = compiler.compile(capture, sop)
    assert missing.ready is False
    assert missing.status == "AMBIGUOUS"
    assert len(missing.ambiguities) == 1
    evidence = ParameterEvidence(
        parameter="booking.reference",
        evidence_ids=("evidence-1",),
        value_digest=VALUE_DIGEST,
    )
    ready = compiler.compile(capture, sop, parameter_evidence=(evidence,))
    assert ready.ready is True
    assert ready.certified is False
    assert ready.parameters[0].parameter == "booking.reference"
    assert "ABC123" not in repr(ready)
    certified = compiler.certify(ready, reviewer="human-reviewer")
    assert certified.certified is True
    assert certified.certified_by == "human-reviewer"

    conflict = compiler.compile(
        capture,
        sop,
        parameter_evidence=(
            evidence,
            ParameterEvidence(
                parameter="booking.reference",
                evidence_ids=("evidence-2",),
                value_digest="sha256:" + "c" * 64,
            ),
        ),
    )
    assert conflict.ready is False
    with pytest.raises(ValueError, match="evidence blockers"):
        compiler.compile(
            capture,
            sop,
            parameter_evidence=(
                evidence,
                ParameterEvidence(
                    parameter="booking.reference",
                    evidence_ids=("evidence-2",),
                    value_digest="sha256:" + "c" * 64,
                ),
            ),
            resolutions=(
                Resolution(
                    ambiguity_id=conflict.ambiguities[0].ambiguity_id,
                    selected_index=conflict.ambiguities[0].candidate_indexes[0],
                    reviewer="human-reviewer",
                ),
            ),
        )


def test_compiler_rejects_capture_sop_locator_drift_and_certifies_only_ready() -> None:
    capture = _capture()
    drifted = _sop(locator=SemanticLocator(kind="test_id", value="reference-input"))
    evidence = ParameterEvidence(
        parameter="booking.reference",
        evidence_ids=("evidence-1",),
        value_digest=VALUE_DIGEST,
    )
    specification = AdapterFactoryCompiler.compile(capture, drifted, parameter_evidence=(evidence,))
    assert specification.ready is False
    with pytest.raises(ValueError):
        AdapterFactoryCompiler.certify(specification, reviewer="reviewer")
    resolved = AdapterFactoryCompiler.compile(
        capture,
        drifted,
        parameter_evidence=(evidence,),
        resolutions=(
            Resolution(
                ambiguity_id=specification.ambiguities[0].ambiguity_id,
                selected_index=specification.ambiguities[0].candidate_indexes[0],
                reviewer="human-reviewer",
            ),
        ),
    )
    assert resolved.ready is True
    assert resolved.parameters[0].locator.kind == "test_id"
