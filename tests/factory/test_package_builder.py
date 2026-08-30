from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from cargomesh.adapters.contracts import RoleLocator, SignatureProbe, ValueLocator
from cargomesh.adapters.package import load_adapter_package
from cargomesh.factory.capture import DemonstrationCapture, FillAction, SemanticLocator
from cargomesh.factory.package_builder import (
    AdapterCertificationRecord,
    AdapterPackageBuildError,
    PackageBuildOptions,
    build_adapter_package,
)
from cargomesh.factory.spec import (
    AdapterFactoryCompiler,
    BindingSpecification,
    ParameterEvidence,
    ReviewedSOP,
)
from cargomesh.factory.tck import TCKCase, TCKObservation, TCKOutcome, TCKSuite, evaluate_tck

NOW = datetime(2041, 2, 3, 4, 5, 6, tzinfo=UTC)
PAGE_DIGEST = "sha256:" + "a" * 64
VALUE_DIGEST = "sha256:" + "b" * 64


def _ready_specification() -> BindingSpecification:
    locator = SemanticLocator(kind="label", value="Booking reference")
    capture = DemonstrationCapture.issue(
        page_signature=PAGE_DIGEST,
        url_path="/tracking",
        actions=(FillAction(locator=locator, parameter="booking.reference"),),
    )
    sop = ReviewedSOP.issue(
        sop_id="tracking-sop",
        supported_parameters=("booking.reference",),
        steps=(FillAction(locator=locator, parameter="booking.reference"),),
    )
    return AdapterFactoryCompiler.compile(
        capture,
        sop,
        parameter_evidence=(
            ParameterEvidence(
                parameter="booking.reference",
                evidence_ids=("evidence-1",),
                value_digest=VALUE_DIGEST,
            ),
        ),
    )


def _options() -> PackageBuildOptions:
    return PackageBuildOptions(
        adapter_name="factory.tracking",
        source_system="synthetic.portal",
        version="1.0.0",
        portal_version="2026.08",
        minimum_cargomesh_version="0.8.0",
        operation="tracking.fetch",
        capability="shipment.track.read",
        navigation_path="/tracking",
        portal_signature=SignatureProbe(
            key="page.heading",
            locator=RoleLocator(role="heading", name="Track shipment"),
        ),
        result_locator=ValueLocator(kind="test_id", value="tracking-status"),
        output_key="tracking.status",
    )


def _suite() -> TCKSuite:
    return TCKSuite.issue(
        suite_id="factory.package",
        version="1.0.0",
        cases=(
            TCKCase(
                case_id="security.halt",
                portal_variant="healthy",
                expected_outcome=TCKOutcome.PASS,
                security_critical=True,
            ),
        ),
    )


def test_build_is_deterministic_roundtrips_loader_and_contains_no_values(tmp_path: Path) -> None:
    specification = _ready_specification()
    first = build_adapter_package(specification, _options())
    second = build_adapter_package(specification, _options())

    assert first.package_digest == second.package_digest
    assert first.manifest_bytes == second.manifest_bytes
    assert first.recipes[0].recipe_bytes == second.recipes[0].recipe_bytes
    package_bytes = b"".join(first.files().values())
    assert b"CUSTOMER-BOOKING-SECRET" not in package_bytes
    assert b"evidence-1" not in package_bytes

    for file_name, content in first.files().items():
        tmp_path.joinpath(file_name).write_bytes(content)
    loaded = load_adapter_package(tmp_path)
    assert loaded.manifest == first.manifest
    assert loaded.recipes["tracking.fetch"] == first.recipes[0].recipe


def test_builder_rejects_unready_or_unsupported_bindings() -> None:
    locator = SemanticLocator(kind="label", value="Booking reference")
    capture = DemonstrationCapture.issue(
        page_signature=PAGE_DIGEST,
        url_path="/tracking",
        actions=(FillAction(locator=locator, parameter="booking.reference"),),
    )
    sop = ReviewedSOP.issue(
        sop_id="tracking-sop",
        supported_parameters=("booking.reference",),
        steps=(FillAction(locator=locator, parameter="booking.reference"),),
    )
    ambiguous = AdapterFactoryCompiler.compile(capture, sop)

    with pytest.raises(AdapterPackageBuildError) as not_ready:
        build_adapter_package(ambiguous, _options())
    assert not_ready.value.code == "factory_spec_not_ready"


def test_certification_requires_matching_compatible_security_clean_tck() -> None:
    specification = _ready_specification()
    package = build_adapter_package(specification, _options())
    suite = _suite()
    passing = evaluate_tck(
        suite,
        package.package_digest,
        (TCKObservation(case_id="security.halt", outcome=TCKOutcome.PASS, duration_ms=1),),
        evaluated_at=NOW,
    )
    record = AdapterCertificationRecord.issue(
        package,
        specification,
        passing,
        certified_by="human-reviewer",
        certified_at=NOW,
    )
    assert record.adapter_package_digest == package.package_digest
    assert record.tck_suite_digest == suite.suite_digest

    failing = evaluate_tck(
        suite,
        package.package_digest,
        (
            TCKObservation(
                case_id="security.halt",
                outcome=TCKOutcome.FAIL,
                duration_ms=1,
                failure_code="blocked",
            ),
        ),
        evaluated_at=NOW,
    )
    with pytest.raises(AdapterPackageBuildError) as failed_security:
        AdapterCertificationRecord.issue(
            package,
            specification,
            failing,
            certified_by="human-reviewer",
            certified_at=NOW,
        )
    assert failed_security.value.code == "factory_certification_tck_incompatible"

    no_security_suite = TCKSuite.issue(
        suite_id="factory.no-security",
        version="1.0.0",
        cases=(
            TCKCase(
                case_id="healthy.read",
                portal_variant="healthy",
                expected_outcome=TCKOutcome.PASS,
            ),
        ),
    )
    no_security = evaluate_tck(
        no_security_suite,
        package.package_digest,
        (TCKObservation(case_id="healthy.read", outcome=TCKOutcome.PASS, duration_ms=1),),
        evaluated_at=NOW,
    )
    with pytest.raises(AdapterPackageBuildError) as missing_security:
        AdapterCertificationRecord.issue(
            package,
            specification,
            no_security,
            certified_by="human-reviewer",
            certified_at=NOW,
        )
    assert missing_security.value.code == "factory_certification_security_missing"
