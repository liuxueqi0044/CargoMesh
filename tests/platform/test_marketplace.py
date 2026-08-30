from __future__ import annotations

from datetime import UTC, datetime

import pytest

from cargomesh.adapters.contracts import RoleLocator, SignatureProbe, ValueLocator
from cargomesh.factory.capture import DemonstrationCapture, FillAction, SemanticLocator
from cargomesh.factory.package_builder import (
    AdapterCertificationRecord,
    PackageBuildOptions,
    build_adapter_package,
)
from cargomesh.factory.spec import (
    AdapterFactoryCompiler,
    ParameterEvidence,
    ReviewedSOP,
)
from cargomesh.factory.tck import TCKCase, TCKObservation, TCKOutcome, TCKSuite, evaluate_tck
from cargomesh.platform.marketplace import (
    MarketplaceCatalogEntry,
    MarketplaceError,
    SQLiteMarketplaceCatalog,
)
from cargomesh.platform.supplychain import (
    SBOM,
    AdapterAttestation,
    Provenance,
    ProvenanceArtifact,
    SBOMComponent,
)

NOW = datetime(2041, 2, 3, 4, 5, 6, tzinfo=UTC)


def digest(char: str) -> str:
    return "sha256:" + char * 64


def evidence_chain():
    locator = SemanticLocator(kind="label", value="Booking reference")
    capture = DemonstrationCapture.issue(
        page_signature=digest("a"),
        url_path="/tracking",
        actions=(FillAction(locator=locator, parameter="booking.reference"),),
    )
    sop = ReviewedSOP.issue(
        sop_id="tracking-sop",
        supported_parameters=("booking.reference",),
        steps=(FillAction(locator=locator, parameter="booking.reference"),),
    )
    specification = AdapterFactoryCompiler.compile(
        capture,
        sop,
        parameter_evidence=(
            ParameterEvidence(
                parameter="booking.reference",
                evidence_ids=("evidence-1",),
                value_digest=digest("b"),
            ),
        ),
    )
    package = build_adapter_package(
        specification,
        PackageBuildOptions(
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
        ),
    )
    suite = TCKSuite.issue(
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
    tck = evaluate_tck(
        suite,
        package.package_digest,
        (TCKObservation(case_id="security.halt", outcome=TCKOutcome.PASS, duration_ms=1),),
        evaluated_at=NOW,
    )
    certification = AdapterCertificationRecord.issue(
        package,
        specification,
        tck,
        certified_by="reviewer",
        certified_at=NOW,
    )
    sbom = SBOM.issue(
        [
            SBOMComponent(
                name="adapter",
                version="1.0",
                purl="pkg:pypi/adapter@1.0",
                license="MIT",
                artifact_digest=package.package_digest,
            )
        ]
    )
    provenance = Provenance.issue(
        source_revision="a" * 40,
        builder_id="builder-1",
        materials=[],
        release_artifacts=(ProvenanceArtifact(name="adapter", digest=package.package_digest),),
    )
    attestation = AdapterAttestation(
        adapter_package_digest=package.package_digest,
        board11_certification_digest=certification.certification_digest,
        tck_suite_digest=tck.suite_digest,
        tck_report_digest=tck.report_digest,
        provenance_digest=provenance.digest,
        sbom_digest=sbom.digest,
    )
    return package, certification, sbom, provenance, attestation, tck


class Verifier:
    def verify(self, payload: bytes, signature: bytes) -> bool:
        return bool(payload and signature == b"valid")


def test_catalog_binds_lockstep_evidence_and_replays(tmp_path) -> None:
    package, certification, sbom, provenance, attestation, tck = evidence_chain()
    entry = MarketplaceCatalogEntry.issue(
        publisher_id="publisher-1",
        capability="shipment.track.read",
        package=package,
        certification=certification,
        sbom=sbom,
        provenance=provenance,
        attestation=attestation,
        tck_report=tck,
        compatibility_min="1.0.0",
        compatibility_max="2.0.0",
    )
    catalog = SQLiteMarketplaceCatalog(tmp_path / "catalog.sqlite3")
    assert (
        catalog.publish(
            entry,
            package=package,
            certification=certification,
            sbom=sbom,
            provenance=provenance,
            attestation=attestation,
            tck_report=tck,
            signature=b"valid",
            verifier=Verifier(),
        )
        == entry
    )
    assert (
        catalog.publish(
            entry,
            package=package,
            certification=certification,
            sbom=sbom,
            provenance=provenance,
            attestation=attestation,
            tck_report=tck,
            signature=b"valid",
            verifier=Verifier(),
        )
        == entry
    )
    assert catalog.get(entry.entry_digest) == entry


def test_catalog_rejects_unverified_or_identity_mismatched_publication(tmp_path) -> None:
    package, certification, sbom, provenance, attestation, tck = evidence_chain()
    entry = MarketplaceCatalogEntry.issue(
        publisher_id="publisher-1",
        capability="shipment.track.read",
        package=package,
        certification=certification,
        sbom=sbom,
        provenance=provenance,
        attestation=attestation,
        tck_report=tck,
        compatibility_min="1.0.0",
        compatibility_max="2.0.0",
    )
    catalog = SQLiteMarketplaceCatalog(tmp_path / "catalog.sqlite3")
    with pytest.raises(MarketplaceError) as failed:
        catalog.publish(
            entry,
            package=package,
            certification=certification,
            sbom=sbom,
            provenance=provenance,
            attestation=attestation,
            tck_report=tck,
            signature=b"bad",
            verifier=Verifier(),
        )
    assert failed.value.code == "attestation_unverified"
    changed = entry.model_copy(update={"publisher_id": "publisher-2"})
    with pytest.raises(MarketplaceError):
        catalog.publish(
            changed,
            package=package,
            certification=certification,
            sbom=sbom,
            provenance=provenance,
            attestation=attestation,
            tck_report=tck,
            signature=b"valid",
            verifier=Verifier(),
        )


def test_catalog_rejects_unproven_package_or_capability() -> None:
    package, certification, sbom, provenance, attestation, tck = evidence_chain()
    with pytest.raises(MarketplaceError) as capability:
        MarketplaceCatalogEntry.issue(
            publisher_id="publisher-1",
            capability="booking.create",
            package=package,
            certification=certification,
            sbom=sbom,
            provenance=provenance,
            attestation=attestation,
            tck_report=tck,
            compatibility_min="1.0.0",
            compatibility_max="2.0.0",
        )
    assert capability.value.code == "catalog_capability_mismatch"

    unrelated = Provenance.issue(
        source_revision="a" * 40,
        builder_id="builder-1",
        materials=[],
        release_artifacts=(ProvenanceArtifact(name="other", digest=digest("9")),),
    )
    mismatched_attestation = attestation.model_copy(
        update={"provenance_digest": unrelated.digest}
    )
    with pytest.raises(MarketplaceError) as provenance_error:
        MarketplaceCatalogEntry.issue(
            publisher_id="publisher-1",
            capability="shipment.track.read",
            package=package,
            certification=certification,
            sbom=sbom,
            provenance=unrelated,
            attestation=mismatched_attestation,
            tck_report=tck,
            compatibility_min="1.0.0",
            compatibility_max="2.0.0",
        )
    assert provenance_error.value.code == "supply_chain_identity_mismatch"
