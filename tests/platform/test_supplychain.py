import pytest
from pydantic import ValidationError

from cargomesh.platform.supplychain import (
    SBOM,
    AdapterAttestation,
    Provenance,
    ProvenanceArtifact,
    SBOMComponent,
    SupplyChainError,
)


def digest(char: str) -> str:
    return "sha256:" + char * 64


def test_sbom_is_cyclonedx_1_6_deterministic_and_sorted() -> None:
    components = [
        SBOMComponent(
            name="zeta",
            version="1.0",
            purl="pkg:pypi/zeta@1.0",
            license="MIT",
            artifact_digest=digest("a"),
        ),
        SBOMComponent(
            name="alpha",
            version="2.0",
            purl="pkg:pypi/alpha@2.0",
            license="Apache-2.0",
            artifact_digest=digest("b"),
        ),
    ]
    first = SBOM.issue(components)
    second = SBOM.issue(list(reversed(components)))
    assert first.components[0].name == "alpha"
    assert first.canonical_bytes() == second.canonical_bytes()
    assert first.digest == second.digest
    with pytest.raises(ValidationError):
        SBOM(components=(components[0], components[0]))


def test_provenance_and_attestation_bind_exact_digests() -> None:
    provenance = Provenance.issue(
        source_revision="a" * 40,
        builder_id="builder-1",
        materials=[],
        release_artifacts=(ProvenanceArtifact(name="adapter", digest=digest("c")),),
    )
    sbom = SBOM.issue([])
    attestation = AdapterAttestation(
        adapter_package_digest=digest("d"),
        board11_certification_digest=digest("e"),
        tck_suite_digest=digest("f"),
        tck_report_digest=digest("0"),
        provenance_digest=provenance.digest,
        sbom_digest=sbom.digest,
    )
    assert attestation.digest.startswith("sha256:")

    class Signer:
        def sign(self, payload: bytes) -> bytes:
            return payload[:16]

    signed = attestation.sign(Signer())
    assert signed.signed
    assert signed.attestation_digest == attestation.digest
    with pytest.raises(ValidationError, match="signature digest"):
        signed.model_copy(update={"signature": b"changed"}).model_validate(
            signed.model_copy(update={"signature": b"changed"}).model_dump()
        )

    class BrokenSigner:
        def sign(self, payload: bytes) -> bytes:
            del payload
            return b""

    with pytest.raises(SupplyChainError) as caught:
        attestation.sign(BrokenSigner())
    assert caught.value.code == "signing_failed"


def test_attestation_verifier_failure_is_not_described_as_verified() -> None:
    attestation = AdapterAttestation(
        adapter_package_digest=digest("1"),
        board11_certification_digest=digest("2"),
        tck_suite_digest=digest("3"),
        tck_report_digest=digest("4"),
        provenance_digest=digest("5"),
        sbom_digest=digest("6"),
    )

    class Verifier:
        def verify(self, payload: bytes, signature: bytes) -> bool:
            del payload, signature
            return False

    assert not attestation.verify(Verifier(), b"signature")
