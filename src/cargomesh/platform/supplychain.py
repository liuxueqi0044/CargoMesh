"""Deterministic, metadata-only supply-chain evidence contracts."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Annotated, Protocol

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

Sha256Digest = Annotated[str, StringConstraints(pattern=r"^sha256:[0-9a-f]{64}$")]
Identifier = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=256,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:+/@-]{0,255}$",
    ),
]
_HEX_REVISION = re.compile(r"^[0-9a-f]{7,64}$")
_PURL = re.compile(r"^pkg:[a-z0-9.+-]+/[A-Za-z0-9._~%/+@:-]+$")
_LICENSE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+-]{0,63}$")


class SupplyChainModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class SupplyChainError(RuntimeError):
    def __init__(self, code: str, message: str = "Supply-chain operation failed") -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class Signer(Protocol):
    def sign(self, payload: bytes) -> bytes: ...


class Verifier(Protocol):
    def verify(self, payload: bytes, signature: bytes) -> bool: ...


class SBOMComponent(SupplyChainModel):
    name: Identifier
    version: Identifier
    purl: str
    license: str
    artifact_digest: Sha256Digest

    @field_validator("purl")
    @classmethod
    def require_purl(cls, value: str) -> str:
        if not _PURL.fullmatch(value):
            raise ValueError("component purl is invalid")
        return value

    @field_validator("license")
    @classmethod
    def require_license(cls, value: str) -> str:
        if not _LICENSE.fullmatch(value):
            raise ValueError("component license is invalid")
        return value


class SBOM(SupplyChainModel):
    bom_format: str = "CycloneDX"
    spec_version: str = "1.6"
    version: int = Field(default=1, ge=1, le=2**31 - 1)
    components: tuple[SBOMComponent, ...] = Field(max_length=4096)

    @model_validator(mode="after")
    def validate_contract(self) -> SBOM:
        if self.bom_format != "CycloneDX" or self.spec_version != "1.6":
            raise ValueError("SBOM format must be CycloneDX 1.6")
        keys = [(item.name, item.version, item.purl) for item in self.components]
        if len(keys) != len(set(keys)):
            raise ValueError("SBOM components must be unique")
        if (
            tuple(sorted(self.components, key=lambda item: (item.name, item.version, item.purl)))
            != self.components
        ):
            raise ValueError("SBOM components must be sorted")
        return self

    @classmethod
    def issue(cls, components: Sequence[SBOMComponent]) -> SBOM:
        ordered = tuple(sorted(components, key=lambda item: (item.name, item.version, item.purl)))
        return cls(components=ordered)

    def canonical_dict(self) -> dict[str, object]:
        return {
            "bomFormat": self.bom_format,
            "specVersion": self.spec_version,
            "version": self.version,
            "components": [
                {
                    "name": item.name,
                    "version": item.version,
                    "purl": item.purl,
                    "licenses": [{"license": {"id": item.license}}],
                    "hashes": [
                        {"alg": "SHA-256", "content": item.artifact_digest.removeprefix("sha256:")}
                    ],
                }
                for item in self.components
            ],
        }

    def canonical_bytes(self) -> bytes:
        return _canonical_bytes(self.canonical_dict())

    @property
    def digest(self) -> str:
        return _sha256(self.canonical_bytes())

    @property
    def sbom_digest(self) -> str:
        return self.digest

    @property
    def sha256(self) -> str:
        return self.digest


class ProvenanceMaterial(SupplyChainModel):
    uri: Identifier
    digest: Sha256Digest


class ProvenanceArtifact(SupplyChainModel):
    name: Identifier
    digest: Sha256Digest


class Provenance(SupplyChainModel):
    source_revision: str
    builder_id: Identifier
    materials: tuple[ProvenanceMaterial, ...] = Field(max_length=4096)
    release_artifacts: tuple[ProvenanceArtifact, ...] = Field(max_length=4096)

    @field_validator("source_revision")
    @classmethod
    def require_revision(cls, value: str) -> str:
        if not _HEX_REVISION.fullmatch(value):
            raise ValueError("source revision must be a hexadecimal revision")
        return value

    @model_validator(mode="after")
    def validate_sorted(self) -> Provenance:
        material_names = [item.uri for item in self.materials]
        artifact_names = [item.name for item in self.release_artifacts]
        if len(material_names) != len(set(material_names)):
            raise ValueError("provenance materials must be unique")
        if len(artifact_names) != len(set(artifact_names)):
            raise ValueError("provenance artifacts must be unique")
        if tuple(sorted(self.materials, key=lambda item: item.uri)) != self.materials:
            raise ValueError("provenance materials must be sorted")
        if (
            tuple(sorted(self.release_artifacts, key=lambda item: item.name))
            != self.release_artifacts
        ):
            raise ValueError("provenance artifacts must be sorted")
        return self

    @classmethod
    def issue(
        cls,
        *,
        source_revision: str,
        builder_id: str,
        materials: Sequence[ProvenanceMaterial],
        release_artifacts: Sequence[ProvenanceArtifact],
    ) -> Provenance:
        return cls(
            source_revision=source_revision,
            builder_id=builder_id,
            materials=tuple(sorted(materials, key=lambda item: item.uri)),
            release_artifacts=tuple(sorted(release_artifacts, key=lambda item: item.name)),
        )

    def canonical_dict(self) -> dict[str, object]:
        return {
            "_type": "https://in-toto.io/Statement/v1",
            "predicateType": "https://slsa.dev/provenance/v1",
            "subject": [
                {"name": item.name, "digest": {"sha256": item.digest.removeprefix("sha256:")}}
                for item in self.release_artifacts
            ],
            "predicate": {
                "buildDefinition": {
                    "buildType": "https://slsa.dev/provenance/v1",
                    "externalParameters": {"sourceRevision": self.source_revision},
                    "resolvedDependencies": [
                        {"uri": item.uri, "digest": {"sha256": item.digest.removeprefix("sha256:")}}
                        for item in self.materials
                    ],
                },
                "runDetails": {"builder": {"id": self.builder_id}},
            },
        }

    def canonical_bytes(self) -> bytes:
        return _canonical_bytes(self.canonical_dict())

    @property
    def digest(self) -> str:
        return _sha256(self.canonical_bytes())

    @property
    def provenance_digest(self) -> str:
        return self.digest

    @property
    def release_artifact_digests(self) -> tuple[str, ...]:
        return tuple(item.digest for item in self.release_artifacts)


class AdapterAttestation(SupplyChainModel):
    adapter_package_digest: Sha256Digest
    board11_certification_digest: Sha256Digest
    tck_suite_digest: Sha256Digest
    tck_report_digest: Sha256Digest
    provenance_digest: Sha256Digest
    sbom_digest: Sha256Digest

    def canonical_bytes(self) -> bytes:
        return _canonical_bytes(
            {
                "type": "cargomesh.adapter-attestation/v1",
                **self.model_dump(mode="python"),
            }
        )

    @property
    def digest(self) -> str:
        return _sha256(self.canonical_bytes())

    @property
    def attestation_digest(self) -> str:
        return self.digest

    @property
    def package_digest(self) -> str:
        return self.adapter_package_digest

    @property
    def certification_digest(self) -> str:
        return self.board11_certification_digest

    def sign(self, signer: Signer) -> SignedAdapterAttestation:
        try:
            signature = signer.sign(self.canonical_bytes())
            if not isinstance(signature, bytes) or not signature:
                raise ValueError
        except Exception as exc:
            del exc
            raise SupplyChainError("signing_failed", "Attestation signing failed") from None
        return SignedAdapterAttestation(
            attestation_digest=self.digest,
            signature_digest=_sha256(signature),
            signature=signature,
        )

    def verify(self, verifier: Verifier, signature: bytes) -> bool:
        if not isinstance(signature, bytes) or not signature:
            return False
        try:
            return bool(verifier.verify(self.canonical_bytes(), signature))
        except Exception:
            return False


class SignedAdapterAttestation(SupplyChainModel):
    attestation_digest: Sha256Digest
    signature_digest: Sha256Digest
    signature: bytes = Field(min_length=1, max_length=8192)

    @model_validator(mode="after")
    def validate_signature_digest(self) -> SignedAdapterAttestation:
        if self.signature_digest != _sha256(self.signature):
            raise ValueError("attestation signature digest does not match")
        return self

    @property
    def signed(self) -> bool:
        return True


def verify_attestation(
    attestation: AdapterAttestation, signature: bytes, verifier: Verifier
) -> bool:
    """Return true only for a cryptographically verified exact payload."""

    return attestation.verify(verifier, signature)


def _sha256(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        _canonical(value), ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")


def _canonical(value: object) -> object:
    if isinstance(value, BaseModel):
        return _canonical(value.model_dump(mode="python"))
    if isinstance(value, datetime):
        return value.astimezone(UTC).isoformat(timespec="microseconds")
    if isinstance(value, Mapping):
        return {str(key): _canonical(item) for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        return [_canonical(item) for item in value]
    return value


__all__ = [
    "SBOM",
    "AdapterAttestation",
    "CycloneDXSBOM",
    "Provenance",
    "ProvenanceArtifact",
    "ProvenanceMaterial",
    "SBOMComponent",
    "SBOMComponentRecord",
    "SLSAProvenance",
    "SignedAdapterAttestation",
    "Signer",
    "SupplyChainError",
    "Verifier",
    "verify_attestation",
]

CycloneDXSBOM = SBOM
SLSAProvenance = Provenance
SBOMComponentRecord = SBOMComponent
