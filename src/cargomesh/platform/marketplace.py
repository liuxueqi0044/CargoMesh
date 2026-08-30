"""Deterministic, metadata-only adapter catalog and publication boundary."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import threading
from collections.abc import Mapping, Sequence
from contextlib import suppress
from pathlib import Path
from typing import Annotated, Protocol

from pydantic import BaseModel, ConfigDict, StringConstraints, model_validator

from cargomesh.factory.package_builder import (
    AdapterCertificationRecord,
    GeneratedAdapterPackage,
)
from cargomesh.factory.tck import TCKReport
from cargomesh.platform.supplychain import SBOM, AdapterAttestation, Provenance

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
SemVer = Annotated[
    str,
    StringConstraints(pattern=r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$"),
]
_SEMVER_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")


class MarketplaceModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class MarketplaceError(RuntimeError):
    def __init__(self, code: str, message: str = "Marketplace operation failed") -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class PublicationConflict(MarketplaceError):
    def __init__(self) -> None:
        super().__init__("publication_conflict", "Catalog entry conflicts with existing metadata")


class AttestationVerifier(Protocol):
    def verify(self, payload: bytes, signature: bytes) -> bool: ...


class MarketplaceCatalogEntry(MarketplaceModel):
    publisher_id: Identifier
    capability: Identifier
    adapter_package_digest: Sha256Digest
    certification_digest: Sha256Digest
    sbom_digest: Sha256Digest
    provenance_digest: Sha256Digest
    attestation_digest: Sha256Digest
    compatibility_min: SemVer
    compatibility_max: SemVer
    entry_digest: Sha256Digest

    @model_validator(mode="after")
    def validate_entry(self) -> MarketplaceCatalogEntry:
        if _version(self.compatibility_min) > _version(self.compatibility_max):
            raise ValueError("marketplace compatibility range is invalid")
        if self.entry_digest != _digest(self.model_dump(exclude={"entry_digest"})):
            raise ValueError("marketplace catalog digest does not match")
        return self

    @classmethod
    def issue(
        cls,
        *,
        publisher_id: str,
        capability: str,
        package: GeneratedAdapterPackage,
        certification: AdapterCertificationRecord,
        sbom: SBOM,
        provenance: Provenance,
        attestation: AdapterAttestation,
        tck_report: TCKReport,
        compatibility_min: str,
        compatibility_max: str,
    ) -> MarketplaceCatalogEntry:
        _validate_evidence(package, certification, sbom, provenance, attestation, tck_report)
        if capability not in package.manifest.capabilities:
            raise MarketplaceError("catalog_capability_mismatch")
        values: dict[str, object] = {
            "publisher_id": publisher_id,
            "capability": capability,
            "adapter_package_digest": certification.adapter_package_digest,
            "certification_digest": certification.certification_digest,
            "sbom_digest": sbom.digest,
            "provenance_digest": provenance.digest,
            "attestation_digest": attestation.digest,
            "compatibility_min": compatibility_min,
            "compatibility_max": compatibility_max,
        }
        values["entry_digest"] = _digest(values)
        return cls.model_validate(values)


class SQLiteMarketplaceCatalog:
    """A deterministic catalog; distribution, payment and legal state stay external."""

    def __init__(self, database: str | Path = ":memory:") -> None:
        self._database = str(database)
        self._lock = threading.RLock()
        self._closed = False
        try:
            self._connection = sqlite3.connect(
                self._database, isolation_level=None, check_same_thread=False, timeout=10
            )
            self._connection.row_factory = sqlite3.Row
            self._connection.execute("PRAGMA busy_timeout=10000")
            if self._database != ":memory:":
                self._connection.execute("PRAGMA journal_mode=WAL")
            self._connection.execute(
                "CREATE TABLE IF NOT EXISTS marketplace_catalog ("
                "entry_digest TEXT PRIMARY KEY, publisher_id TEXT NOT NULL, "
                "capability TEXT NOT NULL, "
                "adapter_package_digest TEXT NOT NULL, certification_digest TEXT NOT NULL, "
                "sbom_digest TEXT NOT NULL, provenance_digest TEXT NOT NULL, "
                "attestation_digest TEXT NOT NULL, compatibility_min TEXT NOT NULL, "
                "compatibility_max TEXT NOT NULL)"
            )
        except sqlite3.Error as exc:
            raise MarketplaceError("catalog_store_unavailable") from exc

    def publish(
        self,
        entry: MarketplaceCatalogEntry,
        *,
        package: GeneratedAdapterPackage,
        certification: AdapterCertificationRecord,
        sbom: SBOM,
        provenance: Provenance,
        attestation: AdapterAttestation,
        tck_report: TCKReport,
        signature: bytes,
        verifier: AttestationVerifier,
    ) -> MarketplaceCatalogEntry:
        self._ensure_open()
        try:
            entry = MarketplaceCatalogEntry.model_validate(entry.model_dump(mode="python"))
        except Exception as exc:
            raise MarketplaceError("catalog_entry_invalid") from exc
        _validate_evidence(
            package, certification, sbom, provenance, attestation, tck_report
        )
        if not _entry_matches_evidence(
            entry, package, certification, sbom, provenance, attestation
        ):
            raise MarketplaceError("catalog_identity_mismatch")
        if not isinstance(signature, bytes) or not 1 <= len(signature) <= 8192:
            raise MarketplaceError("attestation_unverified")
        try:
            verified = bool(verifier.verify(_publication_payload(entry), signature))
        except Exception as exc:
            raise MarketplaceError("attestation_unverified") from exc
        if not verified:
            raise MarketplaceError("attestation_unverified")
        with self._lock:
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                row = self._connection.execute(
                    "SELECT * FROM marketplace_catalog WHERE entry_digest=?",
                    (entry.entry_digest,),
                ).fetchone()
                if row is not None:
                    existing = _decode(row)
                    if existing != entry:
                        raise PublicationConflict()
                    self._connection.commit()
                    return existing
                self._connection.execute(
                    "INSERT INTO marketplace_catalog VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (
                        entry.entry_digest,
                        entry.publisher_id,
                        entry.capability,
                        entry.adapter_package_digest,
                        entry.certification_digest,
                        entry.sbom_digest,
                        entry.provenance_digest,
                        entry.attestation_digest,
                        entry.compatibility_min,
                        entry.compatibility_max,
                    ),
                )
                self._connection.commit()
                return entry
            except MarketplaceError:
                _rollback(self._connection)
                raise
            except sqlite3.Error as exc:
                _rollback(self._connection)
                raise MarketplaceError("catalog_store_unavailable") from exc

    def get(self, entry_digest: str) -> MarketplaceCatalogEntry | None:
        self._ensure_open()
        with self._lock:
            try:
                row = self._connection.execute(
                    "SELECT * FROM marketplace_catalog WHERE entry_digest=?", (entry_digest,)
                ).fetchone()
                return None if row is None else _decode(row)
            except sqlite3.Error as exc:
                raise MarketplaceError("catalog_store_unavailable") from exc

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._connection.close()
                self._closed = True

    def __enter__(self) -> SQLiteMarketplaceCatalog:
        self._ensure_open()
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _ensure_open(self) -> None:
        if self._closed:
            raise MarketplaceError("catalog_store_closed")


MarketplaceCatalog = SQLiteMarketplaceCatalog
CatalogEntry = MarketplaceCatalogEntry
MarketplaceEntry = MarketplaceCatalogEntry


def _validate_evidence(
    package: GeneratedAdapterPackage,
    certification: AdapterCertificationRecord,
    sbom: SBOM,
    provenance: Provenance,
    attestation: AdapterAttestation,
    tck_report: TCKReport,
) -> None:
    try:
        if not isinstance(package, GeneratedAdapterPackage):
            raise TypeError
        if not isinstance(certification, AdapterCertificationRecord):
            raise TypeError
        if not isinstance(sbom, SBOM) or not isinstance(provenance, Provenance):
            raise TypeError
        if not isinstance(attestation, AdapterAttestation) or not isinstance(tck_report, TCKReport):
            raise TypeError
        GeneratedAdapterPackage.model_validate(package.model_dump(mode="python"))
        AdapterCertificationRecord.model_validate(certification.model_dump(mode="python"))
        SBOM.model_validate(sbom.model_dump(mode="python"))
        Provenance.model_validate(provenance.model_dump(mode="python"))
        AdapterAttestation.model_validate(attestation.model_dump(mode="python"))
        TCKReport.model_validate(tck_report.model_dump(mode="python"))
    except Exception as exc:
        raise MarketplaceError("supply_chain_evidence_invalid") from exc
    security_results = [result for result in tck_report.results if result.security_critical]
    if (
        not tck_report.compatible
        or not security_results
        or any(not result.passed for result in security_results)
    ):
        raise MarketplaceError("certification_not_eligible")
    if (
        package.package_digest != certification.adapter_package_digest
        or certification.adapter_package_digest != tck_report.adapter_package_digest
        or certification.tck_suite_digest != tck_report.suite_digest
        or certification.tck_report_digest != tck_report.report_digest
        or attestation.adapter_package_digest != certification.adapter_package_digest
        or attestation.board11_certification_digest != certification.certification_digest
        or attestation.tck_suite_digest != tck_report.suite_digest
        or attestation.tck_report_digest != tck_report.report_digest
        or attestation.sbom_digest != sbom.digest
        or attestation.provenance_digest != provenance.digest
        or certification.adapter_package_digest not in provenance.release_artifact_digests
        or not any(
            component.artifact_digest == certification.adapter_package_digest
            for component in sbom.components
        )
    ):
        raise MarketplaceError("supply_chain_identity_mismatch")


def _entry_matches_evidence(
    entry: MarketplaceCatalogEntry,
    package: GeneratedAdapterPackage,
    certification: AdapterCertificationRecord,
    sbom: SBOM,
    provenance: Provenance,
    attestation: AdapterAttestation,
) -> bool:
    return (
        entry.capability in package.manifest.capabilities
        and entry.adapter_package_digest == package.package_digest
        and entry.adapter_package_digest == certification.adapter_package_digest
        and entry.certification_digest == certification.certification_digest
        and entry.sbom_digest == sbom.digest
        and entry.provenance_digest == provenance.digest
        and entry.attestation_digest == attestation.digest
    )


def _publication_payload(entry: MarketplaceCatalogEntry) -> bytes:
    return json.dumps(
        {
            "type": "cargomesh.marketplace-publication/v1",
            "entry": _canonical(entry),
        },
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _decode(row: sqlite3.Row) -> MarketplaceCatalogEntry:
    try:
        return MarketplaceCatalogEntry.model_validate(dict(row))
    except Exception as exc:
        raise MarketplaceError("catalog_record_invalid") from exc


def _version(value: str) -> tuple[int, int, int]:
    match = _SEMVER_RE.fullmatch(value)
    if match is None:
        raise ValueError("marketplace version is invalid")
    return int(match.group(1)), int(match.group(2)), int(match.group(3))


def _canonical(value: object) -> object:
    if isinstance(value, BaseModel):
        return _canonical(value.model_dump(mode="python"))
    if isinstance(value, Mapping):
        return {str(key): _canonical(item) for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        return [_canonical(item) for item in value]
    return value


def _digest(value: object) -> str:
    encoded = json.dumps(
        _canonical(value), ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _rollback(connection: sqlite3.Connection) -> None:
    with suppress(sqlite3.Error):
        connection.rollback()


__all__ = [
    "AttestationVerifier",
    "CatalogEntry",
    "Identifier",
    "MarketplaceCatalog",
    "MarketplaceCatalogEntry",
    "MarketplaceEntry",
    "MarketplaceError",
    "MarketplaceModel",
    "PublicationConflict",
    "SQLiteMarketplaceCatalog",
]
