"""Safe, local SQLite backup and restore with metadata-only manifests."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

Digest = str


class BackupError(RuntimeError):
    def __init__(self, code: str, message: str = "SQLite backup operation failed") -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class BackupManifest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    schema_version: str = "cargomesh.sqlite-backup/v1"
    backup_path: str
    source_application_id: int = Field(ge=0, le=2**31 - 1)
    source_user_version: int = Field(ge=0, le=2**31 - 1)
    backup_sha256: Digest
    backup_size: int = Field(ge=1, le=2**63 - 1)
    created_at: datetime
    manifest_digest: Digest

    @field_validator("backup_sha256", "manifest_digest")
    @classmethod
    def require_digest(cls, value: str) -> str:
        if len(value) != 71 or not value.startswith("sha256:"):
            raise ValueError("backup digest is invalid")
        int(value[7:], 16)
        return value

    @field_validator("created_at")
    @classmethod
    def require_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("backup time must include a timezone")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def validate_digest(self) -> BackupManifest:
        if self.manifest_digest != _manifest_digest(self):
            raise ValueError("backup manifest digest does not match")
        return self

    @classmethod
    def issue(cls, **values: object) -> BackupManifest:
        payload = dict(values)
        payload.setdefault("schema_version", "cargomesh.sqlite-backup/v1")
        unsigned = cls.model_construct(_fields_set=set(payload), **payload)
        payload["manifest_digest"] = _manifest_digest(unsigned)
        return cls.model_validate(payload)

    @property
    def digest(self) -> str:
        return self.manifest_digest


class RestoreResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    destination_path: str
    application_id: int = Field(ge=0, le=2**31 - 1)
    user_version: int = Field(ge=0, le=2**31 - 1)
    backup_sha256: Digest
    backup_size: int = Field(ge=1, le=2**63 - 1)


class SQLiteBackupService:
    """Consistent backup service that never overwrites caller files."""

    def __init__(
        self,
        application_id: int | None = None,
        *,
        expected_application_id: int | None = None,
    ) -> None:
        if application_id is not None and expected_application_id is not None:
            raise ValueError("application identity was specified twice")
        if expected_application_id is not None:
            application_id = expected_application_id
        if application_id is not None and not 0 <= application_id <= 2**31 - 1:
            raise ValueError("application_id is out of bounds")
        self.application_id = application_id

    def backup(
        self,
        source: str | Path,
        destination: str | Path,
        *,
        created_at: datetime | None = None,
    ) -> BackupManifest:
        source_path = _source_file(source)
        try:
            if Path(destination).resolve(strict=False) == source_path:
                raise BackupError("same_source_destination")
        except BackupError:
            raise
        except Exception as exc:
            del exc
            raise BackupError("invalid_destination_path") from None
        destination_path = _new_destination(destination)
        created = _utc_now(created_at)
        created_target = False
        keep_target = False
        source_db: sqlite3.Connection | None = None
        destination_db: sqlite3.Connection | None = None
        try:
            source_db = sqlite3.connect(
                f"file:{source_path.as_posix()}?mode=ro", uri=True, timeout=10
            )
            _check_database(source_db, self.application_id)
            application_id = int(source_db.execute("PRAGMA application_id").fetchone()[0])
            user_version = int(source_db.execute("PRAGMA user_version").fetchone()[0])
            _create_exclusive(destination_path)
            created_target = True
            destination_db = sqlite3.connect(str(destination_path), timeout=10)
            source_db.backup(destination_db)
            destination_db.commit()
            _check_database(destination_db, application_id)
            destination_db.close()
            destination_db = None
            backup_bytes = destination_path.read_bytes()
            manifest = BackupManifest.issue(
                backup_path=str(destination_path),
                source_application_id=application_id,
                source_user_version=user_version,
                backup_sha256=_sha256(backup_bytes),
                backup_size=len(backup_bytes),
                created_at=created,
            )
            keep_target = True
            return manifest
        except BackupError:
            raise
        except Exception as exc:
            del exc
            raise BackupError("backup_failed") from None
        finally:
            if destination_db is not None:
                destination_db.close()
            if source_db is not None:
                source_db.close()
            if created_target and not keep_target:
                # Only remove the exact target created by this invocation.
                _remove_created(destination_path)

    def restore(
        self,
        manifest: BackupManifest,
        destination: str | Path,
    ) -> RestoreResult:
        try:
            manifest = BackupManifest.model_validate(manifest.model_dump(mode="python"))
        except Exception as exc:
            del exc
            raise BackupError("backup_manifest_invalid") from None
        destination_path = _new_destination(destination)
        source_path = _source_file(manifest.backup_path)
        created_target = False
        keep_target = False
        database: sqlite3.Connection | None = None
        try:
            _validate_manifest_file(manifest, source_path)
            _create_exclusive(destination_path)
            created_target = True
            with source_path.open("rb") as source_file, destination_path.open("wb") as target_file:
                while chunk := source_file.read(1024 * 1024):
                    target_file.write(chunk)
            database = sqlite3.connect(str(destination_path), timeout=10)
            _check_database(database, manifest.source_application_id)
            user_version = int(database.execute("PRAGMA user_version").fetchone()[0])
            if user_version != manifest.source_user_version:
                raise BackupError("backup_identity_mismatch")
            database.close()
            database = None
            data = destination_path.read_bytes()
            if len(data) != manifest.backup_size or _sha256(data) != manifest.backup_sha256:
                raise BackupError("backup_digest_mismatch")
            result = RestoreResult(
                destination_path=str(destination_path),
                application_id=manifest.source_application_id,
                user_version=user_version,
                backup_sha256=manifest.backup_sha256,
                backup_size=len(data),
            )
            keep_target = True
            return result
        except BackupError:
            raise
        except Exception as exc:
            del exc
            raise BackupError("restore_failed") from None
        finally:
            if database is not None:
                database.close()
            if created_target and not keep_target:
                _remove_created(destination_path)

    create_backup = backup
    restore_backup = restore


def _source_file(value: str | Path) -> Path:
    path = Path(value)
    try:
        if path.is_symlink() or not path.exists() or not path.is_file():
            raise BackupError("invalid_source_path")
        return path.resolve(strict=True)
    except BackupError:
        raise
    except Exception as exc:
        del exc
        raise BackupError("invalid_source_path") from None


def _new_destination(value: str | Path) -> Path:
    path = Path(value)
    try:
        if path.exists() or path.is_symlink():
            raise BackupError("destination_exists")
        parent = path.parent
        if parent.is_symlink() or not parent.exists() or not parent.is_dir():
            raise BackupError("invalid_destination_path")
        return path.resolve(strict=False)
    except BackupError:
        raise
    except Exception as exc:
        del exc
        raise BackupError("invalid_destination_path") from None


def _create_exclusive(path: Path) -> None:
    try:
        descriptor = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(descriptor)
    except FileExistsError as exc:
        raise BackupError("destination_exists") from exc
    except OSError as exc:
        raise BackupError("destination_create_failed") from exc


def _remove_created(path: Path) -> None:
    try:
        if path.is_file() and not path.is_symlink():
            path.unlink()
    except OSError:
        pass


def _check_database(connection: sqlite3.Connection, expected_application_id: int | None) -> None:
    result = connection.execute("PRAGMA integrity_check").fetchone()
    if result is None or result[0] != "ok":
        raise BackupError("sqlite_integrity_failed")
    app_id = int(connection.execute("PRAGMA application_id").fetchone()[0])
    if expected_application_id is not None and app_id != expected_application_id:
        raise BackupError("application_identity_mismatch")


def _validate_manifest_file(manifest: BackupManifest, source_path: Path) -> None:
    data = source_path.read_bytes()
    if len(data) != manifest.backup_size or _sha256(data) != manifest.backup_sha256:
        raise BackupError("backup_digest_mismatch")


def _utc_now(value: datetime | None) -> datetime:
    current = value or datetime.now(UTC)
    if current.tzinfo is None or current.utcoffset() is None:
        raise BackupError("invalid_backup_time")
    return current.astimezone(UTC)


def _sha256(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _manifest_digest(manifest: BackupManifest) -> str:
    value = {
        "schema_version": manifest.schema_version,
        "backup_path": manifest.backup_path,
        "source_application_id": manifest.source_application_id,
        "source_user_version": manifest.source_user_version,
        "backup_sha256": manifest.backup_sha256,
        "backup_size": manifest.backup_size,
        "created_at": manifest.created_at.astimezone(UTC).isoformat(timespec="microseconds"),
    }
    canonical = json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
    return _sha256(canonical)


__all__ = [
    "BackupError",
    "BackupManifest",
    "BackupService",
    "RestoreResult",
    "SQLiteBackup",
    "SQLiteBackupService",
]

BackupService = SQLiteBackupService
SQLiteBackup = SQLiteBackupService
