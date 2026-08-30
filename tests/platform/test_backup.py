import sqlite3
from datetime import UTC, datetime

import pytest

from cargomesh.platform.backup import BackupError, SQLiteBackupService


def source_database(path) -> None:
    connection = sqlite3.connect(path)
    connection.execute("PRAGMA application_id=4242")
    connection.execute("PRAGMA user_version=9")
    connection.execute("CREATE TABLE records (value TEXT)")
    connection.execute("INSERT INTO records VALUES ('metadata')")
    connection.commit()
    connection.close()


def test_consistent_backup_manifest_and_restore(tmp_path) -> None:
    source = tmp_path / "source.db"
    backup = tmp_path / "backup.db"
    restored = tmp_path / "restored.db"
    source_database(source)
    service = SQLiteBackupService(application_id=4242)
    manifest = service.backup(source, backup, created_at=datetime(2026, 1, 1, tzinfo=UTC))
    assert backup.exists() and manifest.backup_size == backup.stat().st_size
    result = service.restore(manifest, restored)
    assert result.application_id == 4242 and result.user_version == 9
    with sqlite3.connect(restored) as connection:
        assert connection.execute("SELECT value FROM records").fetchone() == ("metadata",)


def test_backup_rejects_wrong_identity_existing_destination_and_tampering(tmp_path) -> None:
    source = tmp_path / "source.db"
    backup = tmp_path / "backup.db"
    source_database(source)
    with pytest.raises(BackupError) as wrong:
        SQLiteBackupService(application_id=7).backup(source, backup)
    assert wrong.value.code == "application_identity_mismatch"

    service = SQLiteBackupService(application_id=4242)
    manifest = service.backup(source, backup)
    with pytest.raises(BackupError) as exists:
        service.backup(source, backup)
    assert exists.value.code == "destination_exists"
    backup.write_bytes(backup.read_bytes() + b"tampered")
    with pytest.raises(BackupError) as tampered:
        service.restore(manifest, tmp_path / "restored.db")
    assert tampered.value.code == "backup_digest_mismatch"


def test_backup_rejects_directory_and_cleans_failed_target(tmp_path) -> None:
    source = tmp_path / "source.db"
    source_database(source)
    service = SQLiteBackupService(application_id=4242)
    with pytest.raises(BackupError):
        service.backup(source, tmp_path)
    destination = tmp_path / "nested" / "backup.db"
    with pytest.raises(BackupError) as missing_parent:
        service.backup(source, destination)
    assert missing_parent.value.code == "invalid_destination_path"


def test_restore_revalidates_manifest_before_creating_destination(tmp_path) -> None:
    source = tmp_path / "source.db"
    backup = tmp_path / "backup.db"
    restored = tmp_path / "restored.db"
    source_database(source)
    service = SQLiteBackupService(application_id=4242)
    manifest = service.backup(source, backup)
    tampered = manifest.model_copy(update={"source_user_version": 10})
    with pytest.raises(BackupError) as invalid:
        service.restore(tampered, restored)
    assert invalid.value.code == "backup_manifest_invalid"
    assert not restored.exists()
