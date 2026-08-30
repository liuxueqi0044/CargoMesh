"""Metadata-only SQLite credential binding directory."""

from __future__ import annotations

import sqlite3
import threading
from contextlib import suppress
from pathlib import Path
from typing import Any, Protocol

from .models import CREDENTIAL_BINDING_SCHEMA_VERSION, CredentialBinding, validate_binding


class CredentialBindingConflict(RuntimeError):
    code = "credential_binding_conflict"


class CredentialBindingNotFound(RuntimeError):
    code = "credential_binding_not_found"


class CredentialBindingStoreError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


# Short aliases make the storage boundary easy to discover without weakening
# the more specific exception codes above.
BindingConflict = CredentialBindingConflict
BindingNotFound = CredentialBindingNotFound


class CredentialBindingStore(Protocol):
    def provision(self, binding: CredentialBinding) -> CredentialBinding: ...
    def put(self, binding: CredentialBinding) -> CredentialBinding: ...
    def replace(self, binding: CredentialBinding) -> CredentialBinding: ...
    def get(
        self, tenant_id: str, environment_id: str, adapter: str, capability: str
    ) -> CredentialBinding | None: ...
    def list(
        self, tenant_id: str, environment_id: str | None = None
    ) -> tuple[CredentialBinding, ...]: ...
    def close(self) -> None: ...


class SQLiteCredentialBindingStore:
    """SQLite store containing only binding metadata and opaque references."""

    SCHEMA_VERSION = 1

    def __init__(self, database: str | Path = ":memory:") -> None:
        self._closed = False
        self._lock = threading.RLock()
        self._database = str(database)
        try:
            self._connection = sqlite3.connect(
                self._database, isolation_level=None, check_same_thread=False, timeout=10
            )
            self._connection.row_factory = sqlite3.Row
            if self._database != ":memory:":
                self._connection.execute("PRAGMA journal_mode=WAL")
            self._connection.execute("PRAGMA foreign_keys=ON")
            self._connection.execute("PRAGMA busy_timeout=10000")
            self._initialize_schema()
        except sqlite3.Error as exc:
            raise CredentialBindingStoreError(
                "credential_binding_store_unavailable", "Credential binding store is unavailable"
            ) from exc

    def _initialize_schema(self) -> None:
        c = self._connection
        c.execute(
            "CREATE TABLE IF NOT EXISTS credential_binding_schema_version "
            "(component TEXT PRIMARY KEY, version INTEGER NOT NULL)"
        )
        row = c.execute(
            "SELECT version FROM credential_binding_schema_version WHERE component=?",
            (CREDENTIAL_BINDING_SCHEMA_VERSION,),
        ).fetchone()
        if row is not None and row["version"] != self.SCHEMA_VERSION:
            raise CredentialBindingStoreError(
                "credential_binding_schema_unsupported", "Unsupported credential binding schema"
            )
        c.execute(
            "INSERT OR IGNORE INTO credential_binding_schema_version(component,version) "
            "VALUES (?,?)",
            (CREDENTIAL_BINDING_SCHEMA_VERSION, self.SCHEMA_VERSION),
        )
        c.execute(
            """CREATE TABLE IF NOT EXISTS credential_bindings (
                tenant_id TEXT NOT NULL,
                environment_id TEXT NOT NULL,
                adapter TEXT NOT NULL,
                capability TEXT NOT NULL,
                revision INTEGER NOT NULL,
                binding_digest TEXT NOT NULL,
                binding_json TEXT NOT NULL,
                PRIMARY KEY(tenant_id, environment_id, adapter, capability)
            )"""
        )

    def provision(self, binding: CredentialBinding) -> CredentialBinding:
        return self.put(binding)

    bind = provision

    def put(self, binding: CredentialBinding) -> CredentialBinding:
        self._ensure_open()
        value = self._validate(binding)
        with self._lock:
            c = self._connection
            try:
                c.execute("BEGIN IMMEDIATE")
                row = c.execute(
                    "SELECT * FROM credential_bindings "
                    "WHERE tenant_id=? AND environment_id=? AND adapter=? AND capability=?",
                    value.identity,
                ).fetchone()
                if row is not None:
                    current = self._decode(row)
                    if current.binding_digest != value.binding_digest:
                        raise CredentialBindingConflict(
                            "credential binding exists; use replace for changes"
                        )
                    c.commit()
                    return current
                c.execute(
                    "INSERT INTO credential_bindings VALUES (?,?,?,?,?,?,?)",
                    (
                        *value.identity,
                        value.revision,
                        value.binding_digest,
                        value.model_dump_json(),
                    ),
                )
                c.commit()
                return value
            except (CredentialBindingConflict, CredentialBindingStoreError):
                _rollback(c)
                raise
            except sqlite3.Error as exc:
                _rollback(c)
                raise CredentialBindingStoreError(
                    "credential_binding_store_unavailable",
                    "Credential binding store is unavailable",
                ) from exc

    def replace(self, binding: CredentialBinding) -> CredentialBinding:
        self._ensure_open()
        value = self._validate(binding)
        with self._lock:
            c = self._connection
            try:
                c.execute("BEGIN IMMEDIATE")
                row = c.execute(
                    "SELECT * FROM credential_bindings "
                    "WHERE tenant_id=? AND environment_id=? AND adapter=? AND capability=?",
                    value.identity,
                ).fetchone()
                if row is None:
                    raise CredentialBindingNotFound("credential binding does not exist")
                current = self._decode(row)
                if value.revision != current.revision + 1:
                    raise CredentialBindingConflict(
                        "replacement revision must advance exactly once"
                    )
                c.execute(
                    "UPDATE credential_bindings SET revision=?,binding_digest=?,binding_json=? "
                    "WHERE tenant_id=? AND environment_id=? AND adapter=? AND capability=?",
                    (
                        value.revision,
                        value.binding_digest,
                        value.model_dump_json(),
                        *value.identity,
                    ),
                )
                c.commit()
                return value
            except (
                CredentialBindingConflict,
                CredentialBindingNotFound,
                CredentialBindingStoreError,
            ):
                _rollback(c)
                raise
            except sqlite3.Error as exc:
                _rollback(c)
                raise CredentialBindingStoreError(
                    "credential_binding_store_unavailable",
                    "Credential binding store is unavailable",
                ) from exc

    replace_binding = replace

    def get(
        self, tenant_id: str, environment_id: str, adapter: str, capability: str
    ) -> CredentialBinding | None:
        self._ensure_open()
        with self._lock:
            try:
                row = self._connection.execute(
                    "SELECT * FROM credential_bindings "
                    "WHERE tenant_id=? AND environment_id=? AND adapter=? AND capability=?",
                    (tenant_id, environment_id, adapter, capability),
                ).fetchone()
            except sqlite3.Error as exc:
                raise CredentialBindingStoreError(
                    "credential_binding_store_unavailable",
                    "Credential binding store is unavailable",
                ) from exc
            return None if row is None else self._decode(row)

    def list(
        self, tenant_id: str, environment_id: str | None = None
    ) -> tuple[CredentialBinding, ...]:
        self._ensure_open()
        query = "SELECT * FROM credential_bindings WHERE tenant_id=?"
        params: list[str] = [tenant_id]
        if environment_id is not None:
            query += " AND environment_id=?"
            params.append(environment_id)
        query += " ORDER BY environment_id,adapter,capability"
        with self._lock:
            try:
                rows = self._connection.execute(query, params).fetchall()
            except sqlite3.Error as exc:
                raise CredentialBindingStoreError(
                    "credential_binding_store_unavailable",
                    "Credential binding store is unavailable",
                ) from exc
            return tuple(self._decode(row) for row in rows)

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._connection.close()
                self._closed = True

    def __enter__(self) -> SQLiteCredentialBindingStore:
        self._ensure_open()
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

    @staticmethod
    def _validate(value: CredentialBinding) -> CredentialBinding:
        try:
            return validate_binding(value)
        except Exception as exc:
            raise CredentialBindingStoreError(
                "invalid_credential_binding", "Credential binding is invalid"
            ) from exc

    @staticmethod
    def _decode(row: sqlite3.Row) -> CredentialBinding:
        try:
            value = CredentialBinding.model_validate_json(row["binding_json"])
            if value.binding_digest != row["binding_digest"] or value.identity != (
                row["tenant_id"],
                row["environment_id"],
                row["adapter"],
                row["capability"],
            ):
                raise ValueError("stored binding fields mismatch")
            if value.revision != row["revision"]:
                raise ValueError("stored binding revision mismatch")
            return value
        except Exception as exc:
            raise CredentialBindingStoreError(
                "credential_binding_integrity_error", "Stored credential binding is invalid"
            ) from exc

    def _ensure_open(self) -> None:
        if self._closed:
            raise CredentialBindingStoreError("store_closed", "Credential binding store is closed")


def _rollback(connection: sqlite3.Connection) -> None:
    with suppress(sqlite3.Error):
        connection.rollback()


__all__ = [
    "BindingConflict",
    "BindingNotFound",
    "CredentialBindingConflict",
    "CredentialBindingNotFound",
    "CredentialBindingStore",
    "CredentialBindingStoreError",
    "SQLiteCredentialBindingStore",
]
