"""Single-node, tenant/environment-scoped membership directory."""

from __future__ import annotations

import sqlite3
import threading
from contextlib import suppress
from pathlib import Path
from typing import Any, Protocol

from .authorization import MembershipProvider
from .models import (
    MEMBERSHIP_SCHEMA_VERSION,
    Principal,
    TenantMembership,
)


class MembershipConflict(RuntimeError):
    code = "membership_conflict"


class MembershipNotFound(RuntimeError):
    code = "membership_not_found"


class MembershipStoreError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class MembershipStore(MembershipProvider, Protocol):
    """Read/write protocol implemented by the membership directory."""

    def provision(self, membership: TenantMembership) -> TenantMembership: ...
    def replace(
        self, membership: TenantMembership | str, **changes: object
    ) -> TenantMembership: ...
    def get(self, membership_id: str) -> TenantMembership | None: ...
    def list(
        self, tenant_id: str, environment_id: str | None = None
    ) -> tuple[TenantMembership, ...]: ...
    def close(self) -> None: ...


class SQLiteMembershipStore:
    """SQLite reference directory for one process/node.

    Membership rows contain only the validated membership contract.  In
    particular, there is intentionally no token, claim, credential, or secret
    column.  Provisioning is an exact replay when the unique identity key has
    the same digest; a changed row must use ``replace`` explicitly.
    """

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
            raise MembershipStoreError(
                "membership_store_unavailable", "Membership store is unavailable"
            ) from exc

    def _initialize_schema(self) -> None:
        c = self._connection
        c.execute(
            "CREATE TABLE IF NOT EXISTS membership_schema_version "
            "(component TEXT PRIMARY KEY, version INTEGER NOT NULL)"
        )
        row = c.execute(
            "SELECT version FROM membership_schema_version WHERE component = ?",
            (MEMBERSHIP_SCHEMA_VERSION,),
        ).fetchone()
        if row is not None and row["version"] != self.SCHEMA_VERSION:
            raise MembershipStoreError(
                "membership_schema_unsupported", "Unsupported membership schema"
            )
        c.execute(
            "INSERT OR IGNORE INTO membership_schema_version(component,version) VALUES (?,?)",
            (MEMBERSHIP_SCHEMA_VERSION, self.SCHEMA_VERSION),
        )
        c.execute(
            """CREATE TABLE IF NOT EXISTS memberships (
                membership_id TEXT PRIMARY KEY,
                issuer TEXT NOT NULL,
                subject TEXT NOT NULL,
                principal_type TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                environment_id TEXT NOT NULL,
                role TEXT NOT NULL,
                status TEXT NOT NULL,
                revision INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                membership_digest TEXT NOT NULL,
                membership_json TEXT NOT NULL,
                UNIQUE(issuer, subject, tenant_id, environment_id, role)
            )"""
        )
        # Membership replacement is an explicit, revisioned operation, so this
        # directory is mutable by that method.  There is no delete operation.

    def provision(self, membership: TenantMembership) -> TenantMembership:
        self._ensure_open()
        value = self._validate_membership(membership)
        with self._lock:
            c = self._connection
            try:
                c.execute("BEGIN IMMEDIATE")
                row = c.execute(
                    "SELECT membership_digest, membership_json FROM memberships "
                    "WHERE issuer=? AND subject=? AND tenant_id=? AND environment_id=? AND role=?",
                    self._identity_key(value),
                ).fetchone()
                if row is not None:
                    if row["membership_digest"] != value.membership_digest:
                        raise MembershipConflict(
                            "membership already exists; use replace for changes"
                        )
                    c.commit()
                    return self._decode(row["membership_json"], row["membership_digest"])
                # A caller cannot silently reassign an existing membership id.
                by_id = c.execute(
                    "SELECT membership_digest FROM memberships WHERE membership_id=?",
                    (value.membership_id,),
                ).fetchone()
                if by_id is not None:
                    raise MembershipConflict("membership id already contains different content")
                c.execute(
                    "INSERT INTO memberships VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    self._row_values(value),
                )
                c.commit()
                return value
            except (MembershipConflict, MembershipStoreError):
                _rollback(c)
                raise
            except sqlite3.Error as exc:
                _rollback(c)
                raise MembershipStoreError(
                    "membership_store_unavailable", "Membership store is unavailable"
                ) from exc

    def replace(
        self, membership: TenantMembership | str, **changes: object
    ) -> TenantMembership:
        """Replace an existing membership and advance its integer revision.

        The supplied object identifies the existing row by ``membership_id``;
        its role/status and other immutable contract values describe the new
        configuration.  The store, rather than the caller, chooses revision.
        """

        self._ensure_open()
        if isinstance(membership, str):
            current = self.get(membership)
            if current is None:
                raise MembershipNotFound("membership does not exist")
            payload = current.model_dump()
            payload.update(changes)
            membership = TenantMembership.issue(**payload)
        elif changes:
            raise TypeError("replacement changes require a membership id")
        value = self._validate_membership(membership)
        with self._lock:
            c = self._connection
            try:
                c.execute("BEGIN IMMEDIATE")
                row = c.execute(
                    "SELECT membership_json FROM memberships WHERE membership_id=?",
                    (value.membership_id,),
                ).fetchone()
                if row is None:
                    raise MembershipNotFound("membership does not exist")
                current = self._decode(row["membership_json"], None)
                if (
                    current.issuer != value.issuer
                    or current.subject != value.subject
                    or current.tenant_id != value.tenant_id
                    or current.environment_id != value.environment_id
                    or current.principal_type != value.principal_type
                ):
                    raise MembershipConflict("membership identity cannot be reassigned")
                now = value.updated_at
                if now < current.updated_at:
                    raise MembershipConflict("membership update time cannot move backwards")
                replacement = TenantMembership.issue(
                    membership_id=current.membership_id,
                    issuer=current.issuer,
                    subject=current.subject,
                    principal_type=current.principal_type,
                    tenant_id=current.tenant_id,
                    environment_id=current.environment_id,
                    role=value.role,
                    status=value.status,
                    revision=current.revision + 1,
                    created_at=current.created_at,
                    updated_at=now,
                )
                # The old role key must not collide with another membership.
                conflict = c.execute(
                    "SELECT membership_id FROM memberships WHERE issuer=? AND subject=? "
                    "AND tenant_id=? AND environment_id=? AND role=? AND membership_id<>?",
                    (*self._identity_key(replacement), replacement.membership_id),
                ).fetchone()
                if conflict is not None:
                    raise MembershipConflict("replacement role already exists")
                c.execute(
                    "UPDATE memberships SET issuer=?,subject=?,principal_type=?,tenant_id=?,"
                    "environment_id=?,role=?,status=?,revision=?,created_at=?,updated_at=?,"
                    "membership_digest=?,membership_json=? WHERE membership_id=?",
                    (*self._row_values(replacement)[1:], replacement.membership_id),
                )
                c.commit()
                return replacement
            except (MembershipConflict, MembershipNotFound, MembershipStoreError):
                _rollback(c)
                raise
            except sqlite3.Error as exc:
                _rollback(c)
                raise MembershipStoreError(
                    "membership_store_unavailable", "Membership store is unavailable"
                ) from exc

    # Explicit spelling is useful to callers and avoids confusing replacement
    # with a normal upsert.
    replace_membership = replace

    def get(self, membership_id: str) -> TenantMembership | None:
        self._ensure_open()
        with self._lock:
            try:
                row = self._connection.execute(
                    "SELECT membership_digest,membership_json FROM memberships "
                    "WHERE membership_id=?",
                    (membership_id,),
                ).fetchone()
            except sqlite3.Error as exc:
                raise MembershipStoreError(
                    "membership_store_unavailable", "Membership store is unavailable"
                ) from exc
            return (
                None
                if row is None
                else self._decode(row["membership_json"], row["membership_digest"])
            )

    def get_memberships(
        self, principal: Principal, tenant_id: str, environment_id: str
    ) -> tuple[TenantMembership, ...]:
        self._ensure_open()
        with self._lock:
            try:
                rows = self._connection.execute(
                    "SELECT membership_digest,membership_json FROM memberships WHERE issuer=? "
                    "AND subject=? AND principal_type=? AND tenant_id=? AND environment_id=? "
                    "ORDER BY role",
                    (
                        principal.issuer,
                        principal.subject,
                        principal.principal_type.value,
                        tenant_id,
                        environment_id,
                    ),
                ).fetchall()
            except sqlite3.Error as exc:
                raise MembershipStoreError(
                    "membership_store_unavailable", "Membership store is unavailable"
                ) from exc
            return tuple(
                self._decode(row["membership_json"], row["membership_digest"])
                for row in rows
            )

    memberships_for = get_memberships
    list_memberships = get_memberships
    get_for_principal = get_memberships
    list_for_principal = get_memberships

    def list(
        self, tenant_id: str, environment_id: str | None = None
    ) -> tuple[TenantMembership, ...]:
        self._ensure_open()
        with self._lock:
            query = "SELECT membership_digest,membership_json FROM memberships WHERE tenant_id=?"
            params: list[str] = [tenant_id]
            if environment_id is not None:
                query += " AND environment_id=?"
                params.append(environment_id)
            query += " ORDER BY environment_id,issuer,subject,role"
            try:
                rows = self._connection.execute(query, params).fetchall()
            except sqlite3.Error as exc:
                raise MembershipStoreError(
                    "membership_store_unavailable", "Membership store is unavailable"
                ) from exc
            return tuple(
                self._decode(row["membership_json"], row["membership_digest"])
                for row in rows
            )

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._connection.close()
                self._closed = True

    def __enter__(self) -> SQLiteMembershipStore:
        self._ensure_open()
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

    @staticmethod
    def _identity_key(value: TenantMembership) -> tuple[str, str, str, str, str]:
        return (
            value.issuer,
            value.subject,
            value.tenant_id,
            value.environment_id,
            value.role.value,
        )

    @staticmethod
    def _row_values(value: TenantMembership) -> tuple[str, ...]:
        return (
            value.membership_id,
            value.issuer,
            value.subject,
            value.principal_type.value,
            value.tenant_id,
            value.environment_id,
            value.role.value,
            value.status.value,
            str(value.revision),
            value.created_at.isoformat(),
            value.updated_at.isoformat(),
            value.membership_digest,
            value.model_dump_json(exclude_none=True),
        )

    @staticmethod
    def _validate_membership(value: TenantMembership) -> TenantMembership:
        try:
            return TenantMembership.model_validate(value.model_dump())
        except Exception as exc:
            raise MembershipStoreError("invalid_membership", "Membership is invalid") from exc

    @staticmethod
    def _decode(serialized: str, stored_digest: str | None) -> TenantMembership:
        try:
            value = TenantMembership.model_validate_json(serialized)
            if stored_digest is not None and value.membership_digest != stored_digest:
                raise ValueError("membership digest mismatch")
            return value
        except Exception as exc:
            raise MembershipStoreError(
                "membership_integrity_error", "Stored membership is invalid"
            ) from exc

    def _ensure_open(self) -> None:
        if self._closed:
            raise MembershipStoreError("store_closed", "Membership store is closed")


def _rollback(connection: sqlite3.Connection) -> None:
    with suppress(sqlite3.Error):
        connection.rollback()


__all__ = [
    "MembershipConflict",
    "MembershipNotFound",
    "MembershipProvider",
    "MembershipStore",
    "MembershipStoreError",
    "SQLiteMembershipStore",
]
