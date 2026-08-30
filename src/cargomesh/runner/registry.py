"""Atomic SQLite metadata registry for enrolled Private Runners."""

from __future__ import annotations

import secrets
import sqlite3
import threading
from contextlib import suppress
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Protocol

from .identity import (
    EnrollmentChallenge,
    EnrollmentChallengeIssue,
    EnrollmentToken,
    RunnerHealth,
    RunnerIdentity,
    RunnerRecord,
    sha256_digest,
)

_SCHEMA_COMPONENT = "cargomesh.runner-registry/v1"
_SCHEMA_VERSION = 1


class RunnerEnrollmentError(RuntimeError):
    """A bounded enrollment failure that never contains a token or key value."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(message)


class RunnerRegistryError(RuntimeError):
    """A safe registry/health error suitable for a future control-plane transport."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(message)


class RunnerRegistry(Protocol):
    def authorize(
        self,
        runner_id: str,
        tenant_id: str,
        environment_id: str,
        runner_pool: str,
        capability: str,
    ) -> bool: ...

    def issue_challenge(
        self,
        tenant_id: str,
        environment_id: str,
        runner_pool: str,
        *,
        ttl_seconds: int = 600,
        now: datetime | None = None,
    ) -> EnrollmentChallengeIssue: ...

    def enroll(
        self,
        challenge_id: str,
        token: str | EnrollmentToken,
        *,
        tenant_id: str,
        environment_id: str,
        runner_pool: str,
        public_key_digest: str,
        capabilities: tuple[str, ...],
        platform: str,
        version: str,
        runner_id: str | None = None,
        now: datetime | None = None,
    ) -> RunnerIdentity: ...

    def get(
        self, runner_id: str, *, tenant_id: str, environment_id: str, runner_pool: str
    ) -> RunnerRecord | None: ...

    def list(
        self, tenant_id: str, environment_id: str, runner_pool: str
    ) -> tuple[RunnerRecord, ...]: ...

    def revoke(
        self,
        runner_id: str,
        *,
        tenant_id: str,
        environment_id: str,
        runner_pool: str,
        now: datetime | None = None,
    ) -> RunnerRecord: ...

    def heartbeat(
        self,
        runner_id: str,
        *,
        tenant_id: str,
        environment_id: str,
        runner_pool: str,
        now: datetime | None = None,
    ) -> RunnerRecord: ...


class SQLiteRunnerRegistry:
    """Reference registry containing scoped metadata and no plaintext enrollment token.

    Enrollment consumes one challenge using ``BEGIN IMMEDIATE`` so simultaneous
    callers have exactly one winner.  It is deliberately a local SQLite boundary,
    not a remote certificate authority or production mTLS implementation.
    """

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
            raise RunnerRegistryError(
                "runner_registry_unavailable", "Runner registry is unavailable"
            ) from exc

    def issue_challenge(
        self,
        tenant_id: str,
        environment_id: str,
        runner_pool: str,
        *,
        ttl_seconds: int = 600,
        now: datetime | None = None,
    ) -> EnrollmentChallengeIssue:
        self._ensure_open()
        issued_at = _now(now)
        if not isinstance(ttl_seconds, int) or isinstance(ttl_seconds, bool):
            raise ValueError("enrollment ttl must be an integer")
        if not 1 <= ttl_seconds <= 3600:
            raise ValueError("enrollment ttl must be between 1 and 3600 seconds")
        challenge = EnrollmentChallenge(
            challenge_id=_new_id("enroll"),
            tenant_id=tenant_id,
            environment_id=environment_id,
            runner_pool=runner_pool,
            issued_at=issued_at,
            expires_at=issued_at + timedelta(seconds=ttl_seconds),
        )
        token_value = secrets.token_urlsafe(32)
        try:
            with self._lock:
                self._connection.execute(
                    "INSERT INTO enrollment_challenges "
                    "(challenge_id,tenant_id,environment_id,runner_pool,token_digest,"
                    "issued_at,expires_at,consumed_at) VALUES (?,?,?,?,?,?,?,NULL)",
                    (
                        challenge.challenge_id,
                        challenge.tenant_id,
                        challenge.environment_id,
                        challenge.runner_pool,
                        sha256_digest(token_value),
                        _store_time(challenge.issued_at),
                        _store_time(challenge.expires_at),
                    ),
                )
        except sqlite3.Error as exc:
            raise RunnerRegistryError(
                "runner_registry_unavailable", "Runner registry is unavailable"
            ) from exc
        return EnrollmentChallengeIssue(challenge, EnrollmentToken(token_value))

    create_challenge = issue_challenge

    def authorize(
        self,
        runner_id: str,
        tenant_id: str,
        environment_id: str,
        runner_pool: str,
        capability: str,
    ) -> bool:
        record = self.get(
            runner_id,
            tenant_id=tenant_id,
            environment_id=environment_id,
            runner_pool=runner_pool,
        )
        return bool(
            record is not None
            and record.health is RunnerHealth.ONLINE
            and capability in record.identity.capabilities
        )

    def enroll(
        self,
        challenge_id: str,
        token: str | EnrollmentToken,
        *,
        tenant_id: str,
        environment_id: str,
        runner_pool: str,
        public_key_digest: str,
        capabilities: tuple[str, ...],
        platform: str,
        version: str,
        runner_id: str | None = None,
        now: datetime | None = None,
    ) -> RunnerIdentity:
        self._ensure_open()
        enrolled_at = _now(now)
        token_value = _take_token(token)
        try:
            with self._lock:
                c = self._connection
                c.execute("BEGIN IMMEDIATE")
                challenge = c.execute(
                    "SELECT * FROM enrollment_challenges WHERE challenge_id=?", (challenge_id,)
                ).fetchone()
                if challenge is None:
                    raise RunnerEnrollmentError(
                        "enrollment_challenge_unknown", "Enrollment challenge is invalid"
                    )
                if (
                    challenge["tenant_id"] != tenant_id
                    or challenge["environment_id"] != environment_id
                    or challenge["runner_pool"] != runner_pool
                ):
                    raise RunnerEnrollmentError(
                        "enrollment_scope_mismatch", "Enrollment challenge scope is invalid"
                    )
                if challenge["consumed_at"] is not None:
                    raise RunnerEnrollmentError(
                        "enrollment_token_used", "Enrollment token has already been used"
                    )
                if _load_time(challenge["expires_at"]) <= enrolled_at:
                    raise RunnerEnrollmentError(
                        "enrollment_token_expired", "Enrollment token has expired"
                    )
                if not secrets.compare_digest(
                    challenge["token_digest"], sha256_digest(token_value)
                ):
                    raise RunnerEnrollmentError(
                        "enrollment_token_invalid", "Enrollment token is invalid"
                    )
                identity = RunnerIdentity.issue(
                    runner_id=runner_id or _new_id("runner"),
                    tenant_id=tenant_id,
                    environment_id=environment_id,
                    runner_pool=runner_pool,
                    task_queue_id=_new_id("queue"),
                    public_key_digest=public_key_digest,
                    capabilities=capabilities,
                    platform=platform,
                    version=version,
                    enrolled_at=enrolled_at,
                )
                record = RunnerRecord.issue(identity=identity, health=RunnerHealth.ONLINE)
                by_runner = c.execute(
                    "SELECT 1 FROM runners WHERE runner_id=?", (identity.runner_id,)
                ).fetchone()
                if by_runner is not None:
                    raise RunnerEnrollmentError(
                        "runner_identity_conflict", "Runner identity could not be enrolled"
                    )
                c.execute(
                    "INSERT INTO runners "
                    "(runner_id,tenant_id,environment_id,runner_pool,health,last_heartbeat_at,"
                    "revoked_at,identity_digest,identity_json,record_digest,record_json) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    _runner_row(record),
                )
                c.execute(
                    "UPDATE enrollment_challenges SET consumed_at=? WHERE challenge_id=?",
                    (_store_time(enrolled_at), challenge_id),
                )
                c.commit()
                return identity
        except (RunnerEnrollmentError, RunnerRegistryError):
            _rollback(self._connection)
            raise
        except sqlite3.Error as exc:
            _rollback(self._connection)
            raise RunnerRegistryError(
                "runner_registry_unavailable", "Runner registry is unavailable"
            ) from exc
        except Exception as exc:
            _rollback(self._connection)
            raise RunnerEnrollmentError(
                "runner_identity_invalid", "Runner identity is invalid"
            ) from exc

    register = enroll

    def get(
        self, runner_id: str, *, tenant_id: str, environment_id: str, runner_pool: str
    ) -> RunnerRecord | None:
        self._ensure_open()
        with self._lock:
            try:
                row = self._connection.execute(
                    "SELECT * FROM runners WHERE runner_id=? AND tenant_id=? "
                    "AND environment_id=? AND runner_pool=?",
                    (runner_id, tenant_id, environment_id, runner_pool),
                ).fetchone()
            except sqlite3.Error as exc:
                raise RunnerRegistryError(
                    "runner_registry_unavailable", "Runner registry is unavailable"
                ) from exc
        return None if row is None else self._decode_record(row)

    def list(
        self, tenant_id: str, environment_id: str, runner_pool: str
    ) -> tuple[RunnerRecord, ...]:
        self._ensure_open()
        with self._lock:
            try:
                rows = self._connection.execute(
                    "SELECT * FROM runners WHERE tenant_id=? AND environment_id=? "
                    "AND runner_pool=? ORDER BY runner_id",
                    (tenant_id, environment_id, runner_pool),
                ).fetchall()
            except sqlite3.Error as exc:
                raise RunnerRegistryError(
                    "runner_registry_unavailable", "Runner registry is unavailable"
                ) from exc
        return tuple(self._decode_record(row) for row in rows)

    list_runners = list

    def revoke(
        self,
        runner_id: str,
        *,
        tenant_id: str,
        environment_id: str,
        runner_pool: str,
        now: datetime | None = None,
    ) -> RunnerRecord:
        return self._set_health(
            runner_id,
            tenant_id=tenant_id,
            environment_id=environment_id,
            runner_pool=runner_pool,
            health=RunnerHealth.REVOKED,
            now=now,
        )

    def heartbeat(
        self,
        runner_id: str,
        *,
        tenant_id: str,
        environment_id: str,
        runner_pool: str,
        now: datetime | None = None,
    ) -> RunnerRecord:
        return self._set_health(
            runner_id,
            tenant_id=tenant_id,
            environment_id=environment_id,
            runner_pool=runner_pool,
            health=RunnerHealth.ONLINE,
            now=now,
        )

    def mark_offline(
        self,
        runner_id: str,
        *,
        tenant_id: str,
        environment_id: str,
        runner_pool: str,
        now: datetime | None = None,
    ) -> RunnerRecord:
        return self._set_health(
            runner_id,
            tenant_id=tenant_id,
            environment_id=environment_id,
            runner_pool=runner_pool,
            health=RunnerHealth.OFFLINE,
            now=now,
        )

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._connection.close()
                self._closed = True

    def __enter__(self) -> SQLiteRunnerRegistry:
        self._ensure_open()
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

    def _initialize_schema(self) -> None:
        c = self._connection
        c.execute(
            "CREATE TABLE IF NOT EXISTS runner_schema_version "
            "(component TEXT PRIMARY KEY, version INTEGER NOT NULL)"
        )
        row = c.execute(
            "SELECT version FROM runner_schema_version WHERE component=?", (_SCHEMA_COMPONENT,)
        ).fetchone()
        if row is not None and row["version"] != _SCHEMA_VERSION:
            raise RunnerRegistryError(
                "runner_schema_unsupported", "Runner registry schema is unsupported"
            )
        c.execute(
            "INSERT OR IGNORE INTO runner_schema_version(component,version) VALUES (?,?)",
            (_SCHEMA_COMPONENT, _SCHEMA_VERSION),
        )
        c.execute(
            """CREATE TABLE IF NOT EXISTS enrollment_challenges (
                challenge_id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                environment_id TEXT NOT NULL,
                runner_pool TEXT NOT NULL,
                token_digest TEXT NOT NULL,
                issued_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                consumed_at TEXT NULL
            )"""
        )
        c.execute(
            """CREATE TABLE IF NOT EXISTS runners (
                runner_id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                environment_id TEXT NOT NULL,
                runner_pool TEXT NOT NULL,
                health TEXT NOT NULL,
                last_heartbeat_at TEXT NULL,
                revoked_at TEXT NULL,
                identity_digest TEXT NOT NULL,
                identity_json TEXT NOT NULL,
                record_digest TEXT NOT NULL,
                record_json TEXT NOT NULL
            )"""
        )

    def _set_health(
        self,
        runner_id: str,
        *,
        tenant_id: str,
        environment_id: str,
        runner_pool: str,
        health: RunnerHealth,
        now: datetime | None,
    ) -> RunnerRecord:
        self._ensure_open()
        changed_at = _now(now)
        with self._lock:
            c = self._connection
            try:
                c.execute("BEGIN IMMEDIATE")
                row = c.execute(
                    "SELECT * FROM runners WHERE runner_id=? AND tenant_id=? "
                    "AND environment_id=? AND runner_pool=?",
                    (runner_id, tenant_id, environment_id, runner_pool),
                ).fetchone()
                if row is None:
                    raise RunnerRegistryError("runner_not_found", "Runner was not found")
                current = self._decode_record(row)
                if current.health is RunnerHealth.REVOKED and health is not RunnerHealth.REVOKED:
                    raise RunnerRegistryError(
                        "runner_revoked", "Revoked runner cannot report health"
                    )
                if health is RunnerHealth.REVOKED and current.health is RunnerHealth.REVOKED:
                    c.commit()
                    return current
                record = RunnerRecord.issue(
                    identity=current.identity,
                    health=health,
                    last_heartbeat_at=(
                        changed_at
                        if health is RunnerHealth.ONLINE
                        else current.last_heartbeat_at
                    ),
                    revoked_at=(changed_at if health is RunnerHealth.REVOKED else None),
                )
                c.execute(
                    "UPDATE runners SET health=?,last_heartbeat_at=?,revoked_at=?,record_digest=?,"
                    "record_json=? WHERE runner_id=?",
                    (
                        record.health.value,
                        _store_time(record.last_heartbeat_at),
                        _store_time(record.revoked_at),
                        record.record_digest,
                        record.model_dump_json(),
                        runner_id,
                    ),
                )
                c.commit()
                return record
            except RunnerRegistryError:
                _rollback(c)
                raise
            except sqlite3.Error as exc:
                _rollback(c)
                raise RunnerRegistryError(
                    "runner_registry_unavailable", "Runner registry is unavailable"
                ) from exc

    @staticmethod
    def _decode_record(row: sqlite3.Row) -> RunnerRecord:
        try:
            record = RunnerRecord.model_validate_json(row["record_json"])
            identity = record.identity
            stored_identity = RunnerIdentity.model_validate_json(row["identity_json"])
            if (
                stored_identity != identity
                or stored_identity.identity_digest != row["identity_digest"]
                or
                identity.runner_id != row["runner_id"]
                or identity.tenant_id != row["tenant_id"]
                or identity.environment_id != row["environment_id"]
                or identity.runner_pool != row["runner_pool"]
                or identity.identity_digest != row["identity_digest"]
                or record.health.value != row["health"]
                or record.record_digest != row["record_digest"]
            ):
                raise ValueError("runner metadata mismatch")
            return record
        except Exception as exc:
            raise RunnerRegistryError(
                "runner_registry_integrity_error", "Stored runner metadata is invalid"
            ) from exc

    def _ensure_open(self) -> None:
        if self._closed:
            raise RunnerRegistryError("runner_registry_closed", "Runner registry is closed")


def _new_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_urlsafe(32)}"


def _take_token(token: str | EnrollmentToken) -> str:
    if isinstance(token, EnrollmentToken):
        return token.take()
    if not isinstance(token, str) or not token or len(token) > 512:
        raise RunnerEnrollmentError("enrollment_token_invalid", "Enrollment token is invalid")
    return token


def _now(value: datetime | None) -> datetime:
    result = datetime.now(UTC) if value is None else value
    if result.tzinfo is None or result.utcoffset() is None:
        raise ValueError("runner timestamp must include a timezone")
    return result.astimezone(UTC)


def _store_time(value: datetime | None) -> str | None:
    return None if value is None else value.astimezone(UTC).isoformat(timespec="microseconds")


def _load_time(value: object) -> datetime:
    if not isinstance(value, str):
        raise RunnerRegistryError(
            "runner_registry_integrity_error", "Stored runner metadata is invalid"
        )
    parsed = datetime.fromisoformat(value)
    return _now(parsed)


def _runner_row(record: RunnerRecord) -> tuple[object, ...]:
    identity = record.identity
    return (
        identity.runner_id,
        identity.tenant_id,
        identity.environment_id,
        identity.runner_pool,
        record.health.value,
        _store_time(record.last_heartbeat_at),
        _store_time(record.revoked_at),
        identity.identity_digest,
        identity.model_dump_json(),
        record.record_digest,
        record.model_dump_json(),
    )


def _rollback(connection: sqlite3.Connection) -> None:
    with suppress(sqlite3.Error):
        connection.rollback()


__all__ = [
    "RunnerEnrollmentError",
    "RunnerRegistry",
    "RunnerRegistryError",
    "SQLiteRunnerRegistry",
]
