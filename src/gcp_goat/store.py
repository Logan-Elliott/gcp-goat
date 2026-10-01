"""Encrypted SQLite credential and audit-event storage for GCP-GOAT."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .crypto import SecretBox


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _to_iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


def _from_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value)


def _google_expiry_from_iso(value: str | None) -> datetime | None:
    """google-auth currently compares expiry to a naive UTC timestamp."""
    expiry = _from_iso(value)
    if expiry is None:
        return None
    if expiry.tzinfo is not None:
        expiry = expiry.astimezone(timezone.utc).replace(tzinfo=None)
    return expiry


@dataclass(frozen=True)
class StoredCredential:
    email: str
    token: str
    refresh_token: str | None
    token_uri: str
    client_id: str
    client_secret: str
    scopes: tuple[str, ...]
    expiry: datetime | None
    created_at: datetime
    updated_at: datetime


class CredentialStore:
    """Persists encrypted OAuth credentials and metadata in SQLite."""

    def __init__(self, path: Path | str, encryption_key: str):
        self.path = Path(path)
        self.box = SecretBox(encryption_key)
        self._initialize()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 10000")
        try:
            yield connection
            connection.commit()
        finally:
            connection.close()

    def _initialize(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.parent != Path("."):
            with suppress(OSError):
                self.path.parent.chmod(0o700)

        with self._connect() as connection:
            connection.executescript(
                """
                PRAGMA journal_mode = WAL;
                CREATE TABLE IF NOT EXISTS oauth_credentials_v2 (
                    email TEXT PRIMARY KEY NOT NULL,
                    access_token TEXT NOT NULL,
                    refresh_token TEXT,
                    token_uri TEXT NOT NULL,
                    client_id TEXT NOT NULL,
                    client_secret TEXT NOT NULL,
                    scopes_json TEXT NOT NULL,
                    expiry TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_time TEXT NOT NULL,
                    email TEXT,
                    action TEXT NOT NULL,
                    outcome TEXT NOT NULL,
                    details_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_audit_event_time
                    ON audit_events(event_time);
                """
            )
        with suppress(OSError):
            self.path.chmod(0o600)

    def save(
        self,
        *,
        email: str,
        token: str,
        refresh_token: str | None,
        token_uri: str,
        client_id: str,
        client_secret: str,
        scopes: list[str] | tuple[str, ...] | None,
        expiry: datetime | None,
    ) -> None:
        now = _to_iso(utc_now())
        encrypted_token = self.box.encrypt(token)
        encrypted_refresh = self.box.encrypt(refresh_token)
        encrypted_secret = self.box.encrypt(client_secret)
        scopes_json = json.dumps(sorted(set(scopes or [])))
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO oauth_credentials_v2 (
                    email, access_token, refresh_token, token_uri, client_id,
                    client_secret, scopes_json, expiry, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(email) DO UPDATE SET
                    access_token = excluded.access_token,
                    refresh_token = COALESCE(excluded.refresh_token, refresh_token),
                    token_uri = excluded.token_uri,
                    client_id = excluded.client_id,
                    client_secret = excluded.client_secret,
                    scopes_json = excluded.scopes_json,
                    expiry = excluded.expiry,
                    updated_at = excluded.updated_at
                """,
                (
                    email.lower(),
                    encrypted_token,
                    encrypted_refresh,
                    token_uri,
                    client_id,
                    encrypted_secret,
                    scopes_json,
                    _to_iso(expiry),
                    now,
                    now,
                ),
            )

    def get(self, email: str) -> StoredCredential | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM oauth_credentials_v2 WHERE email = ?", (email.lower(),)
            ).fetchone()
        if row is None:
            return None
        return StoredCredential(
            email=row["email"],
            token=self.box.decrypt(row["access_token"]) or "",
            refresh_token=self.box.decrypt(row["refresh_token"]),
            token_uri=row["token_uri"],
            client_id=row["client_id"],
            client_secret=self.box.decrypt(row["client_secret"]) or "",
            scopes=tuple(json.loads(row["scopes_json"])),
            expiry=_google_expiry_from_iso(row["expiry"]),
            created_at=_from_iso(row["created_at"]) or utc_now(),
            updated_at=_from_iso(row["updated_at"]) or utc_now(),
        )

    def list_accounts(self) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT email, scopes_json, expiry, created_at, updated_at
                FROM oauth_credentials_v2 ORDER BY email
                """
            ).fetchall()
        return [
            {
                "email": row["email"],
                "scopes": json.loads(row["scopes_json"]),
                "expiry": row["expiry"],
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
            }
            for row in rows
        ]

    def delete(self, email: str) -> bool:
        with self._connect() as connection:
            cursor = connection.execute(
                "DELETE FROM oauth_credentials_v2 WHERE email = ?", (email.lower(),)
            )
            return cursor.rowcount > 0

    def audit(
        self,
        action: str,
        outcome: str,
        *,
        email: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO audit_events (event_time, email, action, outcome, details_json)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    _to_iso(utc_now()),
                    email.lower() if email else None,
                    action,
                    outcome,
                    json.dumps(details or {}, sort_keys=True),
                ),
            )

    def list_audit_events(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT event_time, email, action, outcome, details_json
                FROM audit_events ORDER BY id DESC LIMIT ?
                """,
                (max(1, min(limit, 5000)),),
            ).fetchall()
        return [
            {
                "event_time": row["event_time"],
                "email": row["email"],
                "action": row["action"],
                "outcome": row["outcome"],
                "details": json.loads(row["details_json"]),
            }
            for row in rows
        ]

    def legacy_table_exists(self) -> bool:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'user_tokens'"
            ).fetchone()
        return row is not None

    def migrate_legacy(self, *, purge_plaintext: bool = False) -> int:
        """Copy the original seven-column token table into encrypted v2 storage."""
        if not self.legacy_table_exists():
            return 0
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT email, access_token, refresh_token, token_uri,
                       client_id, client_secret, scopes
                FROM user_tokens
                """
            ).fetchall()

        migrated = 0
        for row in rows:
            if not row["email"] or not row["access_token"]:
                continue
            self.save(
                email=row["email"],
                token=row["access_token"],
                refresh_token=row["refresh_token"],
                token_uri=row["token_uri"],
                client_id=row["client_id"],
                client_secret=row["client_secret"],
                scopes=json.loads(row["scopes"] or "[]"),
                expiry=None,
            )
            migrated += 1

        if purge_plaintext and migrated == len(rows):
            with self._connect() as connection:
                connection.execute("DROP TABLE user_tokens")
            # Rebuild the file and truncate the WAL so plaintext cells are not
            # left in unused SQLite pages after the legacy table is dropped.
            connection = sqlite3.connect(self.path, isolation_level=None)
            try:
                connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                connection.execute("VACUUM")
                connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            finally:
                connection.close()
        self.audit(
            "legacy_migration",
            "success",
            details={"migrated": migrated, "plaintext_purged": purge_plaintext},
        )
        return migrated
