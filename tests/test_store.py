from __future__ import annotations

import json
import sqlite3
import stat
from datetime import datetime, timedelta, timezone

from gcp_goat.crypto import SecretBox
from gcp_goat.store import CredentialStore


def credential_values(refresh_token: str | None = "refresh-token") -> dict:
    return {
        "email": "User@Example.com",
        "token": "access-token",
        "refresh_token": refresh_token,
        "token_uri": "https://oauth2.googleapis.com/token",
        "client_id": "client-id",
        "client_secret": "client-secret",
        "scopes": ["scope-b", "scope-a"],
        "expiry": datetime.now(timezone.utc) + timedelta(hours=1),
    }


def test_round_trip_encrypts_secrets_and_restricts_permissions(tmp_path):
    database = tmp_path / "nested" / "tokens.db"
    store = CredentialStore(database, SecretBox.generate_key())
    store.save(**credential_values())

    record = store.get("USER@example.com")
    assert record is not None
    assert record.email == "user@example.com"
    assert record.token == "access-token"
    assert record.refresh_token == "refresh-token"
    assert record.client_secret == "client-secret"
    assert record.scopes == ("scope-a", "scope-b")
    assert stat.S_IMODE(database.stat().st_mode) == 0o600

    raw = database.read_bytes()
    assert b"access-token" not in raw
    assert b"refresh-token" not in raw
    assert b"client-secret" not in raw


def test_upsert_preserves_refresh_token_when_google_omits_it(tmp_path):
    store = CredentialStore(tmp_path / "tokens.db", SecretBox.generate_key())
    store.save(**credential_values())
    updated = credential_values(refresh_token=None)
    updated["token"] = "new-access-token"
    store.save(**updated)

    record = store.get("user@example.com")
    assert record is not None
    assert record.token == "new-access-token"
    assert record.refresh_token == "refresh-token"


def test_audit_events_do_not_contain_credentials(tmp_path):
    database = tmp_path / "tokens.db"
    store = CredentialStore(database, SecretBox.generate_key())
    store.audit("list_messages", "success", email="user@example.com", details={"count": 5})

    event = store.list_audit_events()[0]
    assert event["action"] == "list_messages"
    assert event["details"] == {"count": 5}


def test_legacy_migration_encrypts_and_drops_plaintext_table(tmp_path):
    database = tmp_path / "tokens.db"
    connection = sqlite3.connect(database)
    connection.execute(
        """
        CREATE TABLE user_tokens (
            email TEXT PRIMARY KEY, access_token TEXT, refresh_token TEXT,
            token_uri TEXT, client_id TEXT, client_secret TEXT, scopes TEXT
        )
        """
    )
    connection.execute(
        "INSERT INTO user_tokens VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            "legacy@example.com",
            "legacy-access",
            "legacy-refresh",
            "https://oauth2.googleapis.com/token",
            "legacy-client",
            "legacy-secret",
            json.dumps(["scope"]),
        ),
    )
    connection.commit()
    connection.close()

    store = CredentialStore(database, SecretBox.generate_key())
    assert store.migrate_legacy(purge_plaintext=True) == 1
    assert not store.legacy_table_exists()
    assert store.get("legacy@example.com").refresh_token == "legacy-refresh"
    assert b"legacy-refresh" not in database.read_bytes()
