from __future__ import annotations

from pathlib import Path

from gmail_oauth_operator.config import WebSettings
from gmail_oauth_operator.crypto import SecretBox
from gmail_oauth_operator.store import CredentialStore
from gmail_oauth_operator.web import create_app


def settings(tmp_path: Path) -> WebSettings:
    return WebSettings(
        db_path=tmp_path / "tokens.db",
        encryption_key=SecretBox.generate_key(),
        client_id="client-id.apps.googleusercontent.com",
        client_secret="client-secret",
        redirect_uri="https://operator.example.com/oauth/callback",
        flask_secret_key="test-session-secret",
        scopes=("https://www.googleapis.com/auth/gmail.readonly",),
        scope_profile="readonly",
        campaign_name="Authorized Assessment",
        trust_proxy=False,
        cookie_secure=True,
    )


def test_index_health_and_removed_secret_routes(tmp_path):
    config = settings(tmp_path)
    app = create_app(config, CredentialStore(config.db_path, config.encryption_key))
    app.config["TESTING"] = True
    client = app.test_client()

    index = client.get("/")
    assert index.status_code == 200
    assert b"Authorized Assessment" in index.data
    assert b"accounts.google.com" in index.data
    assert b"never asks for or receives your Google password" in index.data
    assert client.get("/healthz").json["status"] == "ok"
    assert client.get("/view_db").status_code == 404
    assert client.get("/manage/user@example.com").status_code == 404


def test_callback_rejects_missing_state_and_writes_audit_event(tmp_path):
    config = settings(tmp_path)
    store = CredentialStore(config.db_path, config.encryption_key)
    app = create_app(config, store)
    app.config["TESTING"] = True
    response = app.test_client().get("/oauth/callback?state=untrusted&code=fake")

    assert response.status_code == 400
    event = store.list_audit_events()[0]
    assert event["action"] == "oauth_callback"
    assert event["details"] == {"reason": "state_mismatch"}
