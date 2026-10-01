from __future__ import annotations

from datetime import datetime, timedelta, timezone

from gmail_oauth_operator.crypto import SecretBox
from gmail_oauth_operator.gmail import GmailOperator, _decode_base64url
from gmail_oauth_operator.store import CredentialStore


class FakeRequest:
    def __init__(self, value):
        self.value = value

    def execute(self):
        return self.value


class FakeMessages:
    def list(self, **kwargs):
        assert kwargs["labelIds"] == ["INBOX"]
        assert kwargs["maxResults"] == 100
        return FakeRequest({"messages": [{"id": "message-1"}]})

    def get(self, **kwargs):
        if kwargs["format"] == "metadata":
            return FakeRequest(
                {
                    "payload": {
                        "headers": [
                            {"name": "From", "value": "sender@example.com"},
                            {"name": "Subject", "value": "Assessment"},
                            {"name": "Date", "value": "Today"},
                        ]
                    }
                }
            )
        raise AssertionError("unexpected full-message call")

    def send(self, **kwargs):
        assert kwargs["body"]["raw"]
        return FakeRequest({"id": "sent-1"})

    def trash(self, **kwargs):
        return FakeRequest({})


class FakeFilters:
    def list(self, **kwargs):
        return FakeRequest({"filter": []})

    def create(self, **kwargs):
        return FakeRequest({"id": "filter-1"})

    def delete(self, **kwargs):
        return FakeRequest({})


class FakeSettings:
    def filters(self):
        return FakeFilters()


class FakeUsers:
    def messages(self):
        return FakeMessages()

    def settings(self):
        return FakeSettings()

    def getProfile(self, **kwargs):
        return FakeRequest({"emailAddress": "user@example.com", "messagesTotal": 42})


class FakeService:
    def users(self):
        return FakeUsers()


def make_operator(tmp_path):
    store = CredentialStore(tmp_path / "tokens.db", SecretBox.generate_key())
    store.save(
        email="user@example.com",
        token="access-token",
        refresh_token="refresh-token",
        token_uri="https://oauth2.googleapis.com/token",
        client_id="client-id",
        client_secret="client-secret",
        scopes=["scope"],
        expiry=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    return GmailOperator(store, "user@example.com", service=FakeService()), store


def test_list_messages_clamps_request_size_and_returns_metadata(tmp_path):
    operator, store = make_operator(tmp_path)
    messages = operator.list_messages(1000)

    assert messages[0].message_id == "message-1"
    assert messages[0].sender == "sender@example.com"
    assert [event["action"] for event in store.list_audit_events()] == [
        "get_message_metadata",
        "list_messages",
    ]


def test_send_records_metadata_but_not_message_body(tmp_path):
    operator, store = make_operator(tmp_path)
    assert operator.send_message("recipient@example.com", "subject", "sensitive body") == "sent-1"

    event = store.list_audit_events()[0]
    assert event["details"] == {"recipient": "recipient@example.com"}
    assert "sensitive body" not in str(event)


def test_base64url_decode_handles_missing_padding():
    assert _decode_base64url("aGVsbG8") == "hello"
