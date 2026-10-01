"""GCP-GOAT Gmail API operations with refresh persistence and local auditing."""

from __future__ import annotations

import base64
from collections.abc import Callable
from dataclasses import dataclass
from email.message import EmailMessage
from typing import Any

import google.auth.transport.requests
from google.auth.exceptions import RefreshError
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

from .store import CredentialStore


class OperatorError(RuntimeError):
    """Base error for actionable operator failures."""


class AccountNotFoundError(OperatorError):
    """Raised when no stored grant exists for a requested account."""


@dataclass(frozen=True)
class MessageSummary:
    message_id: str
    sender: str
    subject: str
    received_at: str


class GmailOperator:
    def __init__(
        self,
        store: CredentialStore,
        email: str,
        *,
        service: Any | None = None,
        service_builder: Callable[..., Any] = build,
    ):
        self.store = store
        self.email = email.lower()
        record = store.get(self.email)
        if record is None:
            raise AccountNotFoundError(f"No stored OAuth grant for {self.email}")

        self.credentials = Credentials(
            token=record.token,
            refresh_token=record.refresh_token,
            token_uri=record.token_uri,
            client_id=record.client_id,
            client_secret=record.client_secret,
            scopes=list(record.scopes),
            expiry=record.expiry,
        )
        self._ensure_fresh_credentials()
        self.service = service or service_builder(
            "gmail", "v1", credentials=self.credentials, cache_discovery=False
        )

    def _ensure_fresh_credentials(self) -> None:
        if self.credentials.expiry is None or not self.credentials.valid:
            if not self.credentials.refresh_token:
                raise OperatorError(
                    f"Stored grant for {self.email} has no usable refresh token; reauthorize it"
                )
            try:
                self.credentials.refresh(google.auth.transport.requests.Request())
            except RefreshError as exc:
                self.store.audit(
                    "token_refresh",
                    "failed",
                    email=self.email,
                    details={"reason": "refresh_rejected"},
                )
                raise OperatorError(
                    f"Google rejected the refresh token for {self.email}; reauthorize or clean up the grant"
                ) from exc
            self._persist_credentials()
            self.store.audit("token_refresh", "success", email=self.email)

    def _persist_credentials(self) -> None:
        self.store.save(
            email=self.email,
            token=self.credentials.token,
            refresh_token=self.credentials.refresh_token,
            token_uri=self.credentials.token_uri,
            client_id=self.credentials.client_id,
            client_secret=self.credentials.client_secret,
            scopes=list(self.credentials.scopes or []),
            expiry=self.credentials.expiry,
        )

    def _execute(
        self,
        request: Any,
        action: str,
        *,
        details: dict[str, Any] | None = None,
    ) -> Any:
        token_before = self.credentials.token
        expiry_before = self.credentials.expiry

        def persist_refresh() -> None:
            if self.credentials.token != token_before or self.credentials.expiry != expiry_before:
                self._persist_credentials()

        try:
            result = request.execute()
        except RefreshError as exc:
            persist_refresh()
            self.store.audit(
                action,
                "failed",
                email=self.email,
                details={**(details or {}), "reason": "refresh_rejected"},
            )
            raise OperatorError(
                f"Google rejected the refresh token for {self.email}; the grant may be revoked"
            ) from exc
        except HttpError as exc:
            persist_refresh()
            status = getattr(exc.resp, "status", "unknown")
            self.store.audit(
                action,
                "failed",
                email=self.email,
                details={**(details or {}), "http_status": status},
            )
            raise OperatorError(
                f"Gmail API returned HTTP {status} while performing {action}"
            ) from exc
        except Exception as exc:
            persist_refresh()
            self.store.audit(
                action,
                "failed",
                email=self.email,
                details={**(details or {}), "reason": type(exc).__name__},
            )
            raise OperatorError(f"Unexpected failure while performing {action}: {exc}") from exc

        persist_refresh()
        self.store.audit(action, "success", email=self.email, details=details)
        return result

    def profile(self) -> dict[str, Any]:
        return self._execute(
            self.service.users().getProfile(userId="me"),
            "profile",
        )

    def list_messages(self, max_results: int = 10) -> list[MessageSummary]:
        max_results = max(1, min(max_results, 100))
        response = self._execute(
            self.service.users()
            .messages()
            .list(userId="me", labelIds=["INBOX"], maxResults=max_results),
            "list_messages",
            details={"max_results": max_results},
        )
        summaries: list[MessageSummary] = []
        for item in response.get("messages", []):
            message = self._execute(
                self.service.users()
                .messages()
                .get(
                    userId="me",
                    id=item["id"],
                    format="metadata",
                    metadataHeaders=["Subject", "From", "Date"],
                ),
                "get_message_metadata",
                details={"message_id": item["id"]},
            )
            headers = _headers(message.get("payload", {}))
            summaries.append(
                MessageSummary(
                    message_id=item["id"],
                    sender=headers.get("from", "(Unknown sender)"),
                    subject=headers.get("subject", "(No subject)"),
                    received_at=headers.get("date", "(Unknown date)"),
                )
            )
        return summaries

    def read_message(self, message_id: str) -> dict[str, str]:
        message = self._execute(
            self.service.users().messages().get(userId="me", id=message_id, format="full"),
            "read_message",
            details={"message_id": message_id},
        )
        payload = message.get("payload", {})
        headers = _headers(payload)
        return {
            "message_id": message_id,
            "from": headers.get("from", "(Unknown sender)"),
            "to": headers.get("to", "(Unknown recipient)"),
            "date": headers.get("date", "(Unknown date)"),
            "subject": headers.get("subject", "(No subject)"),
            "body": _extract_text_body(payload) or message.get("snippet", ""),
        }

    def send_message(self, to: str, subject: str, body: str) -> str:
        message = EmailMessage()
        message.set_content(body)
        message["To"] = to
        message["From"] = self.email
        message["Subject"] = subject
        encoded = base64.urlsafe_b64encode(message.as_bytes()).decode("ascii")
        result = self._execute(
            self.service.users().messages().send(userId="me", body={"raw": encoded}),
            "send_message",
            details={"recipient": to},
        )
        return result["id"]

    def trash_message(self, message_id: str) -> None:
        self._execute(
            self.service.users().messages().trash(userId="me", id=message_id),
            "trash_message",
            details={"message_id": message_id},
        )

    def list_filters(self) -> list[dict[str, Any]]:
        result = self._execute(
            self.service.users().settings().filters().list(userId="me"),
            "list_filters",
        )
        return result.get("filter", [])

    def create_filter(
        self,
        query: str,
        *,
        add_labels: list[str] | None = None,
        remove_labels: list[str] | None = None,
    ) -> str:
        action: dict[str, list[str]] = {}
        if add_labels:
            action["addLabelIds"] = add_labels
        if remove_labels:
            action["removeLabelIds"] = remove_labels
        if not action:
            raise OperatorError("A filter requires at least one label action")
        result = self._execute(
            self.service.users()
            .settings()
            .filters()
            .create(userId="me", body={"criteria": {"query": query}, "action": action}),
            "create_filter",
            details={
                "query": query,
                "add_labels": add_labels or [],
                "remove_labels": remove_labels or [],
            },
        )
        return result["id"]

    def delete_filter(self, filter_id: str) -> None:
        self._execute(
            self.service.users().settings().filters().delete(userId="me", id=filter_id),
            "delete_filter",
            details={"filter_id": filter_id},
        )


def _headers(payload: dict[str, Any]) -> dict[str, str]:
    return {
        header.get("name", "").lower(): header.get("value", "")
        for header in payload.get("headers", [])
    }


def _extract_text_body(payload: dict[str, Any]) -> str:
    mime_type = payload.get("mimeType", "")
    data = payload.get("body", {}).get("data")
    if mime_type == "text/plain" and data:
        return _decode_base64url(data)
    for part in payload.get("parts", []):
        body = _extract_text_body(part)
        if body:
            return body
    return ""


def _decode_base64url(data: str) -> str:
    padded = data + "=" * ((4 - len(data) % 4) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8", errors="replace")
