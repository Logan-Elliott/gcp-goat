"""Command-line interface for authorized Gmail operations."""

from __future__ import annotations

import argparse
import os
import secrets
import stat
import sys
from pathlib import Path
from typing import Any

import requests

from .config import ConfigurationError, StoreSettings
from .crypto import SecretBox
from .gmail import AccountNotFoundError, GmailOperator, OperatorError
from .output import print_json, safe_text
from .store import CredentialStore

DRY_RUN_NOTICE = "Dry run requested. No mailbox or credential changes were made."


def _add_email(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--email", required=True, help="Authorized target mailbox")


def _add_dry_run(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview the action without changing Gmail or stored credentials",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="gmail-ops",
        description="Operate authorized Gmail OAuth grants during a security assessment.",
    )
    parser.add_argument("--db", type=Path, help="Override GMAIL_OAUTH_DB_PATH")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("keygen", help="Generate encryption and Flask session keys")
    subparsers.add_parser("doctor", help="Validate local configuration and storage")
    subparsers.add_parser("accounts", help="List stored account metadata (never tokens)")

    profile = subparsers.add_parser("profile", help="Verify access and show mailbox totals")
    _add_email(profile)

    listing = subparsers.add_parser("list", help="List recent inbox message metadata")
    _add_email(listing)
    listing.add_argument("--max", type=int, default=10, dest="max_results")
    listing.add_argument("--json", action="store_true", help="Emit JSON")

    read = subparsers.add_parser("read", help="Read a message without changing read state")
    _add_email(read)
    read.add_argument("message_id")
    read.add_argument("--json", action="store_true", help="Emit JSON")

    send = subparsers.add_parser("send", help="Send a plain-text message")
    _add_email(send)
    send.add_argument("--to", required=True)
    send.add_argument("--subject", required=True)
    body = send.add_mutually_exclusive_group(required=True)
    body.add_argument("--body", help="Plain-text message body")
    body.add_argument("--body-file", type=Path, help="Read body from a file, or '-' for stdin")
    _add_dry_run(send)

    trash = subparsers.add_parser("trash", help="Move a message to Trash")
    _add_email(trash)
    trash.add_argument("message_id")
    _add_dry_run(trash)

    filters = subparsers.add_parser("list-filters", help="List Gmail filters")
    _add_email(filters)
    filters.add_argument("--json", action="store_true", help="Emit JSON")

    create_filter = subparsers.add_parser("create-filter", help="Create a Gmail filter")
    _add_email(create_filter)
    create_filter.add_argument("--query", required=True, help="Gmail search expression")
    create_filter.add_argument("--add-labels", help="Comma-separated Gmail label IDs")
    create_filter.add_argument("--remove-labels", help="Comma-separated Gmail label IDs")
    _add_dry_run(create_filter)

    delete_filter = subparsers.add_parser("delete-filter", help="Delete a Gmail filter")
    _add_email(delete_filter)
    delete_filter.add_argument("filter_id")
    _add_dry_run(delete_filter)

    audit = subparsers.add_parser("audit", help="Export local operator audit events as JSON")
    audit.add_argument("--limit", type=int, default=100)

    revoke = subparsers.add_parser(
        "revoke", help="Revoke the Google grant and remove local credentials"
    )
    _add_email(revoke)
    _add_dry_run(revoke)

    remove = subparsers.add_parser(
        "remove-local", help="Remove local credentials without revoking the Google grant"
    )
    _add_email(remove)
    _add_dry_run(remove)

    migrate = subparsers.add_parser(
        "migrate-legacy", help="Encrypt the original user_tokens table and purge plaintext"
    )
    _add_dry_run(migrate)
    return parser


def _store(args: argparse.Namespace) -> CredentialStore:
    settings = StoreSettings.from_env()
    return CredentialStore(args.db or settings.db_path, settings.encryption_key)


def _labels(value: str | None) -> list[str]:
    return [item.strip() for item in (value or "").split(",") if item.strip()]


def _message_body(args: argparse.Namespace) -> str:
    if args.body is not None:
        return args.body
    if str(args.body_file) == "-":
        return sys.stdin.read()
    return args.body_file.read_text(encoding="utf-8")


def _dry_run_requested(args: argparse.Namespace, preview: dict[str, Any]) -> bool:
    if not args.dry_run:
        return False
    print_json({"dry_run": True, "preview": preview})
    print(DRY_RUN_NOTICE, file=sys.stderr)
    return True


def _run(args: argparse.Namespace) -> int:
    if args.command == "keygen":
        print(f"GMAIL_OAUTH_ENCRYPTION_KEY={SecretBox.generate_key()}")
        print(f"FLASK_SECRET_KEY={secrets.token_urlsafe(48)}")
        return 0

    store = _store(args)

    if args.command == "doctor":
        mode = stat.S_IMODE(store.path.stat().st_mode)
        result = {
            "database": str(store.path),
            "database_mode": oct(mode),
            "database_mode_secure": mode & 0o077 == 0,
            "legacy_plaintext_table": store.legacy_table_exists(),
            "google_client_configured": bool(os.environ.get("GOOGLE_CLIENT_ID")),
            "redirect_uri_configured": bool(os.environ.get("GOOGLE_REDIRECT_URI")),
            "status": "ok",
        }
        if not result["database_mode_secure"] or result["legacy_plaintext_table"]:
            result["status"] = "attention"
        print_json(result)
        return 0 if result["status"] == "ok" else 1

    if args.command == "accounts":
        print_json(store.list_accounts())
        return 0

    if args.command == "audit":
        print_json(store.list_audit_events(args.limit))
        return 0

    if args.command == "migrate-legacy":
        if not store.legacy_table_exists():
            print("No legacy user_tokens table was found.")
            return 0
        if _dry_run_requested(
            args,
            {"action": "encrypt legacy credentials and drop the plaintext table"},
        ):
            return 0
        count = store.migrate_legacy(purge_plaintext=True)
        print(f"Migrated {count} account(s); the plaintext table was removed.")
        return 0

    if args.command == "remove-local":
        if _dry_run_requested(args, {"action": "remove local credential", "email": args.email}):
            return 0
        deleted = store.delete(args.email)
        store.audit(
            "remove_local",
            "success" if deleted else "not_found",
            email=args.email,
        )
        print("Local credential removed." if deleted else "No local credential was found.")
        return 0 if deleted else 1

    if args.command == "revoke":
        record = store.get(args.email)
        if record is None:
            raise AccountNotFoundError(f"No stored OAuth grant for {args.email}")
        if _dry_run_requested(
            args,
            {"action": "revoke Google grant and remove local credential", "email": args.email},
        ):
            return 0
        token = record.refresh_token or record.token
        try:
            response = requests.post(
                "https://oauth2.googleapis.com/revoke",
                data={"token": token},
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=15,
            )
        except requests.RequestException as exc:
            store.audit(
                "revoke_grant",
                "failed",
                email=args.email,
                details={"reason": type(exc).__name__},
            )
            raise OperatorError("Google token revocation request failed") from exc
        if response.status_code != 200:
            store.audit(
                "revoke_grant",
                "failed",
                email=args.email,
                details={"http_status": response.status_code},
            )
            raise OperatorError(f"Google token revocation returned HTTP {response.status_code}")
        store.delete(args.email)
        store.audit("revoke_grant", "success", email=args.email)
        print("Google grant revoked and local credential removed.")
        return 0

    # Handle explicit dry runs before credentials are loaded or any Google API
    # client is initialized. This guarantees that previews are local-only.
    if args.command == "send" and _dry_run_requested(
        args,
        {"action": "send message", "from": args.email, "to": args.to},
    ):
        return 0
    if args.command == "trash" and _dry_run_requested(
        args,
        {"action": "move message to Trash", "message_id": args.message_id},
    ):
        return 0
    if args.command == "create-filter":
        add_labels = _labels(args.add_labels)
        remove_labels = _labels(args.remove_labels)
        if not add_labels and not remove_labels:
            raise OperatorError("Specify --add-labels and/or --remove-labels")
        if _dry_run_requested(
            args,
            {
                "action": "create filter",
                "query": args.query,
                "add_labels": add_labels,
                "remove_labels": remove_labels,
            },
        ):
            return 0
    if args.command == "delete-filter" and _dry_run_requested(
        args,
        {"action": "delete filter", "filter_id": args.filter_id},
    ):
        return 0

    operator = GmailOperator(store, args.email)

    if args.command == "profile":
        profile = operator.profile()
        print_json(
            {
                "email": profile.get("emailAddress"),
                "messages_total": profile.get("messagesTotal"),
                "threads_total": profile.get("threadsTotal"),
                "history_id": profile.get("historyId"),
            }
        )
    elif args.command == "list":
        messages = operator.list_messages(args.max_results)
        if args.json:
            print_json([message.__dict__ for message in messages])
        else:
            print(f"{'MESSAGE ID':<20}  {'FROM':<32}  SUBJECT")
            print("-" * 96)
            for message in messages:
                sender = safe_text(message.sender)[:32]
                subject = safe_text(message.subject)
                print(f"{message.message_id:<20}  {sender:<32}  {subject}")
    elif args.command == "read":
        message = operator.read_message(args.message_id)
        if args.json:
            print_json(message)
        else:
            print(f"From:    {safe_text(message['from'])}")
            print(f"To:      {safe_text(message['to'])}")
            print(f"Date:    {safe_text(message['date'])}")
            print(f"Subject: {safe_text(message['subject'])}")
            print("-" * 80)
            print(safe_text(message["body"], multiline=True))
    elif args.command == "send":
        message_id = operator.send_message(args.to, args.subject, _message_body(args))
        print(f"Message sent. ID: {message_id}")
    elif args.command == "trash":
        operator.trash_message(args.message_id)
        print(f"Message {args.message_id} moved to Trash.")
    elif args.command == "list-filters":
        filters = operator.list_filters()
        if args.json:
            print_json(filters)
        else:
            for item in filters:
                print(
                    f"{safe_text(item.get('id', ''))}: "
                    f"criteria={safe_text(item.get('criteria', {}))} "
                    f"action={safe_text(item.get('action', {}))}"
                )
    elif args.command == "create-filter":
        filter_id = operator.create_filter(
            args.query,
            add_labels=add_labels,
            remove_labels=remove_labels,
        )
        print(f"Filter created. ID: {filter_id}")
    elif args.command == "delete-filter":
        operator.delete_filter(args.filter_id)
        print(f"Filter {args.filter_id} deleted.")
    return 0


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        raise SystemExit(_run(args))
    except (ConfigurationError, AccountNotFoundError, OperatorError, OSError, ValueError) as exc:
        print(f"error: {safe_text(exc)}", file=sys.stderr)
        raise SystemExit(2) from exc


if __name__ == "__main__":
    main()
