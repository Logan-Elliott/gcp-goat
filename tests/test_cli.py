from __future__ import annotations

import re

import pytest
from cryptography.fernet import Fernet

from gmail_oauth_operator.cli import main


def configure_store(monkeypatch, tmp_path):
    monkeypatch.setenv("GMAIL_OAUTH_ENCRYPTION_KEY", Fernet.generate_key().decode("ascii"))
    monkeypatch.setenv("GMAIL_OAUTH_DB_PATH", str(tmp_path / "tokens.db"))


def invoke(argv):
    with pytest.raises(SystemExit) as exit_info:
        main(argv)
    return exit_info.value.code


def test_keygen_does_not_require_existing_configuration(capsys):
    assert invoke(["keygen"]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert lines[0].startswith("GMAIL_OAUTH_ENCRYPTION_KEY=")
    assert lines[1].startswith("FLASK_SECRET_KEY=")
    assert re.fullmatch(r"[A-Za-z0-9_-]{43}=", lines[0].split("=", 1)[1])


def test_accounts_and_doctor_on_new_encrypted_store(monkeypatch, tmp_path, capsys):
    configure_store(monkeypatch, tmp_path)
    assert invoke(["accounts"]) == 0
    assert capsys.readouterr().out.strip() == "[]"

    assert invoke(["doctor"]) == 0
    output = capsys.readouterr().out
    assert '"database_mode": "0o600"' in output
    assert '"status": "ok"' in output


def test_mutation_preview_is_local_only_and_needs_no_stored_account(monkeypatch, tmp_path, capsys):
    configure_store(monkeypatch, tmp_path)
    assert (
        invoke(
            [
                "send",
                "--email",
                "missing@example.com",
                "--to",
                "recipient@example.com",
                "--subject",
                "Preview",
                "--body",
                "No API request",
            ]
        )
        == 0
    )
    captured = capsys.readouterr()
    assert '"execute": false' in captured.out
    assert "Dry run only" in captured.err


def test_missing_account_returns_actionable_error(monkeypatch, tmp_path, capsys):
    configure_store(monkeypatch, tmp_path)
    assert invoke(["profile", "--email", "missing@example.com"]) == 2
    assert "No stored OAuth grant" in capsys.readouterr().err
