"""GCP-GOAT encryption boundary for secrets stored in SQLite."""

from __future__ import annotations

from cryptography.fernet import Fernet, InvalidToken


class SecretDecryptionError(RuntimeError):
    """Raised when the configured key cannot decrypt stored data."""


class SecretBox:
    PREFIX = "fernet:v1:"

    def __init__(self, key: str):
        try:
            self._fernet = Fernet(key.encode("ascii"))
        except (TypeError, ValueError) as exc:
            raise ValueError(
                "GMAIL_OAUTH_ENCRYPTION_KEY must be a URL-safe Fernet key; "
                "generate one with `gcp-goat keygen`"
            ) from exc

    @staticmethod
    def generate_key() -> str:
        return Fernet.generate_key().decode("ascii")

    def encrypt(self, value: str | None) -> str | None:
        if value is None:
            return None
        token = self._fernet.encrypt(value.encode("utf-8")).decode("ascii")
        return f"{self.PREFIX}{token}"

    def decrypt(self, value: str | None) -> str | None:
        if value is None:
            return None
        if not value.startswith(self.PREFIX):
            raise SecretDecryptionError(
                "Credential data is not encrypted with the v1 format. "
                "Run the legacy migration command before using it."
            )
        token = value.removeprefix(self.PREFIX)
        try:
            return self._fernet.decrypt(token.encode("ascii")).decode("utf-8")
        except (InvalidToken, UnicodeError) as exc:
            raise SecretDecryptionError(
                "Unable to decrypt credential data with the configured key"
            ) from exc
