"""Environment-driven configuration for GCP-GOAT components."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


class ConfigurationError(RuntimeError):
    """Raised when required runtime configuration is missing or invalid."""


SCOPE_PROFILES = {
    "readonly": ("https://www.googleapis.com/auth/gmail.readonly",),
    "operator": (
        "https://www.googleapis.com/auth/gmail.modify",
        "https://www.googleapis.com/auth/gmail.settings.basic",
    ),
}


def _required(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise ConfigurationError(f"Required environment variable {name} is not set")
    return value


def _as_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ConfigurationError(f"Expected a boolean value, got {value!r}")


@dataclass(frozen=True)
class StoreSettings:
    db_path: Path
    encryption_key: str

    @classmethod
    def from_env(cls) -> StoreSettings:
        return cls(
            db_path=Path(os.environ.get("GMAIL_OAUTH_DB_PATH", "./data/oauth_tokens.db")),
            encryption_key=_required("GMAIL_OAUTH_ENCRYPTION_KEY"),
        )


@dataclass(frozen=True)
class WebSettings(StoreSettings):
    client_id: str
    client_secret: str
    redirect_uri: str
    flask_secret_key: str
    scopes: tuple[str, ...]
    scope_profile: str
    campaign_name: str
    trust_proxy: bool
    cookie_secure: bool

    @classmethod
    def from_env(cls) -> WebSettings:
        store = StoreSettings.from_env()
        scope_profile = os.environ.get("GMAIL_OAUTH_SCOPE_PROFILE", "operator").strip().lower()
        if scope_profile not in SCOPE_PROFILES:
            choices = ", ".join(sorted(SCOPE_PROFILES))
            raise ConfigurationError(
                f"Unknown GMAIL_OAUTH_SCOPE_PROFILE {scope_profile!r}; choose {choices}"
            )

        redirect_uri = _required("GOOGLE_REDIRECT_URI")
        cookie_secure = _as_bool(
            os.environ.get("GMAIL_OAUTH_COOKIE_SECURE"),
            default=redirect_uri.lower().startswith("https://"),
        )
        return cls(
            db_path=store.db_path,
            encryption_key=store.encryption_key,
            client_id=_required("GOOGLE_CLIENT_ID"),
            client_secret=_required("GOOGLE_CLIENT_SECRET"),
            redirect_uri=redirect_uri,
            flask_secret_key=_required("FLASK_SECRET_KEY"),
            scopes=SCOPE_PROFILES[scope_profile],
            scope_profile=scope_profile,
            campaign_name=os.environ.get(
                "GMAIL_OAUTH_CAMPAIGN_NAME", "Authorized Gmail Assessment"
            ).strip(),
            trust_proxy=_as_bool(os.environ.get("GMAIL_OAUTH_TRUST_PROXY")),
            cookie_secure=cookie_secure,
        )
