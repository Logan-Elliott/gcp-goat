"""Flask application for interactive Google OAuth authorization."""

from __future__ import annotations

import logging
import os
from typing import Any

from flask import Flask, redirect, render_template_string, request, session, url_for
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from markupsafe import escape
from werkzeug.middleware.proxy_fix import ProxyFix

from . import __version__
from .config import ConfigurationError, WebSettings
from .store import CredentialStore

LOGGER = logging.getLogger(__name__)

PAGE = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{ title }}</title>
  <style>
    :root { color-scheme: dark; --bg:#0b1020; --panel:#141c31; --text:#e8edf7;
      --muted:#9cabc5; --accent:#65d5c2; --border:#2a3652; --danger:#ffb86b; }
    * { box-sizing: border-box; }
    body { margin:0; min-height:100vh; display:grid; place-items:center; padding:24px;
      background:radial-gradient(circle at top,#192746 0,var(--bg) 48%); color:var(--text);
      font:16px/1.55 ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; }
    main { width:min(680px,100%); padding:36px; border:1px solid var(--border); border-radius:18px;
      background:rgba(20,28,49,.96); box-shadow:0 24px 80px rgba(0,0,0,.35); }
    .eyebrow { margin:0 0 10px; color:var(--accent); font-size:.8rem; font-weight:700;
      letter-spacing:.12em; text-transform:uppercase; }
    h1 { margin:.1em 0 .35em; font-size:clamp(1.8rem,5vw,2.7rem); line-height:1.1; }
    p, li { color:var(--muted); } strong { color:var(--text); }
    .notice { padding:14px 16px; border-left:3px solid var(--danger); background:#1b2338; }
    .button { display:inline-block; margin-top:14px; padding:12px 18px; border-radius:9px;
      background:var(--accent); color:#071513; font-weight:750; text-decoration:none; }
    code { color:#b9f6e9; } footer { margin-top:26px; color:#70809d; font-size:.82rem; }
  </style>
</head>
<body><main>
  <p class="eyebrow">{{ eyebrow }}</p>
  <h1>{{ heading }}</h1>
  {{ content|safe }}
  {% if action_url %}<a class="button" href="{{ action_url }}">Continue with Google</a>{% endif %}
  <footer>Gmail OAuth Operator v{{ version }}</footer>
</main></body></html>"""


def _flow(settings: WebSettings) -> Flow:
    return Flow.from_client_config(
        {
            "web": {
                "client_id": settings.client_id,
                "client_secret": settings.client_secret,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",  # nosec B105
            }
        },
        scopes=list(settings.scopes),
        redirect_uri=settings.redirect_uri,
    )


def create_app(
    settings: WebSettings | None = None,
    store: CredentialStore | None = None,
) -> Flask:
    settings = settings or WebSettings.from_env()
    store = store or CredentialStore(settings.db_path, settings.encryption_key)

    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=settings.flask_secret_key,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=settings.cookie_secure,
        PERMANENT_SESSION_LIFETIME=600,
    )
    if settings.trust_proxy:
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    @app.after_request
    def security_headers(response: Any) -> Any:
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; "
            "frame-ancestors 'none'; form-action 'self' https://accounts.google.com"
        )
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/")
    def index() -> str:
        profile_description = (
            "read-only Gmail access"
            if settings.scope_profile == "readonly"
            else "Gmail message and filter management access"
        )
        campaign_name = escape(settings.campaign_name)
        content = f"""
        <p>This authorization endpoint is part of <strong>{campaign_name}</strong>.</p>
        <div class="notice"><strong>Authorized use only.</strong> Continue only if this assessment
        and account are within the approved rules of engagement.</div>
        <p>The Google consent screen will request {profile_description}. Google displays the exact
        permissions before any grant is created.</p>
        """
        return render_template_string(
            PAGE,
            title=settings.campaign_name,
            eyebrow="OAuth assessment",
            heading=settings.campaign_name,
            content=content,
            action_url=url_for("oauth_start"),
            version=__version__,
        )

    @app.get("/oauth/start")
    def oauth_start() -> Any:
        flow = _flow(settings)
        authorization_url, state = flow.authorization_url(
            access_type="offline",
            prompt="consent",
            include_granted_scopes="true",
        )
        session.clear()
        session["oauth_state"] = state
        return redirect(authorization_url)

    @app.get("/oauth/callback")
    def oauth_callback() -> tuple[str, int] | str:
        if request.args.get("error"):
            store.audit(
                "oauth_callback",
                "denied",
                details={"error": request.args.get("error")},
            )
            return _result_page(
                "Authorization was not completed",
                "No credentials were stored. You may close this window.",
                "Authorization stopped",
            ), 400

        expected_state = session.pop("oauth_state", None)
        received_state = request.args.get("state")
        if not expected_state or expected_state != received_state:
            store.audit("oauth_callback", "failed", details={"reason": "state_mismatch"})
            return _result_page(
                "Authorization could not be verified",
                "The request state was missing or invalid. Start a new authorization flow.",
                "Verification failed",
            ), 400

        try:
            flow = _flow(settings)
            flow.fetch_token(authorization_response=request.url)
            credentials = flow.credentials
            gmail = build("gmail", "v1", credentials=credentials, cache_discovery=False)
            profile = gmail.users().getProfile(userId="me").execute()
            email = profile["emailAddress"].lower()
            granted_scopes = credentials.granted_scopes or credentials.scopes or settings.scopes
            store.save(
                email=email,
                token=credentials.token,
                refresh_token=credentials.refresh_token,
                token_uri=credentials.token_uri,
                client_id=credentials.client_id,
                client_secret=credentials.client_secret,
                scopes=list(granted_scopes),
                expiry=credentials.expiry,
            )
            store.audit(
                "oauth_grant",
                "success",
                email=email,
                details={"scope_profile": settings.scope_profile},
            )
        except Exception as exc:
            LOGGER.exception("OAuth callback failed")
            store.audit(
                "oauth_callback",
                "failed",
                details={"reason": type(exc).__name__},
            )
            return _result_page(
                "Authorization could not be completed",
                "The operator has been given a diagnostic event. No token is displayed here.",
                "Authorization error",
            ), 502

        return _result_page(
            "Authorization complete",
            f"The approved OAuth grant for <strong>{escape(email)}</strong> was stored securely. "
            "You may close this window.",
            "Grant recorded",
        )

    @app.get("/healthz")
    def health() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    def _result_page(heading: str, content: str, eyebrow: str) -> str:
        return render_template_string(
            PAGE,
            title=heading,
            eyebrow=eyebrow,
            heading=heading,
            content=f"<p>{content}</p>",
            action_url=None,
            version=__version__,
        )

    return app


def main() -> None:
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))
    try:
        app = create_app()
    except ConfigurationError as exc:
        raise SystemExit(f"Configuration error: {exc}") from exc
    port = int(os.environ.get("PORT", "8000"))
    # The development entry point must accept platform ingress; production uses Gunicorn.
    app.run(host="0.0.0.0", port=port, debug=False)  # nosec B104
