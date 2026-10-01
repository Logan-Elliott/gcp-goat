"""GCP-GOAT Flask application for interactive Google OAuth authorization."""

from __future__ import annotations

import argparse
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
    :root { color-scheme:light; --ink:#172033; --muted:#5d6b82; --blue:#2563eb;
      --blue-dark:#1d4ed8; --line:#dfe5ef; --soft:#f5f7fb; --success:#14866d;
      --page-start:#eef3fb; --page-middle:#f8fafc; --page-end:#edf4ff; --panel:#fff;
      --panel-border:rgba(204,214,230,.9); --panel-shadow:rgba(45,64,96,.16);
      --product-meta:#7a879a; --secure-border:#cfe8df; --secure-bg:#f0faf6;
      --row-line:#edf0f5; --icon-bg:#edf4ff; --detail:#738096; --trust-ink:#526178;
      --trust-bg:#f7f9fc; --quiet:#8995a7; --code:#174ea6; --footer-ink:#8a96a8;
      --footer-bg:#fbfcfe; }
    * { box-sizing: border-box; }
    body { margin:0; min-height:100vh; display:grid; place-items:center; padding:32px 20px;
      color:var(--ink); background:linear-gradient(145deg,var(--page-start) 0%,var(--page-middle) 52%,var(--page-end) 100%);
      font:16px/1.5 ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; }
    main { width:min(720px,100%); overflow:hidden; border:1px solid var(--panel-border);
      border-radius:20px; background:var(--panel); box-shadow:0 28px 80px var(--panel-shadow); }
    .product { display:flex; align-items:center; gap:13px; padding:22px 30px;
      border-bottom:1px solid var(--line); background:var(--panel); }
    .mark { display:grid; place-items:center; width:42px; height:42px; border-radius:12px;
      color:#fff; background:linear-gradient(145deg,#3271ed,#1f52be); box-shadow:0 7px 18px rgba(37,99,235,.24); }
    .mark svg { width:23px; height:23px; }
    .product-name { display:block; font-size:.94rem; font-weight:750; letter-spacing:-.01em; }
    .product-meta { display:block; margin-top:1px; color:var(--product-meta); font-size:.77rem; }
    .secure { margin-left:auto; padding:5px 9px; border:1px solid var(--secure-border); border-radius:999px;
      color:var(--success); background:var(--secure-bg); font-size:.72rem; font-weight:700; }
    .content { padding:36px 42px 30px; }
    .eyebrow { margin:0 0 8px; color:var(--blue); font-size:.74rem; font-weight:800;
      letter-spacing:.11em; text-transform:uppercase; }
    h1 { max-width:600px; margin:0 0 14px; font-size:clamp(2rem,6vw,3rem); line-height:1.08;
      letter-spacing:-.045em; }
    p { color:var(--muted); } strong { color:var(--ink); }
    .lead { max-width:590px; margin:0 0 26px; font-size:1.05rem; }
    .permissions { margin:0 0 22px; padding:0; border:1px solid var(--line); border-radius:14px; overflow:hidden; }
    .permissions h2 { margin:0; padding:14px 18px; border-bottom:1px solid var(--line);
      background:var(--soft); font-size:.8rem; letter-spacing:.04em; text-transform:uppercase; }
    .permissions ul { margin:0; padding:0; list-style:none; }
    .permissions li { display:flex; gap:13px; padding:14px 18px; border-bottom:1px solid var(--row-line); }
    .permissions li:last-child { border-bottom:0; }
    .permission-icon { flex:0 0 auto; display:grid; place-items:center; width:30px; height:30px;
      border-radius:9px; color:var(--blue); background:var(--icon-bg); font-size:.9rem; font-weight:800; }
    .permission-copy strong { display:block; font-size:.92rem; }
    .permission-copy span { display:block; margin-top:2px; color:var(--detail); font-size:.82rem; }
    .trust-note { display:flex; align-items:flex-start; gap:10px; margin:0 0 20px; padding:12px 14px;
      border-radius:11px; color:var(--trust-ink); background:var(--trust-bg); font-size:.83rem; }
    .trust-note svg { flex:0 0 auto; width:17px; height:17px; margin-top:2px; color:var(--success); }
    .button { display:flex; align-items:center; justify-content:center; gap:11px; width:100%; padding:13px 18px;
      border-radius:10px; color:#fff; background:var(--blue); box-shadow:0 8px 20px rgba(37,99,235,.2);
      font-weight:750; text-decoration:none; transition:background .15s ease,transform .15s ease; }
    .button:hover { background:var(--blue-dark); transform:translateY(-1px); }
    .g-mark { display:grid; place-items:center; width:22px; height:22px; border-radius:50%;
      color:#2563eb; background:#fff; font:800 .88rem/1 Arial,sans-serif; }
    .destination { margin:10px 0 0; color:var(--quiet); font-size:.75rem; text-align:center; }
    .boundary { margin:20px 0 12px; color:var(--quiet); font-size:.77rem; text-align:center; }
    code { color:var(--code); } footer { padding:17px 30px; border-top:1px solid var(--line);
      color:var(--footer-ink); background:var(--footer-bg); font-size:.75rem; text-align:center; }
    @media (prefers-color-scheme:dark) { :root { color-scheme:dark; --ink:#f0f4ff; --muted:#aab6cb;
      --blue:#7da5ff; --blue-dark:#6591f5; --line:#344158; --soft:#1b2537; --success:#5bd2b1;
      --page-start:#080e19; --page-middle:#0c1422; --page-end:#101b2c; --panel:#111a2a;
      --panel-border:rgba(101,120,153,.38); --panel-shadow:rgba(0,0,0,.48); --product-meta:#93a1b8;
      --secure-border:#235d52; --secure-bg:#102e2a; --row-line:#273348; --icon-bg:#1b3158;
      --detail:#95a4ba; --trust-ink:#aab7cc; --trust-bg:#172235; --quiet:#8f9db1;
      --code:#9bbcff; --footer-ink:#8997ac; --footer-bg:#0f1725; } }
    @media (max-width:560px) { body { padding:0; background:var(--panel); } main { min-height:100vh; border:0; border-radius:0;
      box-shadow:none; } .product { padding:18px 22px; } .content { padding:30px 22px 24px; }
      .secure { display:none; } }
  </style>
</head>
<body><main>
  <header class="product">
    <span class="mark" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M4 7.5 12 13l8-5.5"/><rect x="3" y="5" width="18" height="14" rx="3"/></svg></span>
    <span><span class="product-name">GCP-GOAT</span><span class="product-meta">Gmail OAuth Assessment Toolkit</span></span>
    <span class="secure">OAuth 2.0</span>
  </header>
  <section class="content">
    <p class="eyebrow">{{ eyebrow }}</p>
    <h1>{{ heading }}</h1>
    {{ content|safe }}
    {% if action_url %}<a class="button" href="{{ action_url }}"><span class="g-mark" aria-hidden="true">G</span><span>Continue to Google</span></a><p class="destination">You will continue securely to accounts.google.com</p>{% endif %}
  </section>
  <footer>GCP-GOAT v{{ version }} &nbsp;•&nbsp; Authorization is completed by Google</footer>
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
        campaign_name = escape(settings.campaign_name)
        if settings.scope_profile == "readonly":
            permissions = """
              <li><span class="permission-icon">1</span><span class="permission-copy"><strong>View Gmail messages and settings</strong><span>Inspect mailbox content without changing message state.</span></span></li>
              <li><span class="permission-icon">2</span><span class="permission-copy"><strong>Maintain approved access</strong><span>Use the connection until the OAuth grant is revoked.</span></span></li>
            """
        else:
            permissions = """
              <li><span class="permission-icon">1</span><span class="permission-copy"><strong>Read, send, and manage Gmail messages</strong><span>Work with messages covered by the approved assessment.</span></span></li>
              <li><span class="permission-icon">2</span><span class="permission-copy"><strong>View and manage Gmail filters</strong><span>Review or exercise filter behavior within the approved scope.</span></span></li>
              <li><span class="permission-icon">3</span><span class="permission-copy"><strong>Maintain approved access</strong><span>Use the connection until the OAuth grant is revoked.</span></span></li>
            """
        content = f"""
        <p class="lead">Connect an approved Google account to <strong>{campaign_name}</strong>.
        Google will show the exact permissions and ask for confirmation before creating a grant.</p>
        <section class="permissions" aria-label="Requested access"><h2>Requested access</h2><ul>{permissions}</ul></section>
        <div class="trust-note"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 3 5 6v5c0 4.7 2.8 8.5 7 10 4.2-1.5 7-5.3 7-10V6l-7-3Z"/><path d="m9 12 2 2 4-4"/></svg><span>The authorization decision happens on Google's domain. This service never asks for or receives your Google password.</span></div>
        <p class="boundary">Continue only with an account included in the approved test scope.</p>
        """
        return render_template_string(
            PAGE,
            title=settings.campaign_name,
            eyebrow="Google Workspace connection",
            heading="Connect your Gmail account",
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


def build_server_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="gcp-goat-server",
        description="Run the GCP-GOAT OAuth callback service for local testing.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "--host",
        default=os.environ.get("HOST", "0.0.0.0"),
        help="Listening host (default: HOST or 0.0.0.0)",
    )
    parser.add_argument(
        "--port",
        type=int,
        help="Listening port (default: PORT or 8000)",
    )
    return parser


def main(argv: list[str] | None = None) -> None:
    args = build_server_parser().parse_args(argv)
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))
    try:
        app = create_app()
    except ConfigurationError as exc:
        raise SystemExit(f"Configuration error: {exc}") from exc
    try:
        port = args.port if args.port is not None else int(os.environ.get("PORT", "8000"))
    except ValueError as exc:
        raise SystemExit("Configuration error: PORT must be an integer") from exc
    # The development entry point must accept platform ingress; production uses Gunicorn.
    app.run(host=args.host, port=port, debug=False)  # nosec B104
