from flask import Flask, request, session, render_template_string, redirect, url_for
from werkzeug.middleware.proxy_fix import ProxyFix  # NEW: Required for Azure App Service
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
import google.auth.transport.requests
import os
import argparse
import sqlite3
import json

# Parse CLI arguments
parser = argparse.ArgumentParser(description='Run the Flask app with Google OAuth.')
parser.add_argument('--client-id', required=True, help='Google Client ID')
parser.add_argument('--client-secret', required=True, help='Google Client Secret')
parser.add_argument('--redir-url', default='https://operator.example.com/callback', help='URL for redirect.')
args = parser.parse_args()

# Configuration
GOOGLE_CLIENT_ID = args.client_id
GOOGLE_CLIENT_SECRET = args.client_secret
REDIRECT_URI = args.redir_url

app = Flask(__name__)
app.secret_key = os.urandom(24)

# --- CRITICAL AZURE CONFIGURATION ---
# Tells Flask to trust the X-Forwarded-Proto headers from Azure's load balancer.
# This ensures that request.url and url_for() generate 'https://' links instead of 'http://'.
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
# ------------------------------------

# --- Database Setup ---
DB_FILE = 'oauth_tokens.db'

def init_db():
    """Initialize the SQLite database and create the tokens table."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_tokens (
            email TEXT PRIMARY KEY,
            access_token TEXT,
            refresh_token TEXT,
            token_uri TEXT,
            client_id TEXT,
            client_secret TEXT,
            scopes TEXT
        )
    ''')
    conn.commit()
    conn.close()

# Initialize the database when the script starts
init_db()
# ----------------------

# Define the OAuth2 flow scopes
SCOPES = [
    "https://mail.google.com/", 
    "https://www.googleapis.com/auth/gmail.settings.basic", 
    "https://www.googleapis.com/auth/gmail.settings.sharing", 
    "https://www.googleapis.com/auth/userinfo.email", 
    "https://www.googleapis.com/auth/userinfo.profile", 
    "openid"
]

def get_flow():
    """Helper to generate a new Flow instance per request."""
    return Flow.from_client_config(
        client_config={
            "web": {
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
            }
        },
        scopes=SCOPES,
        redirect_uri=REDIRECT_URI
    )

@app.route('/')
def index():
    flow = get_flow()
    authorization_url, state = flow.authorization_url(
        access_type='offline',
        prompt='consent' 
    )
    session['state'] = state
    
    return render_template_string("""
        <h2>Internal Gmail Management Tool</h2>
        <a href="{{ auth_url }}" style="padding:10px; background:#4285F4; color:white; text-decoration:none; border-radius:4px;">
            <b>Authorize Gmail Access</b>
        </a>
        <br><br>
        <a href="/view_db">View Database Contents</a>
    """, auth_url=authorization_url)

@app.route('/callback')
def callback():
    if not session.get('state') == request.args.get('state'):
        return "State does not match!", 400
    
    flow = get_flow()
    flow.fetch_token(authorization_response=request.url)
    credentials = flow.credentials

    # 1. Use the access token to figure out WHO just logged in
    oauth2_service = build('oauth2', 'v2', credentials=credentials)
    user_info = oauth2_service.userinfo().get().execute()
    user_email = user_info.get('email')

    # 2. Store their credentials in our SQLite database
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT OR REPLACE INTO user_tokens 
        (email, access_token, refresh_token, token_uri, client_id, client_secret, scopes) 
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (
        user_email,
        credentials.token,
        credentials.refresh_token,
        credentials.token_uri,
        credentials.client_id,
        credentials.client_secret,
        json.dumps(credentials.scopes)
    ))
    conn.commit()
    conn.close()

    return f"<h3>Success!</h3> Tokens for <b>{user_email}</b> saved to the database. <br><br> <a href='/manage/{user_email}'>Test Management Action</a>"

@app.route('/manage/<email>')
def manage_user(email):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM user_tokens WHERE email=?", (email,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return f"No tokens found for {email}."

    creds = Credentials(
        token=row[1],
        refresh_token=row[2],
        token_uri=row[3],
        client_id=row[4],
        client_secret=row[5],
        scopes=json.loads(row[6])
    )

    if creds.expired or not creds.valid:
        request_adapter = google.auth.transport.requests.Request()
        try:
            creds.refresh(request_adapter)
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            cursor.execute("UPDATE user_tokens SET access_token=? WHERE email=?", (creds.token, email))
            conn.commit()
            conn.close()
        except Exception as e:
            return f"Failed to refresh token for {email}. It may be revoked. Error: {e}"

    gmail_service = build('gmail', 'v1', credentials=creds)
    profile = gmail_service.users().getProfile(userId='me').execute()

    return f"Successfully accessed Gmail for <b>{email}</b>! <br> Total messages in their inbox: {profile.get('messagesTotal')}"

@app.route('/view_db')
def view_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT email, access_token, refresh_token FROM user_tokens")
    rows = cursor.fetchall()
    conn.close()
    
    html = "<h3>Database Contents</h3><table border='1' cellpadding='5'><tr><th>Email</th><th>Access Token</th><th>Refresh Token</th></tr>"
    for r in rows:
        access_trunc = f"{r[1][:15]}..." if r[1] else "None"
        refresh_trunc = f"{r[2][:15]}..." if r[2] else "None"
        html += f"<tr><td>{r[0]}</td><td>{access_trunc}</td><td>{refresh_trunc}</td></tr>"
    html += "</table><br><a href='/'>Go Back</a>"
    return html

if __name__ == '__main__':
    # AZURE DEPLOYMENT SETTINGS
    # Binds to 0.0.0.0 and dynamically grabs the port assigned by Azure App Service
    port = int(os.environ.get('PORT', 8000))
    app.run(host='0.0.0.0', port=port)