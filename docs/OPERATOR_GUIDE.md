# GCP-GOAT operator guide

## Pre-engagement checklist

- Record the approved test accounts, testing window, permitted mailbox actions, collection limits, and cleanup owner in the rules of engagement.
- Use a dedicated Google Cloud project and OAuth client. Confirm the redirect URI and OAuth publishing state before the testing window.
- Select the smallest scope profile that supports the plan. Use `readonly` unless message or filter changes are expressly approved.
- Store `GMAIL_OAUTH_ENCRYPTION_KEY` in a secret manager separate from the SQLite database.
- Terminate TLS at the platform ingress and restrict host access to the operator team.
- Agree on expected user notifications and deconfliction contacts before sending the authorization URL.

## Suggested exercise sequence

1. Run `gcp-goat doctor` and resolve any database-permission or legacy-table warnings.
2. Start the callback service and verify `/healthz` through the deployed ingress.
3. Have the in-scope user open the authorization endpoint and review Google's consent screen.
4. Confirm capture with `gcp-goat accounts` and `gcp-goat profile --email TARGET`.
5. Begin with `list` and `read` to validate telemetry without modifying message labels. Use `list --query` with Gmail search syntax when the exercise calls for targeted discovery.
6. Run approved actions within the rules of engagement. Add `--dry-run` when a local preview is useful for command preparation.
7. Export the local audit trail and correlate timestamps with Google Workspace and network telemetry.
8. Revoke the grant, remove deployment secrets, and retain only the evidence allowed by the engagement data-handling plan.

## Operational notes

### Actions

`send`, `trash`, `create-filter`, `delete-filter`, `revoke`, `remove-local`, and `migrate-legacy` execute normally. Add `--dry-run` to print the planned action without changing Gmail or stored credentials. Dry runs are local-only and do not initialize a Gmail API client.

### Message retrieval

The CLI requests message metadata for inbox listings and `format=full` for a selected message. Neither operation changes Gmail labels. The body parser prints the first inline `text/plain` part and falls back to Gmail's snippet; it does not download attachments.

Mailbox-controlled strings are stripped of terminal control characters before display. JSON output should still be treated as untrusted assessment data when passed to other tools.

### Token lifecycle

The callback stores token expiry with the credential. The CLI refreshes an expired token before building the Gmail client and saves a token or expiry changed by the Google transport after API calls. A failed refresh is retained for evidence and reported to the operator; it is never silently deleted.

Refresh tokens can stop working after revocation, password changes affecting Gmail scopes, administrative policy changes, extended non-use, token-count limits, or an external app's Testing expiration. Build reauthorization and cleanup into the exercise plan.

### SQLite

SQLite is suitable for a small, single-host assessment service. The project enables WAL mode and a busy timeout, but deployments should use one Gunicorn worker and one persistent volume. Use a managed secret store and database if the engagement requires multi-host operation or stronger separation of duties.

## Cleanup

Export the audit record before revocation:

```bash
gcp-goat audit --limit 5000 > engagement-oauth-audit.json
gcp-goat revoke --email user@example.com --dry-run
gcp-goat revoke --email user@example.com
```

Verify the application is absent from the account's third-party access page and from the CLI's `accounts` output. Remove the callback service, OAuth client secret, encryption key, database, platform logs, and exported message data according to the rules of engagement and evidence-retention plan.
