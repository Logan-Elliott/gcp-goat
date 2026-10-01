# Detection and purple team guide

This project is intended to produce a controlled OAuth-to-Gmail activity chain that defenders can observe, investigate, contain, and eradicate.

## Expected activity chain

| Phase | Operator activity | Useful evidence |
|---|---|---|
| Authorization | User approves a Google OAuth client and Gmail scopes | OAuth log events, consent timestamp, client ID, scopes, user security notification |
| Persistence | Refresh token is retained and used after access-token expiry | Token and OAuth audit events, repeated client activity, source IP and user agent |
| Discovery | `profile`, `list`, and `read` query Gmail | Gmail API activity where available, egress to Google APIs, process and host telemetry |
| Action | Message send/trash or filter create/delete | Gmail log events, Sent/Trash contents, filter state, user-visible mailbox changes |
| Cleanup | Grant is revoked and encrypted credential removed | OAuth revocation event, failed subsequent refresh, local audit entry |

Telemetry availability varies by Google Workspace edition, licensing, retention configuration, and connector. Validate what your environment actually records before defining exercise success criteria.

## Detection hypotheses

1. Alert when a new or untrusted OAuth client receives high-risk Gmail scopes.
2. Correlate consent with API access from a new network, cloud-hosting provider, or user agent.
3. Detect Gmail filter changes that remove `INBOX`, add `TRASH`, or target identity and security notification senders.
4. Detect unusual send or trash activity performed through API access rather than the user's normal client pattern.
5. During incident response, identify and revoke the OAuth grant even when the user's password has already been reset.

## Investigation pivots

- OAuth client ID, project name, publisher state, and requested scopes
- User, consent timestamp, source IP, user agent, and device context
- Application access-control status: trusted, limited, or blocked
- Gmail message, label, and settings changes around the consent window
- Password-reset, one-time-code, and security-alert messages accessed during the window
- Host execution of `gmail-ops`, callback-service access logs, and outbound connections to Google endpoints
- The tool's local audit export, which intentionally records action metadata without tokens or message bodies

## Containment and validation

1. Revoke the application's OAuth grant in Google Workspace or the user's account security settings.
2. Block or limit the OAuth client in app-access controls when appropriate.
3. Review and remove unauthorized filters, forwarding settings, delegates, sent messages, and trashed messages.
4. Rotate affected identity credentials when mailbox access exposed recovery links or authentication material.
5. Run a benign CLI command after revocation and confirm that refresh fails.
6. Preserve relevant audit data and compare the defender timeline with the operator audit export.

Password rotation alone is not a universal OAuth containment step. The exercise should explicitly test whether responders enumerate and revoke application grants.
