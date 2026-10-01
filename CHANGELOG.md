# Changelog

All notable changes to this project are documented here.

## 1.0.0 - 2026-10-01

### Added

- Installable `gmail-oauth-server` and `gmail-ops` commands
- Encrypted SQLite credential storage and legacy database migration
- Persisted token expiry and refreshed-token updates
- Operator audit events without token or message-body logging
- Optional local-only dry-run previews for mailbox and credential actions
- Grant revocation and cleanup commands
- Read-only and operator OAuth scope profiles
- Container deployment, health check, automated tests, linting, and CI
- Operator, detection, and security documentation

### Changed

- Replaced command-line OAuth secrets with environment and secret-manager configuration
- Replaced the unauthenticated token database and mailbox web routes with a minimal consent service
- Corrected mailbox-wide message-count terminology
- Removed delegate creation because Google requires a Workspace service account with domain-wide delegation
