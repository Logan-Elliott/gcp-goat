# Security policy

## Intended use

GCP-GOAT is built for authorized security assessments. Operators are responsible for obtaining written authorization, defining target accounts and allowed actions in rules of engagement, protecting collected credentials, and removing access when testing ends.

Do not use this project to access accounts or data without the account owner's and system owner's authorization.

## Handling findings

Please do not open a public issue for a vulnerability that could expose OAuth credentials or assessment data. Send a private report to the repository owner with the affected version, reproduction steps, impact, and a suggested remediation when possible.

## Operational security

- Keep the encryption key outside the repository and separate from the database.
- Put the callback service behind HTTPS and restrict administrative access to the host.
- Use a dedicated Google Cloud project and OAuth client for each engagement.
- Prefer the `readonly` scope profile when mailbox changes are outside the rules of engagement.
- Run `gcp-goat revoke --email TARGET` during cleanup and retain the audit export with engagement evidence.
