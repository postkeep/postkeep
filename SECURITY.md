# Security policy

This project handles email credentials, so security reports are taken
seriously.

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Report vulnerabilities through GitHub's private vulnerability reporting: open
<https://github.com/postkeep/postkeep/security/advisories/new> (you need to
be signed in), fill in the report, and submit. It is visible only to you
and the maintainers until an advisory is published.

Please include:

- a description of the issue and its impact,
- steps to reproduce or a proof of concept,
- affected versions or commits, if known.

Leave real credentials and app passwords out of the report. You should
receive an acknowledgement within a few days. Once a fix is available, the
maintainers will publish an advisory and credit you if you wish.

## Design and audits

- [Threat model](docs/security/threat-model.md)
- [Security audit, October 2026](docs/security/audit-2026-10.md)
- [Security review: Outlook and Gmail support, October 2026](docs/security/providers-review-2026-10.md)

## Supported versions

The project is in early development. Security fixes are made on the
`main` branch and released in the next version; only the latest release is
supported.
