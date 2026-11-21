# Endpoints

The server serves these paths:

- `/` (the landing page)
- `/mcp` (MCP)
- `/upload` (`PUT`: a file for [`upload_attachment`](tools.md#uploads), with its token in `Authorization`)
- `/healthz` (health)
- `/readyz` (readiness: `503` while the server drains on shutdown or its database is unavailable or behind)
- `/.well-known/*`
- `/register`, `/authorize`, `/token`, `/revoke` (OAuth)
- `/account` and `/account/*` (the account page)
- `/oauth/microsoft/*` and `/oauth/google/*` (provider sign-in)
- `/push/microsoft`, `/push/microsoft/lifecycle` and `/push/google` (new-mail notifications from Microsoft Graph and Google Pub/Sub)
- `/assets/*` (the styles, script, fonts and images of the server's pages)
- `/metrics` (Prometheus), only on `POSTKEEP_METRICS_BIND` when it is set

`postkeep healthcheck` probes `/healthz` for container health checks.

The redirect URIs to register for provider sign-in are in the
[configuration reference](../configuration.md#microsoft-and-google-sign-in).
