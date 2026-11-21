# Deploying postkeep

postkeep is one binary, and one container image for `linux/amd64` and
`linux/arm64`. The Docker Hub image is `postkeep/postkeep`; the
[Dockerfile](../Dockerfile) builds the same image from source. It needs no
particular platform, and everything is configured with environment
variables.

## What every deployment needs

1. **A public HTTPS URL.** MCP clients and your browser must reach the
   server, and OAuth requires HTTPS outside `localhost`. Terminate TLS in a
   reverse proxy (Caddy, nginx, Traefik) or use a host that provides it.
   Set `POSTKEEP_PUBLIC_URL` to the origin only, such as
   `https://mail.example.com`, with no path.
2. **A master key.** It wraps the data keys that encrypt stored app passwords,
   Microsoft and Google tokens, webhook secrets, the patterns of webhook
   filter rules, stored webhook events and sign-ins in progress
   (AES-256-GCM). It still decrypts directly what an earlier version stored,
   until this version moves that to a data key shortly after it starts.
   Generate one and keep a backup:

   ```sh
   docker run --rm postkeep/postkeep generate-key
   # or: postkeep generate-key, or: openssl rand -hex 32
   ```

   Pass it as `POSTKEEP_MASTER_KEY`, or put it in a file and set
   `POSTKEEP_MASTER_KEY_FILE` (works well with Docker, Kubernetes and
   systemd secrets). If the key is lost or changed, none of these can be
   decrypted: every user must connect again, webhook secrets and queued
   events are lost, and filter rules must be removed and written again (see
   [webhooks](webhooks.md#unreadable-rules)). To change the key without
   that, rotate it (see
   [configuration](configuration.md#rotating-the-master-key)).
3. **Persistent storage.** By default the server uses a SQLite file
   (`/data/postkeep.db` in the image), so mount a volume at `/data`.
   Upgrading from 0.2.x with the default SQLite path: 0.3.0 looks for
   `postkeep.db`, so rename your existing database file to `postkeep.db`
   (in the image, `/data/postkeep.db`) or point `POSTKEEP_DATABASE_URL` at
   it before starting. Account-page users sign in again once.
   If 0.3.0 has already started and created an empty `postkeep.db`,
   stop it and replace that file with your old one.
   For hosts without disks, or several replicas with webhooks off (see
   [New-mail webhooks](#new-mail-webhooks)), use PostgreSQL:
   `POSTKEEP_DATABASE_URL=postgres://user:password@host/db`. When the
   database is remote, add `?sslmode=verify-full`. That checks the
   server certificate and host name against the webpki roots compiled
   into the binary. `sslmode=require` encrypts without that check. If
   the provider uses a private CA, also add
   `sslrootcert=/path/ca.pem` (a PEM file the process can read). The
   schema is created and migrated automatically at startup.
   Each instance opens at most 10 database connections
   (`POSTKEEP_DATABASE_MAX_CONNECTIONS`). Behind a proxy or pooler that
   closes connections, recycle them sooner. For example, Fly Managed
   Postgres recommends a 300-second idle timeout and a 600-second lifetime
   ([Fly](https://fly.io/docs/mpg/client-configuration/)), so set
   `POSTKEEP_DATABASE_IDLE_TIMEOUT=300` and
   `POSTKEEP_DATABASE_MAX_LIFETIME=600`. These are examples, not defaults.
   Migrations run at start. Behind a transaction pooler, run them on a
   direct connection instead: set `POSTKEEP_DATABASE_MIGRATE_URL` to it, run
   `postkeep migrate` as a release command (it exits 0 when there is nothing
   to do), and set `POSTKEEP_DATABASE_MIGRATE_ON_START=false` so the server
   refuses to start on a schema it has not seen.

Recommended: set `POSTKEEP_ALLOWED_EMAILS` to the addresses that may
connect. Without it, anyone who can reach the server can connect any
mailbox it accepts: iCloud, Fastmail, Yahoo and Gmail (with an app password)
by default, Outlook or Gmail when those OAuth apps are set up, and any IMAP
server you configured.

The full list of variables is in [configuration.md](configuration.md)
and in `postkeep serve --help`.

## Docker Compose

[`deploy/compose`](../deploy/compose) contains a ready-to-use setup:

```sh
# App plus Caddy, which gets the HTTPS certificate for you
git clone https://github.com/postkeep/postkeep.git
cd postkeep/deploy/compose
cp -i .env.example .env && chmod 600 .env
# Generate MASTER_KEY once, and keep a copy somewhere safe
docker run --rm postkeep/postkeep generate-key
# edit .env: PUBLIC_URL, MASTER_KEY, ALLOWED_EMAILS, DOMAIN, CLIENT_IP_HEADER
docker compose --profile caddy up -d
```

The `caddy` profile adds [Caddy](https://caddyserver.com), which obtains a
certificate for `DOMAIN` automatically (ports 80 and 443 must be reachable,
and DNS must point at the machine). Without the profile, the app listens on
`127.0.0.1:8080` for your own reverse proxy.

Upgrade with
`git pull --autostash && docker compose pull && docker compose up -d`, with
`--profile caddy` on both `docker compose` commands if you use Caddy
(`--autostash` keeps your own edits to `compose.yaml`). Pin `IMAGE_TAG` to a
version (for example `0.3.3`) for predictable upgrades.

## Docker

Without Compose, run the image behind your own HTTPS proxy:

```sh
# 1. Generate a master key once, and keep a copy of master.key somewhere safe
test -s master.key || (umask 077 && docker run --rm postkeep/postkeep generate-key > master.key)

# 2. From the folder with master.key, start the server behind your HTTPS proxy
docker run -d --name postkeep -p 127.0.0.1:8080:8080 \
  -v postkeep:/data \
  -e POSTKEEP_PUBLIC_URL=https://mail.example.com \
  -e POSTKEEP_MASTER_KEY="$(cat master.key)" \
  -e POSTKEEP_ALLOWED_EMAILS=alice@example.com \
  postkeep/postkeep
```

The proxy needs the [notes below](#reverse-proxy-notes).

## Plain binary

Build it, or take it from the container image (`/usr/local/bin/postkeep`),
and run it behind your HTTPS proxy:

```sh
# Rust 1.94 or newer
cargo build --release
# Generate a master key once, and keep a copy of master.key somewhere safe
test -s master.key || (umask 077 && ./target/release/postkeep generate-key > master.key)

export POSTKEEP_BIND=127.0.0.1:8080
export POSTKEEP_PUBLIC_URL=https://mail.example.com
export POSTKEEP_MASTER_KEY_FILE=$PWD/master.key
export POSTKEEP_ALLOWED_EMAILS=alice@example.com
./target/release/postkeep serve
```

The database is `postkeep.db` in the working directory unless
`POSTKEEP_DATABASE_URL` names another.

[`deploy/systemd/postkeep.service`](../deploy/systemd/postkeep.service)
is a hardened systemd unit. It runs as a dynamic user, passes the master key
as a systemd credential and keeps the database in
`/var/lib/postkeep`.

To install it, from the repository after `cargo build --release`:

```sh
sudo install -m 0755 target/release/postkeep /usr/local/bin/
sudo install -d -m 0700 /etc/postkeep
sudo test -s /etc/postkeep/master.key || postkeep generate-key | sudo tee /etc/postkeep/master.key
sudo chmod 0600 /etc/postkeep/master.key
sudo test -e /etc/postkeep/env || printf 'POSTKEEP_PUBLIC_URL=https://mail.example.com\nPOSTKEEP_ALLOWED_EMAILS=alice@example.com\n' | sudo tee /etc/postkeep/env
sudo cp deploy/systemd/postkeep.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now postkeep
```

The third line prints the new key: keep a copy somewhere safe. Run again,
the block keeps the key and `/etc/postkeep/env`, where OAuth secrets may
have been added since.

## Changing a setting

- **Docker Compose:** add the line to `.env`, such as
  `POSTKEEP_MICROSOFT_CLIENT_ID=...`, and run `docker compose up -d`;
  `docker compose restart` keeps the old settings. Keep the lines `.env`
  already has under their short names, such as `MASTER_KEY`. If
  `compose.yaml` has no `env_file:` line, the clone is older than that:
  upgrade it first ([Docker Compose](#docker-compose)).
- **Docker:** keep the settings in a `.env` file only you can read, in the
  folder with `master.key` (create it with `(umask 077 && touch .env)`):
  one `NAME=value` per line, the value without quotes. Add
  `--env-file .env` to the `docker run` command. After a change, run
  `docker rm -f postkeep` and the command again.
- **systemd:** add the line with `sudoedit /etc/postkeep/env`, then run
  `sudo systemctl restart postkeep`.
- **Plain binary:** make such a file, but with each value in single quotes
  (`NAME='value'`), since the shell reads it: load it before
  `postkeep serve` with `set -a; . ./.env; set +a`, or use the systemd unit.
- **Fly.io:** for a secret, put its line in such a `.env`, without quotes,
  and run `fly secrets import -c deploy/fly/fly.toml < .env`; for the rest,
  `[env]` in `fly.toml`, then `fly deploy -c deploy/fly/fly.toml`. The upload
  bucket's three settings are secrets. Make a Tigris bucket with Tigris's CLI
  and its key in Tigris's console, not with `fly storage create`, which makes a
  key of its own and prints it, or sets `AWS_*` secrets postkeep doesn't read.

## Reverse proxy notes

- Forward the original `Host` header. The MCP endpoint rejects unknown
  hosts to prevent DNS rebinding. If your proxy rewrites `Host`, add the
  value it sends to `POSTKEEP_ALLOWED_HOSTS`.
- Pass the client IP and set `POSTKEEP_CLIENT_IP_HEADER`, so
  sign-in backoff and rate limits apply per client rather than to the proxy
  (see [configuration.md](configuration.md#abuse-limits)).
- Allow long requests. A tool call waits for the mail provider and can take
  tens of seconds (for example `proxy_read_timeout 120s;` in nginx).
- With [uploads](configuration.md#uploads) on, let a 25 MiB `PUT` through on
  `/upload`, pass its body on as it arrives rather than save it to disk first,
  and don't log the `Authorization` header. Caddy does all three by default, so
  the Compose file's Caddyfile needs nothing.
- nginx example (with `POSTKEEP_CLIENT_IP_HEADER=X-Real-IP`):

  ```nginx
  location / {
      proxy_pass http://127.0.0.1:8080;
      proxy_set_header Host $host;
      proxy_set_header X-Real-IP $remote_addr;
      proxy_http_version 1.1;
      proxy_read_timeout 120s;
      # Uploads: up to 25 MiB, passed on as they arrive.
      client_max_body_size 25m;
      proxy_request_buffering off;
  }
  ```

## Hosting platforms

Any platform that runs a container and gives it an HTTPS URL works. Set the
environment variables above and give it a volume or PostgreSQL.

| Platform type | Notes |
| ------------- | ----- |
| A VPS or home server | Docker Compose with the Caddy profile, or the systemd unit |
| Container PaaS with volumes (Fly.io, Railway, Render, Koyeb, ...) | Mount a volume at `/data` and run a single instance, or use PostgreSQL to run several with webhooks off. [`deploy/fly/fly.toml`](../deploy/fly/fly.toml) is a worked example for Fly.io |
| Serverless containers without disks (Cloud Run, Azure Container Apps, ...) | Use PostgreSQL; the server keeps no other state. With webhooks on, run a single instance |
| Kubernetes | A Deployment with the image, a Secret for the key (mounted as a file plus `POSTKEEP_MASTER_KEY_FILE`), a PVC for SQLite (one replica) or PostgreSQL (several, with webhooks off), and an Ingress with TLS. Point the liveness probe at `/healthz` and the readiness probe at `/readyz`, and set `POSTKEEP_SHUTDOWN_DRAIN` (for example `5`) so a pod leaves the Service before it stops accepting connections |

Scale-to-zero is fine. Tokens survive restarts because they live in the
database. The exception is new-mail webhooks, below.

### Fly.io

[`deploy/fly/fly.toml`](../deploy/fly/fly.toml) is a worked example: replace
the app name, organization, region and public URL with your own, and run
these once (later, `fly deploy` alone updates the app). SQLite on a Fly
volume serves one machine; for several, use PostgreSQL and
`POSTKEEP_WEBHOOKS=false`.

```sh
fly apps create my-postkeep --org personal
fly volumes create postkeep_data --size 1 --region sin -y -c deploy/fly/fly.toml
# Generate a master key once, and keep a copy of master.key somewhere safe
test -s master.key || (umask 077 && docker run --rm postkeep/postkeep generate-key > master.key)
fly secrets set POSTKEEP_MASTER_KEY="$(cat master.key)" -c deploy/fly/fly.toml
fly deploy --config deploy/fly/fly.toml
```

### Upgrading

If your Docker Compose `compose.yaml` has no `env_file:` line, the server
ignored every `POSTKEEP_` line in `.env`, `POSTKEEP_ALLOWED_EMAILS`
included, so with `ALLOWED_EMAILS` empty anyone who reached it could
connect a mailbox. Check `.env` first: each `POSTKEEP_` line in it takes
effect after the upgrade, and `ALLOWED_EMAILS` or `POSTKEEP_ALLOWED_EMAILS`
must list your addresses. Then upgrade the clone as
[Docker Compose](#docker-compose) shows.

Replace every instance of a version from before data keys, 0.3.2 or earlier
(the v0.3.2 release), together. An image from main (`latest`, `main` or a
commit hash) built from a commit before the v0.3.3 release commit reports
0.3.2 too: treat it as from before data keys unless its
`org.opencontainers.image.revision` label (`docker inspect`) is `eb43b31` or a
later commit of main (`git merge-base --is-ancestor eb43b31 <revision>`).
Every `0.3.3-dev.N` image already writes data keys.
Stop them all, then start the new version; do not roll them one at a
time, and do not go back to one after the new version has run. Such an
instance cannot open the passwords, webhook secrets, events, provider tokens
and sign-ins in progress that this version stores. For events that can mean
loss: it takes an event it cannot open for unreadable and skips it, and the
account's delivery position, kept in the shared database, then moves past it,
so no instance sends it. This version moves every value that an earlier version
stored to a data key shortly after its first start, so an instance from before
data keys can then read none of them.

### Storage level and rollbacks

The database records a storage level, a number for how new its stored formats
are. Every version from this one on refuses to start on a database recorded
above the level it reads, and so does `postkeep migrate`: "the database is at
storage level 2 and this version reads up to level 1; run the newer release
that raised it". A new database starts at level 1, the formats of this version
(`v1.` and `v2.` values). A version that brings a newer format reads it at once
but writes it only once the database is raised to its level, so it can run
beside older instances. `postkeep storage-level` prints the database's level and
the one this version reads, and `postkeep storage-level raise` raises the
database to the latter if it is lower; nothing lowers it. It takes the database
settings of `postkeep migrate` and needs the same rights. Raise the level only
once every instance runs a version that reads it: postkeep does not check the
running instances yet. Every version so far reads level 1, so there is nothing
to raise yet. After a raise, a rollback to a version that reads less stops at
start, before it can skip or overwrite anything. Run the newer release again,
or restore a backup from before it ran.

A version from before the storage level does not check it. When it applies
migrations at start (0.3.2 always does, later versions by default) it stops at
the first one it does not know, "migration N was previously applied but is
missing in the resolved migrations". With
`POSTKEEP_DATABASE_MIGRATE_ON_START=false` it starts. Do not go back to one.

Going back to a version from before uploads, or restoring a backup, delete
the uploads' rows before it serves (`DELETE FROM uploads;`): a restored copy
can't tell which uploads are still unused. The bucket's expiry rule removes
their pieces.

### New-mail webhooks

Webhook watchers hold an IMAP connection open (iCloud, Fastmail, Yahoo,
Gmail with an app password) or keep a Microsoft Graph subscription and a
Gmail watch renewed (Outlook, Gmail with Sign in with Google), and only
run while the server does. Outlook and Gmail also call
the server at `/push/microsoft`, `/push/microsoft/lifecycle` and
`/push/google`; those paths must be reachable from the internet over
HTTPS. Don't put them behind authentication at the proxy: postkeep checks
each request itself (see [webhooks](webhooks.md#how-new-mail-is-detected)). If anyone uses webhooks, keep one instance running and don't
let the platform stop it when no HTTP traffic arrives. On Fly.io, set in
`fly.toml`:

```toml
[http_service]
  auto_stop_machines = false
  min_machines_running = 1
```

Mail that arrives while the server is down is reported when it starts
again, within these limits. An IMAP backlog is reported oldest first as
several events of at most 50 messages each. Each Outlook event covers at
most 50 messages, and a larger burst is several events in a row, reported
without waiting for another notification. A Gmail history
catch-up can cover more than 50 messages in one event. If that history has
expired or paging is cut off, the resync lists at most one page of 50 Inbox
messages and then moves to the current history id, so older messages past
that page are not reported.
Run a single instance with webhooks enabled: several instances
would each deliver the same events. Set `POSTKEEP_WEBHOOKS=false` to
turn the feature off entirely.

An instance of an earlier version that has filter rules but no on/off switch
judges a rule turned off as if it were on, so turn rules off only once no
such instance runs, for example after an upgrade has finished.

## Health and operations

- `GET /healthz` returns `200 ok` when the database answers. The image's
  `HEALTHCHECK` runs `postkeep healthcheck`, which needs no shell or
  curl.
- `GET /readyz` returns `200 ready` when the database answers, has every
  migration this version needs, and the server is not shutting down.
  Otherwise it returns `503` with the reason: `draining`,
  `database unavailable` or `migrations pending`. An answer is reused for up
  to a second. Point load balancer and readiness checks at `/readyz` and
  liveness checks at `/healthz`, so a server that is shutting down or
  whose database is behind stops getting requests but is not restarted.
- On SIGINT or SIGTERM, `/readyz` answers `503 draining` at once. The
  server keeps serving for `POSTKEEP_SHUTDOWN_DRAIN` seconds (default `0`),
  or until a second signal, so load balancers can stop sending it requests.
  Then it stops accepting connections, gives open requests up to 10
  seconds, gives webhook watchers up to 5 seconds to log out, stops a pass
  that moves stored values to data keys if one is under way (at its next
  database or key service call; what it moved stays moved, and the next pass
  does the rest), and exits. Leave room for all of that in the platform's
  stop timeout, such as `terminationGracePeriodSeconds` on Kubernetes or
  `kill_timeout` on Fly.io.
- Logs go to stderr. Set `POSTKEEP_LOG_FORMAT=json` for log
  collectors. Passwords, tokens and message contents are kept out of the
  logs ([threat model](security/threat-model.md)).
- Set `POSTKEEP_METRICS_BIND` for Prometheus metrics
  ([configuration](configuration.md)). Anyone who reaches that address
  can read it. On Fly.io, bind `[::]:9091` and add a `[metrics]` section
  with `port = 9091` and `path = "/metrics"`: Fly.io scrapes it, and the
  internet cannot reach it while no `[[services]]` or `[http_service]`
  names that port.
- Expired authorization codes and tokens are purged every 10 minutes.
- Backups: back up the database (`/data` volume or PostgreSQL) and the
  master key, stored separately.
- To disconnect someone, see [Disconnect](clients.md#disconnect). To cut
  off everyone, stop the server and delete the database.

## Security checklist

- [ ] Served only over HTTPS; the app port is not exposed directly.
- [ ] `POSTKEEP_ALLOWED_EMAILS` lists the addresses that may connect.
- [ ] The master key is stored as a secret and backed up separately from the database.
- [ ] The image is pinned to a version and upgraded deliberately.
- [ ] If `POSTKEEP_METRICS_BIND` is set, only your monitoring can reach that address.
- [ ] Microsoft and Google client secrets are stored as secrets, and the Microsoft secret's expiry date is in your calendar.
- [ ] For Gmail push, `POSTKEEP_GOOGLE_PUBSUB_SERVICE_ACCOUNT` names a service account used only by the push subscription.
