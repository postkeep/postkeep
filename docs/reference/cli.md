# CLI

The `postkeep` binary has five subcommands.

## `postkeep serve`

Run the server.

Every option can be set with a `POSTKEEP_*` environment variable. A
command-line flag still wins over the variable.

`postkeep serve --help` lists every flag. The essentials are also in the
[configuration reference](../configuration.md).

## `postkeep generate-key`

Print a new random master key (32 random bytes, base64).

## `postkeep healthcheck`

Check that a local server answers `/healthz` (for container health checks).

| Flag | Environment | Default |
| --- | --- | --- |
| `--bind` | `POSTKEEP_BIND` | `0.0.0.0:8080` |

`0.0.0.0` is checked via `127.0.0.1`.

## `postkeep migrate`

Apply pending database migrations and exit (for release commands). It
prints the migrations it applied, or that the database is up to date, and
exits 0 in both cases.

| Flag | Environment | Default |
| --- | --- | --- |
| `--migrate-url` | `POSTKEEP_DATABASE_MIGRATE_URL` | (the database URL) |
| `--database-url` | `POSTKEEP_DATABASE_URL` | `sqlite://postkeep.db` |

## `postkeep storage-level`

Show the database's storage level, or raise it to the one this version reads.
`postkeep storage-level` prints the level, also for a database above this
version:

```text
storage level 1 in the database; this version reads up to level 1
```

`postkeep storage-level raise` then raises the database to the level this
version reads, if it is lower, and prints a second line:
`raised the storage level from 0 to 1`, or
`the storage level is already 1`. It never lowers the level, and it refuses a
database above this version, leaving it as it is. It does not check the
running instances: run it only once every instance runs this version or a
newer one ([storage level and rollbacks](../deployment.md#storage-level-and-rollbacks)).
It needs no master key, and creates and migrates nothing. It takes the
flags of `postkeep migrate`.
