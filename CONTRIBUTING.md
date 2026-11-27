# Contributing

Thanks for your interest in postkeep! Issues and pull requests are
welcome at <https://github.com/postkeep/postkeep>. For larger changes,
please open an issue first to discuss the design.

## Ground rules

- Be kind and constructive.
- Don't include real credentials, app passwords or personal email content
  in issues, tests, logs or commits.
- Report security problems privately; see [SECURITY.md](SECURITY.md).

## Pull request workflow

Every change lands on `main` through a **squash-merged** pull request;
nothing is pushed to `main` directly. The repository allows squash merges
only, with the pull request title as the commit title and an empty body.
GitHub appends ` (#N)` to the title. The `main` ruleset requires the `title`
and `checks` checks and an up-to-date branch, with no bypass.

1. Create a branch, e.g. `feat/store-sqlite`.
2. Commit using [Conventional Commits](https://www.conventionalcommits.org):
   `feat:`, `fix:`, `docs:`, `ci:`, `chore:`, `refactor:`, `test:`, `build:`,
   `perf:`, `style:` or `revert:`, optionally with a scope such as
   `feat(auth):`. Mark breaking changes with `!` (`feat(mail)!: ...`).
3. Open a pull request whose **title** is a Conventional Commit, since it
   becomes the commit on `main`. The `title` check accepts
   `^(feat|fix|docs|style|refactor|perf|test|build|ci|chore|revert)(\([a-z0-9-]+\))?!?: (?![A-Z]).+$`:
   the subject must not start with an ASCII capital letter. Editing the
   title re-runs that check automatically.
4. Run the checks below locally, review the change, wait for GitHub Actions,
   then squash-merge. If `main` moved, update the branch and wait for its
   checks again: the tree that merges must be the tree that passed.

For GitHub's web commits, including squash merges, turn on **Settings >
Emails > Keep my email addresses private** and **Block command line pushes
that expose my email**. Set the GitHub no-reply address shown there with
`git config user.email` too: web privacy does not change local commits or
old history. A maintainer should check these settings before merging here.

Because `main` only contains Conventional Commits,
[release-plz](https://release-plz.dev) derives version bumps and the
changelog from it (see `release-plz.toml`). A final release is a `vX.Y.Z`
tag that someone pushes on purpose. Pushing that tag publishes the Docker Hub
image; `Cargo.toml` does not need a bump for the image binary to report the
tag, and it and the changelog change only at a final release. CI also tags
every merge to `main` with a pre-release, `vX.Y.Z-dev.N` (`N` is the commit
count of `main`), which changes no file and publishes only its own image tag.
A `!` before the colon of your title (a breaking change) raises that version's
minor, or its major from 1.0.0 on. See [RELEASING.md](RELEASING.md).

## Issues

Open new issues at <https://github.com/postkeep/postkeep/issues>.
Issues and merge requests from before the move to GitHub are in the GitLab
project's archive. A `#N` or `!N` written before the move means that GitLab
issue or merge request, and old references are not rewritten. New text that
cites one writes `gitlab#N` (or `gitlab!N`) or its full link, since a bare
`#N` now means a GitHub issue or pull request.

## Development setup

You need a stable Rust toolchain; `rust-toolchain.toml` selects it
automatically when you use [rustup](https://rustup.rs). The minimum supported
Rust version (MSRV) is the `rust-version` in the root `Cargo.toml`; CI does
not verify it.

Before opening a pull request, make sure these pass (CI runs them with
`RUSTFLAGS=-D warnings`, so any warning fails the build):

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
RUSTDOCFLAGS=-D warnings cargo doc --workspace --no-deps
cargo deny check            # https://github.com/EmbarkStudios/cargo-deny
```

### Continuous integration

The workflows in `.github/workflows/` run on GitHub-hosted runners. Every
pull request runs `title.yml` and `checks.yml`; no workflow-level path
filter can leave a required check waiting forever.

- `title`: the Conventional Commit title check and its self-test, including
  when a title is edited without a new commit;
- `lint`: the CI scripts' self-tests, `cargo fmt --check`, cargo-deny,
  clippy and rustdoc, with warnings denied;
- `test`: every test with `cargo nextest`, including the ignored GreenMail
  and PostgreSQL integration tests against `greenmail/standalone:2.1.14` and
  `postgres:17`, then the doc tests. It fails if any test is skipped and
  uploads `nextest.log` and the JUnit report for 14 days, also on failure;
- `site`: `bun run check` in `site/`, the static artifact guard, and a smoke test
  of the pinned deploy tool ([site/README.md](site/README.md));
- `checks`: always reports, failing if a needed job failed or was cancelled.
  A path-skipped job passes this gate.

`.github/paths` is the only list of the jobs' inputs. `changes.sh` compares
`HEAD^1` with `HEAD` on the pull request's merge commit: `lint` and `test`
use `rust`, and `site` uses `site`. Every list includes the workflows,
`.github/paths` and `.github/ci/`, so changing CI runs every check. An initial
commit with no parent runs every list too. The nightly schedule and a hand
`workflow_dispatch` run every check; `release.yml` calls the same checks on
hand-pushed `v*` tags other than `-dev.N`, without inheriting secrets.

A push to `main` runs `main.yml`, not the checks again: direct pushes are
refused, and the required checks already passed on the up-to-date pull
request. It tags every merge `vX.Y.Z-dev.N` and publishes that tag's image
in the same workflow, since a tag pushed with the job's token starts no
workflow. A change to `image` inputs also publishes `latest`, `main` and
the 8-character hash (no hash tag if all digits); a change to `site-deploy`
inputs deploys postkeep.dev. A hand dispatch of `main.yml` on `main` deploys
only the site. See [RELEASING.md](RELEASING.md) for image and tag rules.

All external contributors' fork pull requests need a maintainer's approval
to run. Before approving, review the exact head commit, including its
workflows, actions, build scripts, tests and new dependencies' build scripts.
An approval runs the pull request's code on a fresh hosted runner with a
read-only token, not a deploy credential. No check job names an environment
or holds a secret. Never change these workflows to use `pull_request_target`
or `workflow_run` to run a fork's code with secrets. A new head needs its own
review and successful checks before merging.

Rust jobs use the Rust version pinned in `Dockerfile`; contributors keep the
stable channel in `rust-toolchain.toml`. `.github/ci/versions.sh` pins the
other CI tools, including the SHA-256 of each Bun archive. The Bun version
comes from `site/package.json`.
All actions are pinned by commit. Rust caches are restored in pull requests
but saved only by scheduled or hand-started checks on `main`, never by a
pull request. A newer pull request commit cancels its older run; publishing
and site deployments queue instead of cancelling one another.
Runner failures are retried by a maintainer, once, not automatically.
CI does not verify the MSRV or build or run the fuzz targets.

### Pinned public surface

`crates/server/tests/pins.rs` compares what MCP clients and OAuth clients
see with files in `crates/server/tests/pins/`, byte for byte: the
`tools/list` and `skills/list` (`skills-list.json`) responses, the instructions,
the route table, both OAuth metadata documents and the `WWW-Authenticate`
header. A change fails with a line diff.
The last test starts `postkeep serve` itself with only the required settings
and compares it with the same files, so the binary cannot drift from the
router the other tests build. If the change is intended, rewrite the files
and say why in the pull request:

```sh
UPDATE_PINS=1 cargo test -p postkeep --test pins
```

That run skips the binary's test; the next run checks the binary against the
new files.

### Integration tests

`crates/mail/tests/greenmail.rs` runs against a local
[GreenMail](https://greenmail-mail-test.github.io/greenmail/) IMAP/SMTP
server. The tests are `#[ignore]`d, so a plain `cargo test` skips them. To run
them:

```sh
docker run --rm -p 3025:3025 -p 3143:3143 \
  -e GREENMAIL_OPTS="-Dgreenmail.setup.test.smtp -Dgreenmail.setup.test.imap \
    -Dgreenmail.hostname=0.0.0.0 -Dgreenmail.users.login=email \
    -Dgreenmail.users=alice:alicepass@example.com,bob:abcdabcdabcdabcd@example.com" \
  greenmail/standalone:2.1.14

cargo nextest run --run-ignored all     # or: cargo test -- --include-ignored
```

Without Docker, the GreenMail standalone JAR works the same way:
`java <the -D options above> -jar greenmail-standalone-2.1.14.jar`.
`GREENMAIL_HOST`, `GREENMAIL_IMAP_PORT` and `GREENMAIL_SMTP_PORT` override the
defaults (`127.0.0.1`, `3143`, `3025`).

The store's PostgreSQL test is ignored too and needs `TEST_POSTGRES_URL`:

```sh
docker run --rm -p 5432:5432 -e POSTGRES_PASSWORD=postgres postgres:17
TEST_POSTGRES_URL=postgres://postgres:postgres@127.0.0.1:5432/postgres \
  cargo nextest run --all-features --run-ignored all
```

Don't run tests or examples against a real mail account in CI.

### Live Gmail check

`crates/mail/tests/gmail_live.rs` checks the Gmail preset against a real
account with a Google app password: the server's capabilities and folders, the
Sent copy, a `Trash` delete and a `\Deleted` + `UID EXPUNGE` delete (and which
labels Gmail keeps), the answer to a wrong password, and with
`POSTKEEP_LIVE_GMAIL_IDLE=1` 26 minutes of `IDLE`. It is ignored and does
nothing unless both variables below name a file, so a CI run passes it without
a mail account. Put the address and the app password in two files only you can
read. A run takes about 3 minutes, about 30 with `IDLE`. Run it by hand, with
absolute paths, detached (in tmux, or with `nohup` and a log) so that a closed
terminal does not kill it, and never under the `ci` nextest profile
(`--profile ci`, `NEXTEST_PROFILE=ci`): that ends a test after two minutes, and
a run that is killed does not clean up.

```sh
POSTKEEP_LIVE_GMAIL_ADDRESS_FILE=<file> POSTKEEP_LIVE_GMAIL_PASSWORD_FILE=<file> \
  nohup cargo nextest run -p postkeep-mail --test gmail_live --run-ignored only --no-capture >live.log 2>&1 &
```

It sends two messages from the account to itself and appends a copy of one to
Sent by hand: three messages in all. Each has a random marker (printed first)
in the subject, and every search, move, flag and delete is limited to the UIDs
the marker finds, so no other message is touched. After the delete checks, and
again at the end or after a failure, it moves them to Trash with `MOVE` and
erases them there with `UID EXPUNGE`, only where the server offers `UIDPLUS`,
then prints what it could not remove; if that is not nothing, it stops before
the wrong-password login. A step that fails does not stop the others; the test
fails at the end. The address is printed as `<account>`, the password never.
The wrong-password login can bring a security notice from Google.
`POSTKEEP_LIVE_GMAIL_GREENMAIL=1` points the test at a local GreenMail on its
default ports (see above), with files that hold one of its mailboxes, to
rehearse it.

A run that was killed leaves its messages in the account. Run only the cleanup
for it, with the marker from the first line of its log (`pkl` and 32 lowercase
hex digits; anything else is refused before the account is touched) and the
same two files. It sends nothing and takes about a minute:

```sh
POSTKEEP_LIVE_GMAIL_CLEANUP_MARKER=<marker> \
  POSTKEEP_LIVE_GMAIL_ADDRESS_FILE=<file> POSTKEEP_LIVE_GMAIL_PASSWORD_FILE=<file> \
  cargo nextest run -p postkeep-mail --test gmail_live --run-ignored only --no-capture
```

### Fuzzing

`fuzz/` holds [cargo-fuzz](https://rust-fuzz.github.io/book/cargo-fuzz.html)
targets for code that handles untrusted input: IMAP search strings, folder
names, raw messages and reply headers, HTML bodies, redirect URIs, client IP
and Basic credential headers, stored ciphertexts, and webhook URLs, headers
and signatures. They call `fuzzing` modules that the crates only compile with
their `fuzzing` feature. It needs a nightly toolchain:

```sh
cargo install cargo-fuzz
cd fuzz
cargo +nightly fuzz list
cargo +nightly fuzz run -O --debug-assertions imap_search -- -max_total_time=300
```

CI does not build or run the fuzz targets; run them with the commands above
after changing code they cover. A crash is saved under `fuzz/artifacts/`;
add the fix and a regular unit test for the input.

## Changing a stored format

A change that makes postkeep store something an earlier version cannot read,
such as a value format `v3.`, takes a storage level, so that a rolling deploy
or a rollback never meets data an instance cannot read (see
[the deployment guide](docs/deployment.md#storage-level-and-rollbacks)):

1. In one release, raise `STORAGE_LEVEL_READS` (`crates/store/src/db.rs`) and
   teach every reader the new format. List it under the new level in the test
   `every_stored_format_has_a_storage_level` (`crates/store/src/crypto.rs`);
   a released level's formats never change.
2. Write the new format only where `Store::may_write_level` allows it, and the
   previous one everywhere else. Keep `STORAGE_LEVEL_WRITES` as it is and the
   previous writer for at least one release: the database is raised, with
   `postkeep storage-level raise`, only once every instance reads the level.

## Code style

- Keep modules small and focused, and document public items.
- Return errors (`thiserror`) instead of panicking: `unwrap`, `expect`,
  `panic!`, `todo!`, `dbg!` and `print!` are denied outside tests.
- No `unsafe` code.
- Don't log secrets or message contents.

## License

By contributing, you agree that your contributions are licensed under the
[MIT license](LICENSE), as described in the [README](README.md#license).
