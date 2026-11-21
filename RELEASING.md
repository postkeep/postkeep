# Releasing

Pushing a git tag publishes the Docker Hub image `postkeep/postkeep`
for `linux/amd64` and `linux/arm64`. Before the push, CI runs the amd64
binary and requires `postkeep --version` to print that tag's version.
A push to `main` that changes a build input publishes that same
multi-arch image as `latest`, `main` and the first 8 hex characters of the
commit (only `latest` and `main` when those 8 characters are all digits).
The image built from `main` reports the `Cargo.toml` version.
Older `sha-*` tags already on Docker Hub are left as they are.
CI also tags every merge to `main` with a pre-release version, below. A final
release is a `vX.Y.Z` tag that someone pushes on purpose.

## A pre-release tag on every merge

The `tag-prerelease` job in `.github/workflows/main.yml` runs on every
push to `main`, tags that commit `vX.Y.Z-dev.N`, and outputs the tag for
`publish-dev` in the same run. It makes no commit and changes no file:
`Cargo.toml` and `CHANGELOG.md` change only at a final release.
`.github/ci/tag-prerelease.sh` fetches the tags and derives the name from
the history behind the commit alone:

- `X.Y.Z` starts from the highest final tag behind the commit (`v0.4.0`
  at the move to GitHub), raised as release-plz raises it for the commits
  since: a title with `!` before the colon raises the minor while the
  major is 0 and the major after that; a `feat` title raises the minor
  from major 1 on; anything else raises the patch. The largest raise
  counts, so the version never falls within a series. A clone with no
  `vX.Y.Z` tag is refused.
- `N` counts all commits of the GitHub history, which starts at `v0.4.0`.
  That initial commit has no parent; the next merge is commit 2, so its
  tag is `v0.4.1-dev.2` (a fix) or `v0.5.0-dev.2` (breaking). `main` is
  linear through squash merges, so each merge gets its own `N`. It does
  not restart after a release. Older Docker Hub dev tags stay in place;
  the new version series sorts after them despite the restarted count.
- A commit that already carries a final tag gets no pre-release tag.
  Usually the release commit merges before its final tag is added, so
  it gets a dev tag first.

`publish-dev` publishes `postkeep/postkeep:X.Y.Z-dev.N` only, never
`latest`, `X.Y` or `X`; the image reports `postkeep X.Y.Z-dev.N`. A tag
pushed with the job's `GITHUB_TOKEN` starts no workflow, so publishing it
must happen in that same run, not in a second tag workflow. Neither a
push to `main` nor its dev tag re-runs checks: `main` accepts no direct
push, and required `title` and `checks` checks pass on an up-to-date pull
request before its squash merge. Forks need a maintainer's approval and
successful checks too (see `CONTRIBUTING.md`).

A hand-pushed final tag or other pre-release runs `release.yml`, which
calls `checks.yml` (lint, tests and site, without inheriting secrets)
before publishing. It never runs `tag-prerelease`, so tags cannot tag
again. A build from source at a dev tag still reports the workspace
version: a `version = "=0.4.0"` requirement keeps matching until the next
final release bumps it.

The tag job alone gets `contents: write`; checkout authenticates origin
with its job token. There is no deploy key or stored tag-push secret. The
script pushes only the tag ref and never forces it; the `v*` tag ruleset
also refuses updates and deletion. A retry finds the same name in place,
and a name already on another commit fails. A final tag cut on an older
commit can add a second name, never reuse one.
`.github/ci/tag-prerelease.sh --print <commit>` prints the derived name.
release-plz reads only exact `vX.Y.Z` tags as final releases.

GitHub may refuse a job-token tag push when `.github/workflows/` changed
on `main` after the tagged commit. This can affect a late retry or two
merges in quick succession; wait for each merge's `main.yml` run before
merging again. If refused, the next merge tags and publishes normally;
never move a tag to work around it.

## Cut a final release

First merge a `chore: release vX.Y.Z` pull request that writes the
version into `Cargo.toml` and `Cargo.lock` and the release's section into
`CHANGELOG.md`, from the titles merged since the last release. release-plz
prepares it (`release-plz.toml`); no workflow runs release-plz yet.
Without that bump the image would still report the tag, since its build
stamps the tag into the binary, but a local `cargo build` and the image
published from `main` report the workspace version in `Cargo.toml`.

Then, from that pull request's squash commit:

```sh
git tag -s -m "Release vX.Y.Z" vX.Y.Z
git push origin vX.Y.Z
```

The tag is signed and annotated, so a maintainer's Git must be set up to
sign tags. The tag must be strict semver with no build metadata.

- `v1.2.3` is a final release. The image is tagged `1.2.3`, `1.2`, `1`,
  and `latest`. `postkeep --version` prints `postkeep 1.2.3`.
- `v1.2.3-rc.1` is a pre-release. The image is tagged `1.2.3-rc.1` only.
  `latest`, `1.2`, and `1` stay where they are.
  `postkeep --version` prints `postkeep 1.2.3-rc.1`.
- Anything else, such as `v1.2`, `v1.2.3foo`, or `v1.2.3+build`, fails
  the publish job.

The Docker Hub token is an environment secret of `image-release`, which
allows `main` and `v*` tags only. `.github/ci/versions.sh` sets the public
`DOCKERHUB_USERNAME`; publish jobs receive `DOCKERHUB_TOKEN` there. Check jobs
have neither an environment nor this secret. The final tag must name a commit
with these GitHub workflows.

Check it after the release workflow is green:

```sh
docker run --rm postkeep/postkeep:X.Y.Z --version
```

## `main`

A push to `main` that changes a build input publishes
`postkeep/postkeep:latest`, `postkeep/postkeep:main` and
`postkeep/postkeep:<8 hex chars>`.
The third tag is the first 8 characters of the commit, with no `sha-`
prefix, for example `7620e4c6`. A commit whose first 8 characters are all
digits gets no third tag, only `latest` and `main`. Those tags are one
image, for `linux/amd64` and `linux/arm64`. Tags already published as
`sha-<hash>` are left as they are.

A build input is anything the image is compiled or published from. The
`image` section of `.github/paths` is the only list of them: add a new
input there. `main.yml`'s `changes` job reads it. CI changes are inputs to
every list, so changing a workflow, `.github/paths` or `.github/ci/`
publishes too, including a change to the pinned CI/image Rust version.
A docs-only change outside those inputs publishes no branch image and
`latest` stays where it was; every merge still gets its dev-tag image.

The hash tag cannot collide with a release tag. `X.Y.Z`, `X.Y` and a
pre-release all contain a dot, and the hash does not. A floating major
tag is a decimal integer, so an all-digit hash is not published as a tag;
that commit moves only `latest` and `main`.
The binary reports the `Cargo.toml` version, so `latest` from `main` is
not a release version. A final `vX.Y.Z` tag moves `latest` again, along
with `X.Y.Z`, `X.Y` and `X`. A pre-release never moves `latest`.

If the publish fails for a build input change on `main` and
the next merge changes none, `latest` stays on the previous image. Retry the
failed job rather than wait, but never a job of an older `main` workflow run
after a newer workflow run has published: that moves `latest` and `main` back.
A failed release workflow may be retried: always for a pre-release, which sets
only its own tag, and for a final release unless a newer final release has
been published since, because the retry would move `latest` back, and `X.Y`
and `X` when the newer release shares them.

A retry uses the old commit's files, not a later fix. Merge a fix to a
workflow or `.github/ci/` to publish it through that change's own run;
otherwise the next change to an `image` input publishes both changes.

No local Docker Hub login is required. CI logs in with `DOCKERHUB_USERNAME`
and `DOCKERHUB_TOKEN` only for the push, after loading an amd64 image and
checking `docker run --rm … --version`. It uses a local `docker-container`
buildx builder; its BuildKit image is digest-pinned in
`.github/ci/versions.sh`. Cross-compiling needs no emulation. All publish
jobs share the `publish-image` concurrency group with `queue: max`, including
final releases and dev tags. They queue by when they began waiting, not dispatch
time; execution order is not guaranteed. Newer merges do not cancel them.
A runner failure can be retried once by a maintainer; there is no
automatic retry. A hand dispatch of `main.yml` only deploys the site and
never tags or publishes an image.
