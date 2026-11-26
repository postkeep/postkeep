#!/bin/sh
# Build and push postkeep/postkeep on GitHub Actions with a local buildx builder.
# An optional tag argument publishes the dev tag made in this workflow; otherwise
# a tag push uses GITHUB_REF_NAME, and a main push publishes the branch tags.
#
# Default-branch pushes publish latest, main and the first 8 hex chars of
# the commit (no sha- prefix), as one multi-arch image. A commit whose 8
# hex chars are all digits gets no hash tag, only latest and main. The
# binary keeps the Cargo.toml version. Tags already published as sha-<hash>
# are not removed.
# A strict vX.Y.Z tag publishes X.Y.Z, X.Y, X and latest, and the binary
# reports that version.
# A strict pre-release (vX.Y.Z-prerelease) publishes only that version and
# does not move latest. Any other tag fails the job.
# Nothing is pushed if the amd64 smoke test fails.
set -eu
set +x

. .github/ci/versions.sh

sh tools/stamp-workspace-version.sh --self-test

image=postkeep/postkeep
source=$(sed -n 's/^repository = "\([^"]*\)"/\1/p' Cargo.toml)
[ -n "$source" ] || { echo "Cargo.toml has no repository URL" >&2; exit 1; }
licenses=MIT
smoke=postkeep-smoke:local

if [ -z "${DOCKERHUB_USERNAME:-}" ] || [ -z "${DOCKERHUB_TOKEN:-}" ]; then
  echo "DOCKERHUB_USERNAME and DOCKERHUB_TOKEN are required" >&2
  exit 1
fi
if [ -z "${GITHUB_SHA:-}" ]; then
  echo "GITHUB_SHA is required" >&2
  exit 1
fi

created=$(date -u +%Y-%m-%dT%H:%M:%SZ)
tags=""
version=""
# Empty on a branch build, so the image keeps the Cargo.toml version.
postkeep_version=""

tag=${1:-}
if [ -z "$tag" ] && [ "${GITHUB_REF_TYPE:-}" = tag ]; then tag=$GITHUB_REF_NAME; fi
if [ -n "$tag" ]; then
  plan=$(sh tools/stamp-workspace-version.sh --plan-tag "$tag") || exit 1
  version=$(printf '%s\n' "$plan" | sed -n '1p')
  tags=$(printf '%s\n' "$plan" | sed -n '2p')
  postkeep_version=$version
  case " $tags " in
    *" latest "*) echo "release tags: $tags" ;;
    *) echo "pre-release tag: $tags (latest is unchanged)" ;;
  esac
else
  # Always the first 8 hex characters, with no sha- prefix.
  short=$(printf '%.8s' "$GITHUB_SHA" | tr 'ABCDEF' 'abcdef')
  plan=$(sh tools/stamp-workspace-version.sh --plan-branch "$short") || exit 1
  tags=$(printf '%s\n' "$plan" | sed -n '2p')
  version=$short
  echo "branch tags: $tags"
fi

# The builder and the registry login live in a private docker config that
# is removed on exit, not in the job's default one.
DOCKER_CONFIG=$(mktemp -d)
export DOCKER_CONFIG
cleanup() {
  docker image rm "$smoke" >/dev/null 2>&1 || true
  docker buildx rm postkeep >/dev/null 2>&1 || true
  rm -rf "$DOCKER_CONFIG"
}
trap cleanup EXIT
docker buildx create --name postkeep --driver docker-container --driver-opt "image=$BUILDKIT_IMAGE" >/dev/null
docker buildx inspect postkeep >/dev/null

set -- \
  --builder postkeep \
  --provenance=false \
  --sbom=false \
  --build-arg "POSTKEEP_VERSION=${postkeep_version}" \
  --build-arg "IMAGE_SOURCE=${source}" \
  --build-arg "IMAGE_REVISION=${GITHUB_SHA}" \
  --build-arg "IMAGE_CREATED=${created}" \
  --build-arg "IMAGE_VERSION=${version}" \
  --build-arg "IMAGE_LICENSES=${licenses}" \
  --label "org.opencontainers.image.source=${source}" \
  --label "org.opencontainers.image.revision=${GITHUB_SHA}" \
  --label "org.opencontainers.image.created=${created}" \
  --label "org.opencontainers.image.version=${version}" \
  --label "org.opencontainers.image.licenses=${licenses}"

echo "smoke test: linux/amd64 --version and OCI label"
docker buildx build \
  "$@" \
  --platform linux/amd64 \
  --load -t "$smoke" \
  .

reported=$(docker run --rm "$smoke" --version)
echo "smoke: $reported"
if [ -n "$postkeep_version" ]; then
  expected="postkeep ${postkeep_version}"
  if [ "$reported" != "$expected" ]; then
    echo "smoke expected: ${expected}" >&2
    exit 1
  fi
else
  case "$reported" in
    postkeep\ *) ;;
    *)
      echo "unexpected version output" >&2
      exit 1
      ;;
  esac
fi

expected_label='"io.github.postkeep/postkeep"'
reported_label=$(docker image inspect --format '{{json (index .Config.Labels "io.modelcontextprotocol.server.name")}}' "$smoke")
if [ "$reported_label" != "$expected_label" ]; then
  echo "smoke: expected io.modelcontextprotocol.server.name=${expected_label}, got '${reported_label}'" >&2
  exit 1
fi

echo "logging in to the registry"
printf '%s' "$DOCKERHUB_TOKEN" | docker login --username "$DOCKERHUB_USERNAME" --password-stdin >/dev/null

set -- "$@" --platform linux/amd64,linux/arm64 --push
for tag in $tags; do
  set -- "$@" -t "${image}:${tag}"
done
echo "pushing ${image} for linux/amd64,linux/arm64"
docker buildx build "$@" .
echo "pushed ${image}: ${tags}"
