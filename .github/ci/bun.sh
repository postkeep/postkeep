#!/bin/sh
# Always verify the release archive before installing Bun in the site container.
set -eu
. .github/ci/versions.sh

case $(uname -s):$(uname -m) in
  Linux:x86_64) arch=x64; sha=$BUN_SHA256_X64 ;;
  Linux:aarch64) arch=aarch64; sha=$BUN_SHA256_AARCH64 ;;
  *) echo 'No pinned Bun archive for this platform' >&2; exit 1 ;;
esac
exec .github/ci/install-tool.sh \
  "https://github.com/oven-sh/bun/releases/download/bun-v$BUN_VERSION/bun-linux-$arch.zip" \
  "$sha" "bun-linux-$arch/bun"
