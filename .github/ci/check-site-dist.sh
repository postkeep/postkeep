#!/usr/bin/env bash
# Pages builds may contain only static files and directories.
set -euo pipefail

if [ "${1:-}" = --self-test ]; then
  work=$(mktemp -d)
  trap 'rm -rf "$work"' EXIT
  dist=$work/dist
  reject() {
    if "$0" "$1" 2> /dev/null; then echo "accepted $2" >&2; exit 1; fi
  }
  reject "$dist" 'missing artifact'
  mkdir -p "$dist/nested"
  touch "$dist/index.html" "$dist/nested/.static"
  "$0" "$dist"
  ln -s "$dist" "$work/link"
  reject "$work/link" 'symlink root'
  ln -s index.html "$dist/link"
  reject "$dist" 'symlink file'
  rm "$dist/link"
  ln -s missing "$dist/link"
  reject "$dist" 'dangling symlink'
  rm "$dist/link"
  mkfifo "$dist/pipe"
  reject "$dist" 'FIFO'
  rm "$dist/pipe"
  touch "$dist/_worker.js"
  reject "$dist" 'root worker file'
  rm "$dist/_worker.js"
  mkdir "$dist/nested/_worker.js"
  reject "$dist" 'nested worker directory'
  rmdir "$dist/nested/_worker.js"
  printf '#!/bin/sh\nexit 1\n' > "$work/find"
  chmod +x "$work/find"
  PATH="$work:$PATH" reject "$dist" 'failed tree walk'
  echo 'check-site-dist self-test ok'
  exit
fi

if [ "$#" -ne 1 ] || [[ "$1" == */ ]] || [ ! -d "$1" ] || [ -L "$1" ]; then
  echo 'Expected a plain site artifact directory (no trailing slash)' >&2
  exit 1
fi
bad=$(find -P "$1" \( -name _worker.js -o ! -type f ! -type d \) -print -quit)
if [ -n "$bad" ]; then
  printf 'Site artifact contains a worker or non-regular entry: %q\n' "$bad" >&2
  exit 1
fi
