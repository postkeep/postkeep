#!/usr/bin/env bash
# Emit one name=true|false per .github/paths section for the checked-out commit.
set -euo pipefail

self_test() {
  local script paths failed=0
  script=$(cd "$(dirname "$0")" && pwd)/$(basename "$0")
  paths=$(dirname "$script")/../paths
  dir=$(mktemp -d)
  trap 'rm -rf "$dir"' EXIT
  export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
  export GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@example.com GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@example.com
  export GITHUB_EVENT_NAME=pull_request GITHUB_REF_TYPE=branch
  git init -q -b main "$dir/repo"
  cd "$dir/repo"
  mkdir .github && cp "$paths" .github/paths
  git add . && git commit -qm 'ci: initial tree'
  check() { # NAME EXPECTED (in section order)
    local got
    got=$("$script" | cut -d= -f2 | paste -sd' ' -)
    if [ "$got" = "$2" ]; then echo "ok    $1"; else echo "FAIL  $1: $got (wanted $2)"; failed=1; fi
  }
  commit() { mkdir -p "$(dirname "$1")"; printf 'change\n' >>"$1"; git add .; git commit -qm 'test: change a path'; }
  check 'a commit with no parent runs every list' 'true true true true'
  commit CONTRIBUTING.md
  check 'unrelated docs' 'false false false false'
  commit README.md
  check 'README facts' 'false true false false'
  commit Cargo.toml
  check 'Cargo metadata feeds Rust, site, image and deploy' 'true true true true'
  commit crates/mail/src/lib.rs
  check 'Rust source' 'true false true false'
  commit crates/mail/src/presets.rs
  check 'provider facts' 'true true true false'
  commit crates/server/tests/pins/tools-list.json
  check 'tool pin' 'true true true true'
  commit docs/guide.md
  check 'docs feed site and deploy' 'false true false true'
  commit Dockerfile
  check 'image-only input' 'false false true false'
  for path in .github/workflows/checks.yml .github/paths .github/ci/changes.sh; do
    commit "$path"
    check 'CI inputs run every list' 'true true true true'
  done
  git mv Dockerfile 'old image file' && git commit -qm 'test: move a build input'
  check 'renamed build input' 'false false true false'
  git rm -q docs/guide.md && git commit -qm 'test: delete docs'
  check 'deleted input' 'false true false true'
  for GITHUB_EVENT_NAME in schedule workflow_dispatch workflow_call; do
    check "$GITHUB_EVENT_NAME forces every list" 'true true true true'
  done
  GITHUB_EVENT_NAME=push GITHUB_REF_TYPE=tag check 'release tags force every list' 'true true true true'
  [ "$failed" = 0 ]
}

if [ "${1:-}" = --self-test ]; then self_test; exit; fi
[ "$#" = 0 ] || { echo "usage: $0 [--self-test]" >&2; exit 2; }
all=false
case ${GITHUB_EVENT_NAME:-pull_request} in pull_request | push) ;; *) all=true ;; esac
if [ "${GITHUB_REF_TYPE:-}" = tag ] || ! git rev-parse --verify -q HEAD^1 >/dev/null; then all=true; fi
section=
paths=()
emit() {
  [ -n "$section" ] || return 0
  local changed='' value=$all
  if [ "$all" = false ]; then
    changed=$(git diff --name-only HEAD^1 HEAD -- "${paths[@]}")
    [ -z "$changed" ] || value=true
  fi
  printf '%s=%s\n' "$section" "$value"
}
while IFS= read -r line || [ -n "$line" ]; do
  case $line in
    '' | \#*) ;;
    \[*\]) emit; section=${line:1:-1}; paths=() ;;
    *) paths+=(":(glob)$line") ;;
  esac
done <.github/paths
emit
