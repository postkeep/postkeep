#!/bin/sh
# Checks that a pull request title is a Conventional Commit: GitHub uses the
# title as the squash commit on main, and release-plz builds the changelog
# and version bumps from those commits.
#
#   check-mr-title.sh "<title>"     check one title
#   check-mr-title.sh --self-test   check every line of mr-title-fixtures.txt
#
# The rule is ^(type)(\([a-z0-9-]+\))?!?: (?![A-Z]).+$ with the types below.
# POSIX regular expressions have no lookahead, so "(?![A-Z]).+" is written as
# "[^A-Z].*" in the C locale: one or more characters, the first of which is
# not an ASCII capital letter.
set -eu

pattern='^(feat|fix|docs|style|refactor|perf|test|build|ci|chore|revert)(\([a-z0-9-]+\))?!?: [^A-Z].*$'

valid() {
  case $1 in
    *"
"*) return 1 ;;
  esac
  printf '%s\n' "$1" | LC_ALL=C grep -Eq "$pattern"
}

if [ "${1:-}" = "--self-test" ]; then
  fixtures="$(dirname "$0")/mr-title-fixtures.txt"
  failed=0
  checked=0
  while IFS='|' read -r expected title; do
    case $expected in
      pass | fail) ;;
      *) continue ;;
    esac
    checked=$((checked + 1))
    if valid "$title"; then actual=pass; else actual=fail; fi
    if [ "$actual" = "$expected" ]; then
      echo "ok    $expected: $title"
    else
      echo "WRONG expected $expected, got $actual: $title"
      failed=1
    fi
  done <"$fixtures"
  echo "$checked fixture titles checked"
  exit "$failed"
fi

if [ "$#" -ne 1 ] || [ -z "$1" ]; then
  echo "usage: $0 \"<pull request title>\" | --self-test" >&2
  exit 2
fi

if valid "$1"; then
  echo "pull request title is a Conventional Commit: $1"
else
  cat >&2 <<EOF
The pull request title "$1" is not a Conventional Commit.

It becomes the squash commit on main, so it must look like
"type(scope): description" or "type: description", where type is one of
feat, fix, docs, style, refactor, perf, test, build, ci, chore or revert, the
optional scope uses lowercase letters, digits and hyphens, "!" before the
colon marks a breaking change, and the description does not start with a
capital letter. For example: "fix(store): handle an empty subject".

Edit the title to re-run this check.
EOF
  exit 1
fi
