#!/usr/bin/env bash
# Installs one binary from a pinned release archive into /usr/local/bin after
# checking the archive's SHA-256, unless the image already has that version.
#
# Usage: install-tool.sh <https url of a .tar.gz or .zip> <sha256> <path inside the archive>
#                        [<version> [<version command>]]
#        install-tool.sh --self-test
#
# With a <version>, nothing is downloaded when the version command (default:
# "<binary> --version") exits 0 and the first line it prints starts with the
# binary's name followed by exactly <version>, like "cargo-deny 0.20.2" or
# "cargo-nextest 0.9.148 (cd1d6d546 2026-10-07)". Versions and checksums are
# pinned in .github/ci/versions.sh.
# Anything else (no such binary, another version, other output, no <version>
# argument) downloads the archive, checks its SHA-256 and installs the binary,
# and a failed download or checksum fails the job. A binary the script cannot
# identify is never used.
set -euo pipefail

dest=${INSTALL_TOOL_DEST:-/usr/local/bin} # only --self-test points this elsewhere

usage() {
  echo "usage: $0 <url> <sha256> <path inside the archive> [<version> [<version command>]]" >&2
  echo "       $0 --self-test" >&2
}

# Succeeds when <probe> exits 0 and its first output line is "<name> <version>",
# optionally followed by more words.
reports_version() {
  local name=$1 version=$2 probe=$3 out line
  local -a words
  # shellcheck disable=SC2086 # the version command is a word list by design
  out=$($probe 2>/dev/null) || return 1
  line=${out%%$'\n'*}
  read -r -a words <<<"$line" || true
  [ "${words[0]:-}" = "$name" ] && [ "${words[1]:-}" = "$version" ]
}

# shellcheck disable=SC2329 # predicates are passed to check
self_test() {
  local self bin dir log archive good_sum bad_sum failures=0
  local rc out fake_out fake_exit curl_exit url member
  self=$(cd "$(dirname "$0")" && pwd)/$(basename "$0")
  work=$(mktemp -d) # global: the EXIT trap runs after this function has returned
  trap 'rm -rf "$work"' EXIT
  bin=$work/bin
  dir=$work/dest
  log=$work/curl.log
  archive=$work/good.tar.gz
  url=https://example.invalid/tool-1.2.3.tar.gz
  member=tool-1.2.3/faketool
  mkdir -p "$bin" "$dir" "$work/src/tool-1.2.3"

  # A private PATH holding only what the script needs, so a real cargo-deny or
  # curl on this machine cannot leak into a case.
  local t p
  for t in basename cat chmod cp gzip head install mkdir mktemp rm sha256sum tar unzip; do
    p=$(command -v "$t") && ln -s "$p" "$bin/$t"
  done

  # The fake curl records its call and "downloads" the prepared archive. The
  # archive is a real tarball, so a missing checksum test cannot hide behind a
  # failing tar.
  cat >"$bin/curl" <<'EOF'
#!/bin/sh
echo "$*" >>"$FAKE_LOG"
[ "${FAKE_CURL_EXIT:-0}" = 0 ] || exit "$FAKE_CURL_EXIT"
out=
while [ "$#" -gt 0 ]; do
  [ "$1" = -o ] && out=$2
  shift
done
cp "$FAKE_ARCHIVE" "$out"
EOF
  chmod +x "$bin/curl"
  printf '#!/bin/sh\necho the downloaded faketool\n' >"$work/src/$member"
  chmod +x "$work/src/$member"
  tar -czf "$archive" -C "$work/src" "$member"
  good_sum=$(sha256sum "$archive" | cut -d' ' -f1)
  bad_sum=0000000000000000000000000000000000000000000000000000000000000000

  tool() { # tool on|off: put the fake "faketool" on the private PATH, or take it away
    if [ "$1" = on ]; then
      cat >"$bin/faketool" <<'EOF'
#!/bin/sh
if [ "$1" = --long-version ]; then
  printf 'faketool 1.2.3\n'
  exit 0
fi
printf '%b' "$FAKE_OUT"
exit "${FAKE_EXIT:-0}"
EOF
      chmod +x "$bin/faketool"
    else
      rm -f "$bin/faketool"
    fi
  }
  run() { # run the script under the private PATH; sets rc and out
    : >"$log"
    rm -f "$dir"/*
    out=$(env -i PATH="$bin" HOME="$work" FAKE_LOG="$log" FAKE_ARCHIVE="$archive" \
      FAKE_CURL_EXIT="$curl_exit" FAKE_OUT="$fake_out" FAKE_EXIT="$fake_exit" \
      INSTALL_TOOL_DEST="$dir" "$BASH" "$self" "$@" 2>&1) && rc=0 || rc=$?
  }
  check() { # check <what> <command...>
    local what=$1
    shift
    if "$@"; then echo "ok    $what"; else echo "FAIL  $what"; failures=$((failures + 1)); fi
  }
  skipped() { [ "$rc" = 0 ] && [ ! -s "$log" ] && [ ! -e "$dir/faketool" ] && [[ "$out" == *"faketool 1.2.3 found on PATH"* ]]; }
  downloaded() { [ "$rc" = 0 ] && [ -s "$log" ] && [ -x "$dir/faketool" ]; }
  refused() { [ "$rc" != 0 ] && [ ! -e "$dir/faketool" ]; }

  curl_exit=0
  fake_exit=0

  # The skip: the tool reports exactly the pinned version.
  tool on
  fake_out='faketool 1.2.3\n'
  run "$url" "$good_sum" "$member" 1.2.3 "faketool --version"
  check "the exact version is found on PATH, nothing downloaded" skipped
  fake_out='faketool 1.2.3 (cd1d6d546 2026-10-07)\nrelease: 1.2.3\nhost: x86_64\n'
  run "$url" "$good_sum" "$member" 1.2.3 "faketool --version"
  check "extra words on the first line and more lines after it are fine" skipped
  fake_out='faketool 9.9.9\n'
  run "$url" "$good_sum" "$member" 1.2.3 "faketool --long-version"
  check "the version command argument is the command that runs" skipped

  # Everything else takes the download path and installs.
  for fake_out in 'faketool 1.2.30\n' 'faketool 1.2.3-rc.1\n' 'faketool 1.2.3+build\n' 'faketool 1.2\n' \
    'faketool 11.2.3\n' 'other 1.2.3\n' 'Faketool 1.2.3\n' '' '\n' 'warning: x\nfaketool 1.2.3\n' \
    '1.2.3 faketool\n' 'faketool\n'; do
    run "$url" "$good_sum" "$member" 1.2.3 "faketool --version"
    check "downloads for the output '$fake_out'" downloaded
  done
  fake_out='faketool 1.2.3\n'
  fake_exit=1
  run "$url" "$good_sum" "$member" 1.2.3 "faketool --version"
  check "a version command that exits 1 downloads even if it printed the version" downloaded
  fake_exit=0
  tool off
  run "$url" "$good_sum" "$member" 1.2.3 "faketool --version"
  check "no such binary downloads" downloaded
  tool on
  fake_out='faketool 9.9.9\n'
  run "$url" "$good_sum" "$member" 1.2.3
  check "without a command, '<binary> --version' runs and a mismatch downloads" downloaded
  fake_out='faketool 1.2.3\n'
  run "$url" "$good_sum" "$member"
  check "three arguments download even when the right version is on PATH" downloaded

  # The download path fails closed.
  tool off
  run "$url" "$bad_sum" "$member" 1.2.3 "faketool --version"
  check "a wrong checksum fails and installs nothing" refused
  run "$url" "$bad_sum" "$member"
  check "a wrong checksum fails without a version argument too" refused
  curl_exit=22
  run "$url" "$good_sum" "$member" 1.2.3 "faketool --version"
  check "a failed download fails and installs nothing" refused
  curl_exit=0

  # Arguments.
  run "$url" "$good_sum"
  check "too few arguments: usage error" test "$rc" = 2
  run "$url" "$good_sum" "$member" 1.2.3 "faketool --version" extra
  check "too many arguments: usage error" test "$rc" = 2

  archive=$work/good.zip
  url=https://example.invalid/tool-1.2.3.zip
  (cd "$work/src" && zip -q "$archive" "$member")
  good_sum=$(sha256sum "$archive" | cut -d' ' -f1)
  run "$url" "$good_sum" "$member"
  check 'a verified ZIP installs the requested binary' downloaded
  run "$url" "$bad_sum" "$member"
  check 'a wrong ZIP checksum fails and installs nothing' refused

  if [ "$failures" -ne 0 ]; then
    echo "install-tool self-test: $failures check(s) failed" >&2
    exit 1
  fi
  echo "install-tool self-test ok"
}

if [ "${1:-}" = "--self-test" ]; then
  self_test
  exit
fi

if [ "$#" -lt 3 ] || [ "$#" -gt 5 ]; then
  usage
  exit 2
fi
url=$1
sum=$2
member=$3
version=${4:-}
name=$(basename "$member")

if [ -n "$version" ]; then
  if reports_version "$name" "$version" "${5:-$name --version}"; then
    echo "$name $version found on PATH"
    exit 0
  fi
  echo "$name $version not on PATH, downloading it"
fi

missing=()
command -v curl >/dev/null || missing+=(curl)
if [[ "$url" == *.zip ]] && ! command -v unzip >/dev/null; then
  missing+=(unzip)
fi
if [ "${#missing[@]}" -gt 0 ]; then
  apt-get update -qq
  apt-get install -y -qq --no-install-recommends "${missing[@]}" >/dev/null
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
curl --proto '=https' --tlsv1.2 -sSfL --retry 3 -o "$tmp/archive" "$url"
echo "$sum  $tmp/archive" | sha256sum -c --quiet -
if [[ "$url" == *.zip ]]; then
  unzip -p "$tmp/archive" "$member" > "$tmp/binary"
  install -m 0755 "$tmp/binary" "$dest/$name"
else
  tar -xzf "$tmp/archive" -C "$tmp" "$member"
  install -m 0755 "$tmp/$member" "$dest/"
fi
echo "installed $(basename "$member") from $url"
