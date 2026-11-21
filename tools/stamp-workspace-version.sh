#!/bin/sh
# Version stamped into a release image, and the Docker tags for that image.
#
# A local build never runs this, so the workspace version stays whatever
# Cargo.toml says. The image build runs it only when POSTKEEP_VERSION is set:
#
#   stamp-workspace-version.sh X.Y.Z
#
# That rewrites the workspace version in Cargo.toml and the matching
# path packages in Cargo.lock, then `cargo build --locked` can proceed.
# The version must be strict semver without build metadata: X.Y.Z or
# X.Y.Z-prerelease (for example 1.2.3-rc.1).
#
#   stamp-workspace-version.sh --plan-tag vX.Y.Z
#     line 1: version without the leading v
#     line 2: Docker tags. A final release is "X.Y.Z X.Y X latest".
#             A pre-release is only "X.Y.Z-prerelease".
#   stamp-workspace-version.sh --plan-branch <8-hex-chars>
#     line 1: empty (the binary keeps the Cargo.toml version)
#     line 2: "latest main <8-hex-chars>", or "latest main" alone when the
#             hash is all digits
#     The hash is the tag itself: no sha- prefix. X.Y.Z, X.Y and a
#     pre-release all contain a dot, so they cannot equal it. Eight
#     digits could equal a floating major tag, so that commit gets no
#     hash tag.
#   stamp-workspace-version.sh --self-test
set -eu

# SemVer 2.0.0, without build metadata. Numeric identifiers cannot have
# a leading zero. This is the whole tag after the leading v.
release_re='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'
semver_re='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-((0|[1-9][0-9]*)|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(\.((0|[1-9][0-9]*)|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*)?$'

version_kind() {
  ver=$1
  if printf '%s\n' "$ver" | grep -Eq "$release_re"; then
    printf '%s\n' release
    return 0
  fi
  if printf '%s\n' "$ver" | grep -Eq "$semver_re"; then
    printf '%s\n' prerelease
    return 0
  fi
  return 1
}

plan_tag() {
  tag=$1
  case $tag in
    v*) ;;
    *)
      echo "refusing tag ${tag}: want vX.Y.Z or vX.Y.Z-prerelease" >&2
      return 1
      ;;
  esac
  ver=${tag#v}
  if ! kind=$(version_kind "$ver"); then
    echo "refusing tag ${tag}: want vX.Y.Z or vX.Y.Z-prerelease" >&2
    return 1
  fi
  printf '%s\n' "$ver"
  if [ "$kind" = release ]; then
    major=${ver%%.*}
    rest=${ver#*.}
    minor=${rest%%.*}
    printf '%s\n' "$ver ${major}.${minor} $major latest"
  else
    printf '%s\n' "$ver"
  fi
}

plan_branch() {
  sha=$1
  # Whole string, exactly 8 hex chars. case matches the entire value.
  case $sha in
    [0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f]) ;;
    *)
      echo "refusing short sha ${sha}: want 8 hex chars" >&2
      return 1
      ;;
  esac
  sha=$(printf '%s' "$sha" | tr 'ABCDEF' 'abcdef')
  # A floating major tag is a decimal integer with no dot. Eight digits
  # would publish the same name. Any a-f character makes that impossible,
  # and X.Y.Z / X.Y / pre-release tags all contain a dot. So a commit whose
  # hash is all digits gets no hash tag: latest and main still move to it.
  printf '\n'
  case $sha in
    *[!0-9]*) printf '%s\n' "latest main ${sha}" ;;
    *) printf '%s\n' "latest main" ;;
  esac
}

# Package names of workspace members, one per line.
package_names() {
  root=$1
  find "$root/crates" "$root/tools" -name Cargo.toml -type f | sort | while IFS= read -r manifest; do
    sed -n 's/^name = "\([^"]*\)"$/\1/p' "$manifest" | head -n 1
  done
}

stamp_root() {
  root=$1
  ver=$2
  names=$(mktemp)
  toml_new=$(mktemp)
  lock_new=$(mktemp)
  cleanup() {
    rm -f "$names" "$toml_new" "$lock_new"
  }
  if ! version_kind "$ver" >/dev/null; then
    echo "POSTKEEP_VERSION is not strict semver: ${ver}" >&2
    cleanup
    return 1
  fi
  if [ ! -f "$root/Cargo.toml" ] || [ ! -f "$root/Cargo.lock" ]; then
    echo "Cargo.toml and Cargo.lock are required in ${root}" >&2
    cleanup
    return 1
  fi
  package_names "$root" > "$names"
  if ! grep -q . "$names"; then
    echo "no workspace packages found under ${root}" >&2
    cleanup
    return 1
  fi
  if ! POSTKEEP_STAMP_VERSION=$ver awk '
    BEGIN { in_pkg = 0; stamped = 0 }
    /^\[workspace\.package\]$/ { in_pkg = 1; print; next }
    /^\[/ { in_pkg = 0 }
    in_pkg && /^version = "/ {
      print "version = \"" ENVIRON["POSTKEEP_STAMP_VERSION"] "\""
      stamped = 1
      next
    }
    { print }
    END { if (stamped != 1) exit 2 }
  ' "$root/Cargo.toml" > "$toml_new"; then
    echo "failed to stamp Cargo.toml" >&2
    cleanup
    return 1
  fi
  if ! POSTKEEP_STAMP_VERSION=$ver POSTKEEP_STAMP_NAMES=$names awk '
    BEGIN {
      ver = ENVIRON["POSTKEEP_STAMP_VERSION"]
      names = ENVIRON["POSTKEEP_STAMP_NAMES"]
      total = 0
      stamped = 0
      while ((getline name < names) > 0) {
        if (name != "") {
          wanted[name] = 1
          total++
        }
      }
      close(names)
      if (total < 1) exit 2
    }
    {
      n = ""
      if (prev ~ /^name = "/) {
        n = prev
        sub(/^name = "/, "", n)
        sub(/"$/, "", n)
      }
      if (n != "" && (n in wanted) && wanted[n] == 1 && $0 ~ /^version = "/) {
        print "version = \"" ver "\""
        wanted[n] = 2
        stamped++
        prev = ""
        next
      }
      print
      prev = $0
    }
    END {
      if (stamped != total) exit 3
      for (n in wanted) if (wanted[n] != 2) exit 4
    }
  ' "$root/Cargo.lock" > "$lock_new"; then
    echo "failed to stamp Cargo.lock (workspace package set changed?)" >&2
    cleanup
    return 1
  fi
  mv "$toml_new" "$root/Cargo.toml"
  mv "$lock_new" "$root/Cargo.lock"
  rm -f "$names"
  echo "stamped workspace version ${ver}"
}

self_test() {
  failed=0
  check_tag() {
    tag=$1
    want_ver=$2
    want_tags=$3
    if ! out=$(plan_tag "$tag"); then
      echo "self-test: ${tag} was refused" >&2
      failed=1
      return
    fi
    got_ver=$(printf '%s\n' "$out" | sed -n '1p')
    got_tags=$(printf '%s\n' "$out" | sed -n '2p')
    if [ "$got_ver" != "$want_ver" ] || [ "$got_tags" != "$want_tags" ]; then
      echo "self-test: ${tag} got [${got_ver}] [${got_tags}]" >&2
      failed=1
    fi
  }
  refuse_tag() {
    tag=$1
    if plan_tag "$tag" >/dev/null 2>&1; then
      echo "self-test: ${tag} should have been refused" >&2
      failed=1
    fi
  }

  check_tag v1.2.3 1.2.3 "1.2.3 1.2 1 latest"
  check_tag v0.3.3 0.3.3 "0.3.3 0.3 0 latest"
  check_tag v10.20.30 10.20.30 "10.20.30 10.20 10 latest"
  check_tag v0.3.3-rc.1 0.3.3-rc.1 "0.3.3-rc.1"
  check_tag v1.2.3-alpha 1.2.3-alpha "1.2.3-alpha"
  check_tag v1.2.3-alpha.1 1.2.3-alpha.1 "1.2.3-alpha.1"
  check_tag v1.2.3-rc-1 1.2.3-rc-1 "1.2.3-rc-1"
  check_tag v1.2.3-0 1.2.3-0 "1.2.3-0"

  refuse_tag v1.2
  refuse_tag v1.2.3.4
  refuse_tag v1.2.3foo
  refuse_tag v1.2.3+build
  refuse_tag v1.2.3-rc.1+build
  refuse_tag v01.2.3
  refuse_tag v1.02.3
  refuse_tag v1.2.03
  refuse_tag v1.2.3-
  refuse_tag v1.2.3-rc.
  refuse_tag v1.2.3-01
  refuse_tag v1.2.3-rc.01
  refuse_tag 1.2.3
  refuse_tag v1.2.3-α
  refuse_tag ""

  check_branch() {
    sha=$1
    want_tags=$2
    if ! out=$(plan_branch "$sha"); then
      echo "self-test: branch plan ${sha} was refused" >&2
      failed=1
      return
    fi
    got_ver=$(printf '%s\n' "$out" | sed -n '1p')
    got_tags=$(printf '%s\n' "$out" | sed -n '2p')
    if [ -n "$got_ver" ] || [ "$got_tags" != "$want_tags" ]; then
      echo "self-test: branch plan ${sha} got [${got_ver}] [${got_tags}]" >&2
      failed=1
    fi
    # No tag of the plan may be made only of digits: it could equal a
    # floating major tag.
    for word in $got_tags; do
      case $word in
        *[!0-9]*) ;;
        *)
          echo "self-test: branch plan ${sha} has the all-digit tag ${word}" >&2
          failed=1
          ;;
      esac
    done
  }
  refuse_branch() {
    sha=$1
    if plan_branch "$sha" >/dev/null 2>&1; then
      echo "self-test: branch plan ${sha} should have been refused" >&2
      failed=1
    fi
  }

  check_branch a330f961 "latest main a330f961"
  check_branch 7620e4c6 "latest main 7620e4c6"
  check_branch A330F961 "latest main a330f961"
  # One letter is enough for a hash tag, wherever it stands.
  check_branch a1234567 "latest main a1234567"
  check_branch 1234567a "latest main 1234567a"
  check_branch 12345E78 "latest main 12345e78"
  # Eight digits could equal a floating major tag, so such a commit gets no
  # hash tag. latest and main still move to it.
  check_branch 12345678 "latest main"
  check_branch 01234567 "latest main"
  check_branch 00000000 "latest main"
  check_branch 99999999 "latest main"
  # Eight hex chars do not match a dotted release or pre-release.
  if printf '%s\n' a330f961 | grep -Eq "$release_re" || printf '%s\n' a330f961 | grep -Eq "$semver_re"; then
    echo "self-test: hash tag matched a release pattern" >&2
    failed=1
  fi
  refuse_branch ""
  refuse_branch "not-a-sha"
  refuse_branch "sha-a330f961"
  refuse_branch a330f96
  refuse_branch a330f9610
  refuse_branch 1234567
  refuse_branch 123456789

  dir=$(mktemp -d)
  mkdir -p "$dir/crates/a" "$dir/tools/b"
  cat > "$dir/Cargo.toml" << 'EOF'
[workspace]
resolver = "3"
members = ["crates/*", "tools/*"]

[workspace.package]
version = "0.3.2"
edition = "2024"

[workspace.dependencies]
want = "0.3.2"
EOF
  printf '%s\n' '[package]' 'name = "crate-a"' 'version.workspace = true' > "$dir/crates/a/Cargo.toml"
  printf '%s\n' '[package]' 'name = "tool-b"' 'version.workspace = true' > "$dir/tools/b/Cargo.toml"
  cat > "$dir/Cargo.lock" << 'EOF'
# This file is automatically @generated by Cargo.
version = 4

[[package]]
name = "crate-a"
version = "0.3.2"
dependencies = [
 "tool-b",
 "want",
]

[[package]]
name = "tool-b"
version = "0.3.2"

[[package]]
name = "want"
version = "0.3.2"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "unused"
EOF
  if ! stamp_root "$dir" "0.3.3-rc.1" >/dev/null; then
    echo "self-test: stamp failed" >&2
    failed=1
  else
    toml_ver=$(sed -n '/^\[workspace\.package\]$/,/^\[/s/^version = "\(.*\)"$/\1/p' "$dir/Cargo.toml")
    if [ "$toml_ver" != "0.3.3-rc.1" ]; then
      echo "self-test: Cargo.toml version is [${toml_ver}]" >&2
      failed=1
    fi
    if grep -q 'version = "0.3.2"' "$dir/Cargo.toml"; then
      echo "self-test: Cargo.toml still has 0.3.2" >&2
      failed=1
    fi
    # The registry package that happens to be 0.3.2 must stay.
    if ! grep -A1 'name = "want"' "$dir/Cargo.lock" | grep -q 'version = "0.3.2"'; then
      echo "self-test: registry package version changed" >&2
      failed=1
    fi
    for name in crate-a tool-b; do
      if ! grep -A1 "name = \"${name}\"" "$dir/Cargo.lock" | grep -q 'version = "0.3.3-rc.1"'; then
        echo "self-test: ${name} was not stamped" >&2
        failed=1
      fi
    done
  fi
  if stamp_root "$dir" "1.2.3+build" >/dev/null 2>&1; then
    echo "self-test: bad version was stamped" >&2
    failed=1
  fi
  rm -rf "$dir"

  if [ "$failed" -ne 0 ]; then
    echo "self-test failed" >&2
    return 1
  fi
  echo "self-test ok"
}

case ${1:-} in
  --self-test)
    self_test
    ;;
  --plan-tag)
    if [ $# -ne 2 ]; then
      echo "usage: stamp-workspace-version.sh --plan-tag vX.Y.Z" >&2
      exit 1
    fi
    plan_tag "$2"
    ;;
  --plan-branch)
    if [ $# -ne 2 ]; then
      echo "usage: stamp-workspace-version.sh --plan-branch <8-hex-chars>" >&2
      exit 1
    fi
    plan_branch "$2"
    ;;
  "")
    echo "usage: stamp-workspace-version.sh X.Y.Z" >&2
    exit 1
    ;;
  -*)
    echo "unknown option: $1" >&2
    exit 1
    ;;
  *)
    if [ $# -ne 1 ]; then
      echo "usage: stamp-workspace-version.sh X.Y.Z" >&2
      exit 1
    fi
    stamp_root . "$1"
    ;;
esac
