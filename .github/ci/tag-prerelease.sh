#!/bin/sh
# Tags a commit of the default branch with a pre-release version, vX.Y.Z-dev.N,
# so that every merge has a version (RELEASING.md). It makes no commit and
# changes no file.
#
#   tag-prerelease.sh               fetch the tags, tag $GITHUB_SHA, push the tag
#   tag-prerelease.sh --print [REV] print the tag REV (default HEAD) gets
#   tag-prerelease.sh --self-test   check the rules on scratch repositories
#
# The name depends only on the commit and the final tags behind it, so a re-run
# gives the same tag and two merges give two tags, whichever job runs first.
# X.Y.Z is the highest final tag vX.Y.Z behind the commit, raised as release-plz
# raises a version from 0.1.0 on for the commits since: a "!" title raises the
# minor while the major is 0 and the major after that, a feat title the minor
# from major 1 on, any other commit the patch; the largest raise of all the
# titles counts. N is the number of commits behind the commit, itself included:
# main is linear (squash merges), so N is unique per merge and only grows.
# The commit that carries the final tag gets none, and a clone with no final tag
# is refused.
#
# The job's token authenticates origin through checkout. Only the tag ref is
# pushed, never forced; GitHub's tag rules also refuse updates and deletion.
set -eu

final_re='^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'

# derive REV: print the pre-release tag of REV, nothing if REV is a release.
derive() {
  sha=$(git rev-parse --verify -q "$1^{commit}") || { echo "no such commit: $1" >&2; return 1; }
  [ "$(git rev-parse --is-shallow-repository)" = false ] || { echo "shallow clone: the history behind $1 is incomplete" >&2; return 1; }
  tags=$(git tag --merged "$sha" --list 'v*' --sort=-v:refname) || return 1
  last=$(printf '%s\n' "$tags" | grep -E "$final_re" | head -n 1)
  [ -n "$last" ] || { echo "no vX.Y.Z tag is reachable from $1: this clone has no release tags (git fetch --tags)" >&2; return 1; }
  [ "$(git rev-parse "refs/tags/$last^{commit}")" != "$sha" ] || return 0
  n=$(git rev-list --count "$sha") || return 1
  titles=$(git log --format=%s "refs/tags/$last..$sha") || return 1
  breaking=$(printf '%s\n' "$titles" | grep -Ec '^[A-Za-z]+(\([^)]*\))?!:' || true)
  feats=$(printf '%s\n' "$titles" | grep -Ec '^feat(\([^)]*\))?:' || true)
  base=${last#v}
  major=${base%%.*} rest=${base#*.}
  minor=${rest%%.*} patch=${rest#*.}
  if [ "$breaking" -gt 0 ] && [ "$major" -gt 0 ]; then
    major=$((major + 1)) minor=0 patch=0
  elif [ "$breaking" -gt 0 ]; then
    minor=$((minor + 1)) patch=0
  elif [ "$feats" -gt 0 ] && [ "$major" -gt 0 ]; then
    minor=$((minor + 1)) patch=0
  else
    patch=$((patch + 1))
  fi
  echo "v$major.$minor.$patch-dev.$n"
}

self_test() {
  script=$(cd "$(dirname "$0")" && pwd)/$(basename "$0")
  stamp=$(dirname "$script")/../../tools/stamp-workspace-version.sh
  dir=$(mktemp -d)
  trap 'rm -rf "$dir"' EXIT
  export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 HOME="$dir/home"
  export GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@example.com GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@example.com
  unset GITHUB_SHA GITHUB_OUTPUT
  failed=0
  is() { # NAME WANT GOT
    if [ "$2" = "$3" ]; then echo "ok    $1: $3"; else echo "WRONG $1: want [$2], got [$3]"; failed=1; fi
  }
  c() { git commit -q --allow-empty -m "$1"; }
  refuses() { derive "$@" >"$dir/out" 2>&1 && echo derived || echo refused; }
  job() { # REV [CLONE]: push only to the scratch bare repository
    : >"$dir/trace" && : >"$dir/output"
    (cd "${2:-.}" && GIT_TRACE="$dir/trace" GITHUB_OUTPUT="$dir/output" GITHUB_SHA=$(git rev-parse "$1") sh "$script") >"$dir/out" 2>&1 && rc=0 || rc=$?
  }
  remote() { git -C "$dir/remote.git" "$@"; }
  git init -q -b main "$dir/work" && git init -q --bare "$dir/remote.git" && cd "$dir/work"
  git remote add origin "file://$dir/remote.git"

  c "fix: a"
  is "no release tag: refused, with the reason" "refused 1" "$(refuses HEAD) $(grep -c 'no vX.Y.Z tag' "$dir/out")"
  git tag v0.9.0 && git tag v0.10.0
  is "a release gets no pre-release" "" "$(derive HEAD)"
  c "feat: b"
  is "highest tag by version; feat before 1.0.0 is a patch; N counts all" v0.10.1-dev.2 "$(derive HEAD)"
  git tag v0.99.0-rc.1 && git tag v0.3.3-dev.7 && git tag v0.10.1-dev.2 && git tag v1.0.0.1 && git tag v1.0.0x
  is "other tags are no release" v0.10.1-dev.2 "$(derive HEAD)"
  c "feat(x)!: d"
  is "breaking before 1.0.0 raises the minor" v0.11.0-dev.3 "$(derive HEAD)"
  c "fix: e"
  is "a series never falls back" v0.11.0-dev.4 "$(derive HEAD)"
  git tag v1.2.3
  c "fix: f" && c "feat: g" && c "refactor!: h"
  is "fix after 1.2.3" v1.2.4-dev.5 "$(derive HEAD~2)"
  is "feat from 1.0.0 raises the minor" v1.3.0-dev.6 "$(derive HEAD~1)"
  is "breaking from 1.0.0 raises the major" v2.0.0-dev.7 "$(derive HEAD)"
  git tag v5.0.0
  is "a later release does not change an older commit" v1.2.4-dev.5 "$(derive HEAD~2)"
  is "a pre-release publishes its own tag only" 1.3.0-dev.6 "$(sh "$stamp" --plan-tag v1.3.0-dev.6 | sed -n 2p)"
  git clone -q --depth 1 "file://$dir/work" "$dir/shallow"
  is "a shallow clone is refused" refused "$(cd "$dir/shallow" && refuses HEAD)"
  is "an unknown commit is refused" refused "$(refuses nope)"
  is "--print gives the name without pushing" v1.2.4-dev.5 "$(sh "$script" --print HEAD~2)"
  job HEAD~1 # the later of two merges first
  is "job pushes only its tag ref to origin" "0 git push origin $(git rev-parse HEAD~1):refs/tags/v1.3.0-dev.6" "$rc $(sed -n 's/.*built-in: //p' "$dir/trace" | grep 'git push' | tr -d "'")"
  is "the tag is a job output" "tag=v1.3.0-dev.6" "$(cat "$dir/output")"
  job HEAD~2; r1=$rc
  job HEAD~1; r2=$rc # a re-run
  job HEAD; r3=$rc # a release commit
  is "a release commit outputs no tag" "" "$(cat "$dir/output")"
  is "the earlier merge, a re-run, a release commit: all succeed" "0 0 0" "$r1 $r2 $r3"
  git clone -q --no-tags "file://$dir/work" "$dir/fresh"
  job HEAD~2 "$dir/fresh" # a clone without tags: the job fetches them
  is "a clone without tags: the job fetches them" 0 "$rc"
  is "two merges, two tags, nothing else, each on its commit" "v1.2.4-dev.5 v1.3.0-dev.6 $(git rev-parse HEAD~2)" "$(remote for-each-ref --format='%(refname:short)' | paste -sd' ' -) $(remote rev-parse v1.2.4-dev.5)"
  c "fix: i"
  remote tag v5.0.1-dev.8 "$(git rev-parse HEAD~2)"
  job HEAD
  is "a tag on another commit fails the job" 1 "$rc"
  is "and stays where it was" "$(git rev-parse HEAD~2)" "$(remote rev-parse v5.0.1-dev.8)"

  git init -q -b main "$dir/late" && cd "$dir/late"
  c "fix: 0" && git tag v0.3.2
  for t in "fix: a" "feat!: b" "fix: c" "fix: d"; do c "$t" && git tag "$(derive HEAD)"; done # the names the jobs gave
  git tag v0.3.3 HEAD~3 # a final tag on an older commit, after later merges
  c "fix: 7"
  is "final tag on an ancestor after later merges: the next number, a new name" "v0.4.0-dev.6 " "$(derive HEAD) $(git tag --list "$(derive HEAD)")"
  git init -q -b main "$dir/none" && (cd "$dir/none" && c "fix: z") && git clone -q "file://$dir/none" "$dir/untagged"
  job HEAD "$dir/untagged"
  is "no release tag anywhere: the job stops, with the reason" "1 1" "$rc $(grep -c 'no vX.Y.Z tag' "$dir/out")"

  [ "$failed" -eq 0 ] || { echo "self-test failed" >&2; return 1; }
  echo "self-test ok"
}

case ${1:-} in
  --self-test) self_test ;;
  --print) derive "${2:-HEAD}" ;;
  "")
    sha=${GITHUB_SHA:?GITHUB_SHA is not set: this runs in GitHub Actions}
    git fetch --quiet --tags origin
    tag=$(derive "$sha")
    if [ -z "$tag" ]; then
      echo "$sha is a final release: no pre-release tag"
      exit 0
    fi
    echo "tagging $sha as $tag"
    git push origin "$sha:refs/tags/$tag"
    printf 'tag=%s\n' "$tag" >>"${GITHUB_OUTPUT:?GITHUB_OUTPUT is not set}"
    ;;
  *)
    echo "usage: $0 [--print [REV] | --self-test]" >&2
    exit 2
    ;;
esac
