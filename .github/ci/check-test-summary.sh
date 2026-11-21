#!/usr/bin/env bash
# Fails unless the nextest run in <log> ran every test, including the ignored
# integration tests, and skipped none.
#
# Usage: check-test-summary.sh <nextest output> <number of ignored tests listed>
set -euo pipefail

log=$1
ignored=$2

summary=$(sed 's/\x1b\[[0-9;]*m//g' "$log" | grep -E '^ *Summary \[' | tail -n 1 || true)
if [ -z "$summary" ]; then
  echo "no nextest summary found in $log" >&2
  exit 1
fi
run=$(sed -nE 's/.* ([0-9]+) tests? run.*/\1/p' <<<"$summary")
skipped=$(sed -nE 's/.* ([0-9]+) skipped.*/\1/p' <<<"$summary")
skipped=${skipped:-0}

echo "tests run: $run (of which ignored integration tests: $ignored); skipped: $skipped"
if [ "$ignored" -eq 0 ]; then
  echo "no ignored integration tests were listed; expected the GreenMail and Postgres tests" >&2
  exit 1
fi
if [ "$skipped" -ne 0 ]; then
  echo "$skipped tests were skipped; every test must run in CI" >&2
  exit 1
fi
