#!/bin/sh
# In a dedicated site job container, install dependencies and run a command as node.
set -eu
test ! -L "$1"
cd "$1"
shift
node_uid=$(id -u node)

node_stopped() {
  # A non-reaping PID 1 can leave zombies; a zombie leader with other threads
  # still present does not count as stopped.
  awk -v uid="$node_uid" '
    FNR == 1 { state = ""; owned = 0 }
    $1 == "State:" { state = $2 }
    $1 == "Uid:" { owned = ($2 == uid || $3 == uid || $4 == uid || $5 == uid) }
    $1 == "Threads:" && owned && (state != "Z" || $2 != 1) { exit 1 }
  ' /proc/[0-9]*/status
}

cleanup() {
  status=$?
  for attempt in 1 2 3 4 5; do
    # Signal from node in the private PID namespace, including detached children.
    runuser -u node -- sh -c 'kill -KILL -1' 2>/dev/null || :
    if node_stopped; then
      chown -hRP 0:0 .
      chmod -R a-s,go-w .
      exit "$status"
    fi
    sleep 0.1
  done
  echo 'Could not verify that the unprivileged site processes stopped' >&2
  exit 1
}
trap cleanup EXIT
chown -hRP node:node .
runuser -u node -- setpriv --no-new-privs env -i \
  HOME=/home/node PATH=/usr/local/bin:/usr/bin:/bin CI=true WRANGLER_SEND_METRICS=false sh -ec '
    bun install --frozen-lockfile --ignore-scripts
    if [ "$#" -gt 0 ]; then exec "$@"; fi
  ' sh "$@"
