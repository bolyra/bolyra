#!/usr/bin/env bash
# Boot integrations/hosted-verify under `wrangler dev` with a generated .dev.vars, wait
# for /health, run the given command against it, and always stop the Worker — on normal
# exit, on failure, and on SIGINT/SIGTERM. Only the Worker's own process tree is ever
# signalled. Nothing from .dev.vars is printed; the Worker's log stays in a temp file that
# is never echoed and is deleted unless something fails (its path is then reported; it
# names bindings, values are hidden). The generated .dev.vars is removed on exit.
#
#   bash scripts/with-worker.sh npm run demo
#   HOSTED_VERIFY_PORT=8790 bash scripts/with-worker.sh npm run demo
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
worker="$(cd "$here/../../../integrations/hosted-verify" && pwd)"
port="${HOSTED_VERIFY_PORT:-8787}"
export VERIFY_URL="http://127.0.0.1:$port"
READY_TIMEOUT_S=90

if ! command -v lsof >/dev/null 2>&1; then
  echo "lsof is required (it checks the port before the Worker starts)" >&2
  exit 1
fi
if [ ! -x "$worker/node_modules/.bin/wrangler" ]; then
  echo "install the Worker's dependencies first: (cd $worker && npm ci)" >&2
  exit 1
fi
if [ -n "$(lsof -ti "tcp:$port" -sTCP:LISTEN 2>/dev/null || true)" ]; then
  echo "port $port is already in use; set HOSTED_VERIFY_PORT to a free port" >&2
  exit 1
fi

node "$here/dev-vars.mjs"

log="$(mktemp "${TMPDIR:-/tmp}/hosted-verify-dev.XXXXXX")"
keep_log=0
(
  cd "$worker"
  exec env WRANGLER_SEND_METRICS=false npx --no-install wrangler dev --env="" --ip 127.0.0.1 --port "$port" </dev/null >"$log" 2>&1
) &
worker_pid=$!

# Every process below the Worker's shell, deepest first (wrangler forks workerd).
descendants() {
  local child
  for child in $(pgrep -P "$1" 2>/dev/null || true); do
    descendants "$child"
    echo "$child"
  done
}

# Stop a process and everything below it: TERM, one second, then KILL; then reap.
stop_tree() {
  local pids
  pids="$(descendants "$1") $1"
  # shellcheck disable=SC2086
  kill -TERM $pids 2>/dev/null || true
  sleep 1
  # shellcheck disable=SC2086
  kill -KILL $pids 2>/dev/null || true
  wait "$1" 2>/dev/null || true
}

cleanup() {
  stop_tree "$worker_pid"
  if [ -n "$(lsof -ti "tcp:$port" -sTCP:LISTEN 2>/dev/null || true)" ]; then
    echo "warning: something still listens on port $port after the Worker was stopped; it was not started by this script and was left alone" >&2
  fi
  rm -f "$worker/.dev.vars"
  if [ "$keep_log" -eq 1 ]; then
    echo "wrangler dev log kept at $log (it names bindings; values are hidden)" >&2
  else
    rm -f "$log"
  fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

ready=0
SECONDS=0
while [ "$SECONDS" -lt "$READY_TIMEOUT_S" ]; do
  if curl -sf --max-time 3 "$VERIFY_URL/health" >/dev/null 2>&1; then ready=1; break; fi
  if ! kill -0 "$worker_pid" 2>/dev/null; then
    keep_log=1
    echo "wrangler dev exited before /health answered" >&2
    exit 1
  fi
  sleep 1
done
if [ "$ready" -ne 1 ]; then
  keep_log=1
  echo "hosted-verify did not become ready at $VERIFY_URL within ${READY_TIMEOUT_S} s" >&2
  exit 1
fi

# Run the command as a child so a signal to this script stops the command's whole
# process tree before the Worker is torn down.
"$@" &
cmd_pid=$!
trap 'stop_tree "$cmd_pid"; exit 130' INT
trap 'stop_tree "$cmd_pid"; exit 143' TERM
if wait "$cmd_pid"; then
  status=0
else
  status=$?
  keep_log=1
fi
exit "$status"
