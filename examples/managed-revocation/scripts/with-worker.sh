#!/usr/bin/env bash
# Boot integrations/hosted-verify under `wrangler dev` with a generated .dev.vars, wait
# for /health, run the given command against it, and always stop the Worker. Nothing
# from .dev.vars is printed; the Worker's log stays in a temp file that is never echoed
# and is deleted on success (its path is reported when the Worker fails to start).
#
#   bash scripts/with-worker.sh npm run demo
#   HOSTED_VERIFY_PORT=8790 bash scripts/with-worker.sh npm run demo
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
worker="$(cd "$here/../../../integrations/hosted-verify" && pwd)"
port="${HOSTED_VERIFY_PORT:-8787}"
export VERIFY_URL="${VERIFY_URL:-http://127.0.0.1:$port}"

node "$here/dev-vars.mjs"

if [ -n "$(lsof -ti "tcp:$port" 2>/dev/null || true)" ]; then
  echo "port $port is already in use; set HOSTED_VERIFY_PORT to a free port" >&2
  exit 1
fi

log="$(mktemp -t hosted-verify-dev.XXXXXX)"
keep_log=0
(
  cd "$worker"
  exec env WRANGLER_SEND_METRICS=false npx wrangler dev --ip 127.0.0.1 --port "$port" </dev/null >"$log" 2>&1
) &
worker_pid=$!

cleanup() {
  kill "$worker_pid" 2>/dev/null || true
  pkill -P "$worker_pid" 2>/dev/null || true
  # wrangler forks workerd; anything still holding the port (which was free when we
  # started, so it is ours) goes too.
  local holders
  holders="$(lsof -ti "tcp:$port" 2>/dev/null || true)"
  if [ -n "$holders" ]; then kill $holders 2>/dev/null || true; fi
  wait "$worker_pid" 2>/dev/null || true
  if [ "$keep_log" -eq 1 ]; then
    echo "wrangler dev log kept at $log (it names bindings; values are hidden)" >&2
  else
    rm -f "$log"
  fi
}
trap cleanup EXIT

ready=0
for _ in $(seq 1 90); do
  if curl -sf "$VERIFY_URL/health" >/dev/null 2>&1; then ready=1; break; fi
  if ! kill -0 "$worker_pid" 2>/dev/null; then
    keep_log=1
    echo "wrangler dev exited before /health answered" >&2
    exit 1
  fi
  sleep 1
done
if [ "$ready" -ne 1 ]; then
  keep_log=1
  echo "hosted-verify did not become ready at $VERIFY_URL within 90 s" >&2
  exit 1
fi

"$@"
