#!/usr/bin/env bash
#
# tenant-lock-check.sh — prove that tenant.sh keeps its per-environment lock until the
# in-flight `wrangler secret put` has finished, so an interrupted run cannot be overtaken.
#
# The failure this guards: an operator TERMs a sync that is paused inside the upload. If the
# EXIT trap released the lock there, a second operator's `disable` + `sync` would land FIRST
# and the interrupted run's OLDER (still active) map would overwrite it — the quarantine
# silently undone.
#
# Self-contained and offline: shims for `security`, `npx` and `wrangler` go FIRST on PATH, so
# no keychain item is read or written on any machine, no network call is made, and wrangler is
# never reached. The registry lives in a temp directory under HOSTED_VERIFY_ENV=lockcheck.
# Runs on Linux and macOS; bash 3.2 (no flock, no associative arrays, no `wait -n`).
#
#   bash pilot/tenant-lock-check.sh          (SHIM_SLEEP=<seconds> widens the timing window)
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TENANT="$SCRIPT_DIR/tenant.sh"
SHIM_SLEEP="${SHIM_SLEEP:-3}"

WORK="$(mktemp -d)"
SHIM="$WORK/bin"
TENANTS_DIR="$WORK/tenants"
LOCK_DIR="$TENANTS_DIR/.lock"
MARKER="$WORK/marker"
BG=""
SLEEPER=""
PUT=""

cleanup() {
  # Nothing here may outlive the check: a stray shim sleep would look like a live upload.
  for p in "$BG" "$SLEEPER" "$PUT"; do
    [ -z "$p" ] || kill -9 "$p" 2>/dev/null || true
  done
  rm -rf "$WORK"
}
trap cleanup EXIT

ok()   { echo "ok: $*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
wait_for_file() {  # $1 path — poll for up to 5 s
  local i=0
  while [ ! -f "$1" ]; do
    i=$((i + 1))
    [ "$i" -le 50 ] || return 1
    sleep 0.1
  done
  return 0
}

mkdir -p "$SHIM" "$TENANTS_DIR"

# A fake `security`: tokens are derived from the account name, so they are deterministic,
# distinct per role (the validator refuses a repeated token) and never touch a keychain.
cat > "$SHIM/security" <<'SHIM_SECURITY'
#!/usr/bin/env bash
cmd="${1:-}"; [ $# -eq 0 ] || shift
acct=""; want_w=0
while [ $# -gt 0 ]; do
  case "$1" in
    -a) acct="${2:-}"; shift; [ $# -gt 0 ] && shift ;;
    -s|-j) shift; [ $# -gt 0 ] && shift ;;
    -w) want_w=1; shift ;;
    *) shift ;;
  esac
done
case "$cmd" in
  find-generic-password)
    if [ "$want_w" = 1 ]; then
      if command -v shasum >/dev/null 2>&1; then
        printf '%s' "$acct" | shasum -a 256 | cut -c1-64
      else
        printf '%s' "$acct" | sha256sum | cut -c1-64
      fi
    fi
    exit 0 ;;
  add-generic-password)
    cat >/dev/null   # the real one reads the password twice; never leave the writer on a SIGPIPE
    exit 0 ;;
  delete-generic-password)
    exit 0 ;;
esac
exit 1
SHIM_SECURITY

# A fake `npx`: records its argv, then stays busy long enough for the check to observe an
# upload that is still in flight. Its TERM handler is what proves the interrupt reached the
# child — and, like bash itself, it only runs once the foreground sleep has returned.
cat > "$SHIM/npx" <<'SHIM_NPX'
#!/usr/bin/env bash
: "${MARKER:?tenant-lock-check: MARKER must be set}"
printf 'npx %s\n' "$*" >> "$MARKER"
trap 'printf "term\n" >> "$MARKER"; exit 143' TERM
sleep "${SHIM_SLEEP:-3}"
printf 'done\n' >> "$MARKER"
exit 0
SHIM_NPX

# Reaching the real wrangler would mean a network call and a live secret: make it loud.
cat > "$SHIM/wrangler" <<'SHIM_WRANGLER'
#!/usr/bin/env bash
echo "tenant-lock-check: the wrangler shim was reached; nothing here may talk to Cloudflare" >&2
exit 9
SHIM_WRANGLER

chmod +x "$SHIM/security" "$SHIM/npx" "$SHIM/wrangler"

printf '%s\n' '{"org_id":"acme","status":"active","trustedOperators":["1:2"]}' > "$TENANTS_DIR/acme.json"

# Every tenant.sh call in this check runs with the shims first on PATH and with the temp
# registry; nothing reads the operator's own environment.
TENANT_ENV=(PATH="$SHIM:$PATH" HOSTED_VERIFY_ENV=lockcheck TENANTS_DIR="$TENANTS_DIR" MARKER="$MARKER" SHIM_SLEEP="$SHIM_SLEEP")
tenant() { env "${TENANT_ENV[@]}" bash "$TENANT" "$@"; }

# (a) a dry run validates and stops short of the upload.
out="$(tenant sync --dry-run 2>&1)"; rc=$?
[ "$rc" = 0 ] || fail "sync --dry-run exited $rc: $out"
[ ! -e "$MARKER" ] || fail "sync --dry-run reached the put stage"
ok "sync --dry-run validates without starting an upload"

# (b) a real sync holds the lock while the upload is in flight.
env "${TENANT_ENV[@]}" bash "$TENANT" sync > "$WORK/sync.log" 2>&1 &
BG=$!
wait_for_file "$MARKER" || fail "the upload never started: $(cat "$WORK/sync.log")"
out="$(tenant disable acme 2>&1)"; rc=$?
[ "$rc" = 1 ] || fail "disable during an upload exited $rc, expected 1: $out"
case "$out" in *"another tenant.sh is running"*) ;; *) fail "disable was refused for the wrong reason: $out" ;; esac
[ "$(grep -c '^npx ' "$MARKER")" = 1 ] || fail "a second run reached the put stage while the first held the lock"
ok "a second operator's disable is refused while the upload is in flight"

# (c) the interrupt is the whole point: TERM must not hand the lock over mid-upload.
kill -TERM "$BG" || fail "could not signal the running sync"
out="$(tenant disable acme 2>&1)"; rc=$?
[ "$rc" = 1 ] || fail "disable after the interrupt exited $rc, expected 1: $out"
case "$out" in *"another tenant.sh is running"*) ;; *) fail "disable was refused for the wrong reason: $out" ;; esac
[ "$(grep -c '^npx ' "$MARKER")" = 1 ] || fail "a second run reached the put stage after the interrupt"
ok "the lock is still held after the interrupted run is signalled"

# (d) the interrupt takes effect only once the put has finished, and then the lock goes.
wait "$BG"; rc=$?
BG=""
[ "$rc" = 143 ] || fail "the interrupted sync exited $rc, expected 143"
[ "$(tail -n 1 "$MARKER")" = "done" ] || fail "the in-flight upload did not finish: $(cat "$MARKER")"
grep -q "interrupted by SIGTERM" "$WORK/sync.log" || fail "the interrupt was not reported: $(cat "$WORK/sync.log")"
[ ! -d "$LOCK_DIR" ] || fail "the lock survived a finished upload"
ok "the interrupt lands after the put completes and the lock is then released"

# (e) with the lock gone, the quarantine goes through — on its own, not racing anyone.
out="$(tenant disable acme 2>&1)"; rc=$?
[ "$rc" = 0 ] || fail "disable exited $rc: $out"
[ "$(grep -c '^npx ' "$MARKER")" = 2 ] || fail "disable did not push its own map"
grep -q '"status": "disabled"' "$TENANTS_DIR/acme.json" || fail "the registry was not quarantined"
ok "disable succeeds once the lock is free and pushes its own map"

# (f) and the quarantine is what an operator sees.
out="$(tenant show 2>&1)"; rc=$?
[ "$rc" = 0 ] || fail "show exited $rc: $out"
echo "$out" | grep -qE '^acme[[:space:]]+disabled' || fail "show does not report acme as disabled: $out"
ok "show reports acme as disabled"

# (g) a lock whose upload pid is still alive is nobody else's to take or to clear.
sleep 30 &
SLEEPER=$!
mkdir -p "$LOCK_DIR"
echo "$SLEEPER" > "$LOCK_DIR/upload.pid"
out="$(tenant sync --dry-run 2>&1)"; rc=$?
[ "$rc" = 1 ] || fail "sync --dry-run against a held lock exited $rc, expected 1: $out"
[ -d "$LOCK_DIR" ] || fail "a refused run removed a lock it did not create"
[ -f "$LOCK_DIR/upload.pid" ] || fail "a refused run cleared another run's upload pid"
kill "$SLEEPER" 2>/dev/null || true
wait "$SLEEPER" 2>/dev/null
SLEEPER=""
out="$(tenant disable acme 2>&1)"; rc=$?
[ "$rc" = 1 ] || fail "disable against a leftover lock exited $rc, expected 1: $out"
rm -rf "$LOCK_DIR"
ok "a lock left behind by an uncertain upload blocks every other run until it is cleared"

# (h) the same rule from inside the put stage: the upload pid is recorded while wrangler runs,
# an interrupt is forwarded to it, and the pid file is cleared only once the child is gone.
MARKER_PUT="$WORK/marker-put"
LOCK_PUT="$WORK/lock-put"
mkdir -p "$LOCK_PUT"
printf '{"acme":{}}' | env PATH="$SHIM:$PATH" MARKER="$MARKER_PUT" SHIM_SLEEP="$SHIM_SLEEP" TENANT_LOCK_DIR="$LOCK_PUT" \
  node "$SCRIPT_DIR/tenants-put.mjs" --env=lockcheck > "$WORK/put.log" 2>&1 &
PUT=$!
wait_for_file "$LOCK_PUT/upload.pid" || fail "the put stage never recorded its upload pid: $(cat "$WORK/put.log")"
upload_pid="$(cat "$LOCK_PUT/upload.pid")"
kill -0 "$upload_pid" 2>/dev/null || fail "the recorded upload pid $upload_pid is not a live process"
kill -TERM "$PUT" || fail "could not signal the put stage"
wait "$PUT"; rc=$?
PUT=""
[ "$rc" != 0 ] || fail "the put stage reported success after an interrupt"
grep -qx 'term' "$MARKER_PUT" || fail "the interrupt did not reach the upload child: $(cat "$MARKER_PUT")"
[ ! -f "$LOCK_PUT/upload.pid" ] || fail "the upload pid file survived the upload"
ok "the put stage tracks its upload pid, forwards the interrupt, and clears the pid when done"

echo "tenant-lock-check: all checks passed"
