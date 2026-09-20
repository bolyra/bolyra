#!/usr/bin/env bash
#
# tenant-lock-check.sh — prove that tenant.sh keeps its per-environment lock until the
# `wrangler secret put` it started has been CONFIRMED finished, so an interrupted, crashed or
# killed run cannot be overtaken.
#
# The failure this guards: an operator TERMs a sync that is paused inside the upload. If the
# EXIT trap released the lock there, a second operator's `disable` + `sync` would land FIRST
# and the interrupted run's OLDER (still active) map would overwrite it — the quarantine
# silently undone. The same applies when the put stage is killed outright: the upload may
# already have been accepted, so the lock must stay until someone has looked.
#
# Self-contained and offline: shims for `security`, `npx` and `wrangler` go FIRST on PATH, so
# no keychain item is read or written on any machine, no network call is made, and wrangler is
# never reached. The `npx` shim behaves like the real launcher: it reads the map off stdin,
# takes its time, IGNORES interrupts, and prints wrangler's own success line only when what it
# received is a non-empty JSON object. The registry lives in a temp directory under
# HOSTED_VERIFY_ENV=lockcheck.
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
MARKER_BODY="$WORK/marker-body"
BG=""
ORPHAN=""

cleanup() {
  # Nothing here may outlive the check: a stray shim sleep would look like a live upload.
  for p in "$BG" "$ORPHAN"; do
    [ -z "$p" ] || kill -9 "$p" 2>/dev/null || true
  done
  rm -rf "$WORK"
}
trap cleanup EXIT

ok()   { echo "ok: $*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
wait_for_file() {  # $1 path — poll for up to 5 s
  local i=0
  while [ ! -e "$1" ]; do
    i=$((i + 1))
    [ "$i" -le 50 ] || return 1
    sleep 0.1
  done
  return 0
}
# The check has to reach INTO a running sync to kill or signal one of its processes, so it
# needs their pids. Each process writes its OWN: the put stage puts `put <pid>` in the marker
# under the lock, the upload stand-in writes its $$ beside the marker. Matching a name against
# a process list cannot do this — any ancestor or bystander whose command line happens to
# mention these files matches too, and the signal lands on the wrong process (in a container
# the `sh -c` at pid 1 matched first, ignored the kill, and the check passed vacuously).
put_pid()  { awk '/^put /{print $2}' "$LOCK_DIR/upload.pending" 2>/dev/null; }
shim_pid() { cat "$MARKER.pid" 2>/dev/null; }
wait_for_put() {  # echo the pid the put stage recorded for itself — poll for up to 5 s
  local i=0 p=""
  while [ -z "$p" ]; do
    p="$(put_pid)"
    [ -z "$p" ] || break
    i=$((i + 1))
    [ "$i" -le 50 ] || return 1
    sleep 0.1
  done
  printf '%s' "$p"
}
require_live() {  # $1 pid, $2 what it is — nothing is signalled on a guess
  [ -n "$1" ] || fail "could not determine the $2 pid"
  kill -0 "$1" 2>/dev/null || fail "could not determine the $2 pid: $1 is not a live process"
}
wait_for_gone() {  # $1 pid — poll for up to 20 s
  local i=0
  while kill -0 "$1" 2>/dev/null; do
    i=$((i + 1))
    [ "$i" -le 200 ] || return 1
    sleep 0.1
  done
  return 0
}
body_says() {  # $1 body file, $2 "active" | "disabled" — what the upload actually carried
  node -e '
const fs=require("fs");const [p,want]=process.argv.slice(1);
let m;try{m=JSON.parse(fs.readFileSync(p,"utf8"))}catch(e){process.stderr.write("body is not JSON: "+e.message+"\n");process.exit(1)}
const t=m&&m.acme;
if(!t){process.stderr.write("body has no acme entry\n");process.exit(1)}
const disabled=t.disabled===true;
if(want==="disabled"&&!disabled){process.stderr.write("body does not quarantine acme\n");process.exit(1)}
if(want==="active"&&disabled){process.stderr.write("body quarantines acme\n");process.exit(1)}' "$1" "$2"
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

# A fake `npx`, shaped like the real launcher: it records its argv, drains the map off stdin
# into $MARKER_BODY (so the check can assert WHAT was uploaded), stays busy long enough to be
# observed mid-flight, records its own pid beside the marker (the check signals nothing it has
# not been told the pid of), and IGNORES INT/TERM the way the launcher swallows its child's
# signal death. Only a non-empty JSON object earns wrangler's success line — the one thing the put
# stage accepts as confirmation. SHIM_NO_SUCCESS=1 exits 0 without printing it.
cat > "$SHIM/npx" <<'SHIM_NPX'
#!/usr/bin/env bash
: "${MARKER:?tenant-lock-check: MARKER must be set}"
: "${MARKER_BODY:?tenant-lock-check: MARKER_BODY must be set}"
trap '' INT TERM
printf '%s\n' "$$" > "$MARKER.pid"
printf 'npx %s\n' "$*" >> "$MARKER"
cat > "$MARKER_BODY"
sleep "${SHIM_SLEEP:-3}"
if ! node -e '
const fs=require("fs");let m;
try{m=JSON.parse(fs.readFileSync(process.argv[1],"utf8"))}catch(e){process.exit(1)}
if(typeof m!=="object"||m===null||Array.isArray(m)||Object.keys(m).length===0)process.exit(1)' "$MARKER_BODY"; then
  echo "shim: bad body" >&2
  exit 1
fi
if [ "${SHIM_NO_SUCCESS:-0}" != 1 ]; then
  printf '\xe2\x9c\xa8 Success! Uploaded secret TENANTS\n'
fi
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
TENANT_ENV=(PATH="$SHIM:$PATH" HOSTED_VERIFY_ENV=lockcheck TENANTS_DIR="$TENANTS_DIR" MARKER="$MARKER" MARKER_BODY="$MARKER_BODY" SHIM_SLEEP="$SHIM_SLEEP")
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
body_says "$MARKER_BODY" active || fail "the upload did not carry the active map: $(cat "$MARKER_BODY")"
[ ! -d "$LOCK_DIR" ] || fail "the lock survived a confirmed upload"
ok "the interrupt lands after the put completes and the lock is then released"

# (e) with the lock gone, the quarantine goes through — on its own, not racing anyone.
out="$(tenant disable acme 2>&1)"; rc=$?
[ "$rc" = 0 ] || fail "disable exited $rc: $out"
[ "$(grep -c '^npx ' "$MARKER")" = 2 ] || fail "disable did not push its own map"
grep -q '"status": "disabled"' "$TENANTS_DIR/acme.json" || fail "the registry was not quarantined"
# Kept for (g4): later checks run their own uploads over the same body file.
cp "$MARKER_BODY" "$WORK/body-after-disable"
ok "disable succeeds once the lock is free and pushes its own map"

# (f) and the quarantine is what an operator sees.
out="$(tenant show 2>&1)"; rc=$?
[ "$rc" = 0 ] || fail "show exited $rc: $out"
echo "$out" | grep -qE '^acme[[:space:]]+disabled' || fail "show does not report acme as disabled: $out"
ok "show reports acme as disabled"

# (g1) the owner's own lock is retained when the put stage dies without confirming: the upload
# it started is orphaned, not cancelled, and may already have been accepted.
rm -f "$MARKER.pid"
env "${TENANT_ENV[@]}" SHIM_SLEEP=6 bash "$TENANT" sync > "$WORK/sync-kill.log" 2>&1 &
BG=$!
put="$(wait_for_put)" || fail "could not determine the put pid: nothing was recorded under the lock: $(cat "$WORK/sync-kill.log")"
require_live "$put" put
wait_for_file "$MARKER.pid" || fail "could not determine the upload pid: the upload recorded none"
ORPHAN="$(shim_pid)"
require_live "$ORPHAN" upload
kill -9 "$put" || fail "could not kill the put stage (pid $put)"
wait "$BG"; rc=$?
BG=""
[ "$rc" != 0 ] || fail "a sync whose put was killed reported success: $(cat "$WORK/sync-kill.log")"
grep -q "was NOT updated" "$WORK/sync-kill.log" || fail "the killed put was not reported: $(cat "$WORK/sync-kill.log")"
grep -q "lock retained at" "$WORK/sync-kill.log" || fail "the lock was not retained: $(cat "$WORK/sync-kill.log")"
[ -d "$LOCK_DIR" ] || fail "the lock was released after the put was killed"
[ -e "$LOCK_DIR/upload.pending" ] || fail "the unconfirmed upload left no marker under the lock"
out="$(tenant disable acme 2>&1)"; rc=$?
[ "$rc" = 1 ] || fail "disable against a retained lock exited $rc, expected 1: $out"
case "$out" in *"another tenant.sh is running"*) ;; *) fail "disable was refused for the wrong reason: $out" ;; esac
wait_for_gone "$ORPHAN" || fail "the orphaned upload never finished"
ORPHAN=""
rm -rf "$LOCK_DIR"
ok "a put that is killed leaves the lock, and every other run, blocked until an operator clears it"

# (g2) an upload that ends 0 WITHOUT wrangler's success line is not a success: the exit code of
# the launcher is not evidence, and the lock stays.
out="$(env "${TENANT_ENV[@]}" SHIM_NO_SUCCESS=1 bash "$TENANT" sync 2>&1)"; rc=$?
[ "$rc" != 0 ] || fail "a sync with no success line reported success: $out"
case "$out" in *"upload NOT confirmed"*) ;; *) fail "the missing success line was not reported: $out" ;; esac
case "$out" in *"lock retained at"*) ;; *) fail "the lock was not retained without a success line: $out" ;; esac
[ -e "$LOCK_DIR/upload.pending" ] || fail "the unconfirmed upload left no marker under the lock"
rm -rf "$LOCK_DIR"
ok "an exit 0 without wrangler's success line is refused and keeps the lock"

# (g3) if the upload cannot be recorded under the lock, nothing is uploaded at all.
out="$(printf '{"acme":{}}' | env PATH="$SHIM:$PATH" MARKER="$WORK/marker-nolock" MARKER_BODY="$WORK/body-nolock" \
  TENANT_LOCK_DIR=/nonexistent/dir node "$SCRIPT_DIR/tenants-put.mjs" --env=lockcheck 2>&1)"; rc=$?
[ "$rc" = 1 ] || fail "the put stage exited $rc with an unusable lock directory, expected 1: $out"
case "$out" in *"cannot record the upload under the lock"*) ;; *) fail "the unusable lock directory was not reported: $out" ;; esac
[ ! -e "$WORK/marker-nolock" ] || fail "the upload started even though it could not be recorded"
ok "an upload that cannot be recorded under the lock is never started"

# (g4) what the operator asked for is what went up: the quarantine reached the upload body.
body_says "$WORK/body-after-disable" disabled || fail "the pushed map did not quarantine acme: $(cat "$WORK/body-after-disable")"
ok "the map the disable pushed carries the quarantine"

# (g5) an interrupt aimed at the put stage itself is deferred there too: the upload finishes,
# is confirmed, and only then does the run exit 143 — with the lock released.
env "${TENANT_ENV[@]}" SHIM_SLEEP=6 bash "$TENANT" sync > "$WORK/sync-put-term.log" 2>&1 &
BG=$!
put="$(wait_for_put)" || fail "could not determine the put pid: nothing was recorded under the lock: $(cat "$WORK/sync-put-term.log")"
require_live "$put" put
kill -TERM "$put" || fail "could not signal the put stage (pid $put)"
wait "$BG"; rc=$?
BG=""
[ "$rc" = 143 ] || fail "the sync exited $rc after its put was TERMed, expected 143: $(cat "$WORK/sync-put-term.log")"
grep -q "received; the upload in flight runs to completion first" "$WORK/sync-put-term.log" \
  || fail "the put stage did not defer the interrupt: $(cat "$WORK/sync-put-term.log")"
grep -q "an interrupt arrived after the put completed" "$WORK/sync-put-term.log" \
  || fail "the completed upload was not reported as completed: $(cat "$WORK/sync-put-term.log")"
[ "$(tail -n 1 "$MARKER")" = "done" ] || fail "the interrupted upload did not finish: $(cat "$MARKER")"
body_says "$MARKER_BODY" disabled || fail "the upload did not carry the map: $(cat "$MARKER_BODY")"
[ ! -d "$LOCK_DIR" ] || fail "the lock survived a confirmed upload"
ok "an interrupt aimed at the put stage still lets the upload finish, and the lock is released"

echo "tenant-lock-check: all checks passed"
