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
# It also holds the reporting to the same standard. What a sync says about an upload comes
# from the marker the put stage left under the lock, never from an exit code — confirmed,
# unknown, or never started — and a retained lock is cleared only by `unlock`, which refuses
# while the recorded upload can still be alive.
#
# Self-contained and offline: shims for `security`, `npx` and `wrangler` go FIRST on PATH, so
# no keychain item is read or written on any machine, no network call is made, and wrangler is
# never reached. The `npx` shim is shaped like the real launcher AND the process it launches:
# a launcher that ignores interrupts, and a separate uploader that drains the map off stdin,
# takes its time, and can OUTLIVE the launcher — which is the case that matters, because a
# launcher pid that dies first would otherwise report an upload as finished while the process
# talking to Cloudflare is still running. wrangler's success line is printed only when what
# arrived is a non-empty JSON object. The registry lives in a temp directory under
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
UPLOADER=""

cleanup() {
  # Nothing here may outlive the check: a stray shim sleep would look like a live upload.
  for p in "$BG" "$ORPHAN" "$UPLOADER"; do
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
uploader_pid() { cat "$MARKER.uploader.pid" 2>/dev/null; }
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

# A fake `npx`, shaped like the real launcher AND the uploader it launches. The launcher
# records its argv and its own pid (the check signals nothing it has not been told the pid
# of), IGNORES INT/TERM the way the real one swallows its child's signal death, and starts a
# background UPLOADER: a separate process, in the launcher's process group, which drains the
# map off stdin into $MARKER_BODY (so the check can assert WHAT was uploaded) and stays busy
# long enough to be observed mid-flight. Only a non-empty JSON object earns wrangler's success
# line — the one thing the put stage accepts as confirmation. SHIM_NO_SUCCESS=1 finishes
# without printing it.
#
# The split is what makes the launcher's death observable. The uploader's own streams go to
# /dev/null and its output is left in files that the launcher relays to ITS stdout on the way
# out, so the launcher holds the only copies of the pipes the put stage reads. With
# SHIM_LAUNCHER_DIES=1 the launcher exits the moment the uploader exists: the put stage sees
# both streams close and an exit 0 with no success line behind it, while the uploader is still
# running — a process group that is very much alive with nothing recorded in it left to wait
# for. That is the case `unlock` has to refuse.
cat > "$SHIM/npx" <<'SHIM_NPX'
#!/usr/bin/env bash
: "${MARKER:?tenant-lock-check: MARKER must be set}"
: "${MARKER_BODY:?tenant-lock-check: MARKER_BODY must be set}"
trap '' INT TERM
printf '%s\n' "$$" > "$MARKER.pid"
printf 'npx %s\n' "$*" >> "$MARKER"
: > "$MARKER.out"
: > "$MARKER.err"
# No job control in a non-interactive shell, so this stays in the launcher's process group —
# exactly like wrangler and its own children under the real launcher. The same absence of job
# control is why stdin has to be carried over on fd 3: bash points an asynchronous list's
# stdin at /dev/null before any explicit redirection, and the uploader is the process that has
# to drain the map.
exec 3<&0
(
  trap '' INT TERM
  cat <&3 > "$MARKER_BODY"
  sleep "${SHIM_SLEEP:-3}"
  if ! node -e '
const fs=require("fs");let m;
try{m=JSON.parse(fs.readFileSync(process.argv[1],"utf8"))}catch(e){process.exit(1)}
if(typeof m!=="object"||m===null||Array.isArray(m)||Object.keys(m).length===0)process.exit(1)' "$MARKER_BODY"; then
    printf 'shim: bad body\n' >> "$MARKER.err"
    exit 1
  fi
  if [ "${SHIM_NO_SUCCESS:-0}" != 1 ]; then
    printf '\xe2\x9c\xa8 Success! Uploaded secret TENANTS\n' >> "$MARKER.out"
  fi
  printf 'done\n' >> "$MARKER"
  exit 0
) >/dev/null 2>/dev/null &
up=$!
printf '%s\n' "$up" > "$MARKER.uploader.pid"
[ "${SHIM_LAUNCHER_DIES:-0}" != 1 ] || exit 0
wait "$up"; rc=$?
cat "$MARKER.out"
cat "$MARKER.err" >&2
exit "$rc"
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
# it started is orphaned, not cancelled, and may already have been accepted. So the sync must
# report the outcome as UNKNOWN — saying the map was "NOT updated" would send an operator away
# from a quarantine that might well be live — and the lock it leaves behind is cleared only by
# `unlock`, which refuses for as long as that orphan can still be talking to Cloudflare.
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
grep -q "outcome of the upload is UNKNOWN" "$WORK/sync-kill.log" \
  || fail "the killed put was not reported as an unknown outcome: $(cat "$WORK/sync-kill.log")"
if grep -q "started no upload and changed nothing" "$WORK/sync-kill.log"; then
  fail "the killed put was reported as having changed nothing: $(cat "$WORK/sync-kill.log")"
fi
grep -q "lock retained at" "$WORK/sync-kill.log" || fail "the lock was not retained: $(cat "$WORK/sync-kill.log")"
[ -d "$LOCK_DIR" ] || fail "the lock was released after the put was killed"
[ -e "$LOCK_DIR/upload.pending" ] || fail "the unconfirmed upload left no marker under the lock"
[ ! -e "$LOCK_DIR/upload.confirmed" ] || fail "a put that never confirmed left a confirmation behind"
out="$(tenant disable acme 2>&1)"; rc=$?
[ "$rc" = 1 ] || fail "disable against a retained lock exited $rc, expected 1: $out"
case "$out" in *"another tenant.sh is running"*) ;; *) fail "disable was refused for the wrong reason: $out" ;; esac
# The orphan is still sleeping, so the recovery must not run yet: clearing the lock now is the
# interleaving the lock exists to prevent, with the orphan's older map landing last.
out="$(tenant unlock 2>&1)"; rc=$?
[ "$rc" = 1 ] || fail "unlock while the upload was still alive exited $rc, expected 1: $out"
case "$out" in *"process group"*"is still alive"*) ;; *) fail "unlock was refused for the wrong reason: $out" ;; esac
[ -d "$LOCK_DIR" ] || fail "unlock cleared the lock while the upload was still alive"
wait_for_gone "$ORPHAN" || fail "the orphaned upload never finished"
ORPHAN=""
out="$(tenant unlock 2>&1)"; rc=$?
[ "$rc" = 0 ] || fail "unlock exited $rc once no upload could still be running: $out"
case "$out" in *"lock cleared"*) ;; *) fail "unlock did not report clearing the lock: $out" ;; esac
[ ! -d "$LOCK_DIR" ] || fail "unlock left the lock directory behind"
# And the re-sync the recovery calls for goes through, leaving no marker behind it.
out="$(tenant sync 2>&1)"; rc=$?
[ "$rc" = 0 ] || fail "the re-sync after unlock exited $rc: $out"
case "$out" in *"done. Secrets take effect"*) ;; *) fail "the re-sync did not report a confirmed upload: $out" ;; esac
[ ! -e "$LOCK_DIR/upload.confirmed" ] || fail "the re-sync left its confirmation behind"
[ ! -d "$LOCK_DIR" ] || fail "the re-sync left its lock behind"
ok "a killed put reports an UNKNOWN outcome and keeps the lock; unlock refuses while the upload lives, then clears it and the re-sync goes through"

# (g2) an upload that ends 0 WITHOUT wrangler's success line is not a success: the exit code of
# the launcher is not evidence, and the lock stays.
out="$(env "${TENANT_ENV[@]}" SHIM_NO_SUCCESS=1 bash "$TENANT" sync 2>&1)"; rc=$?
[ "$rc" != 0 ] || fail "a sync with no success line reported success: $out"
case "$out" in *"upload NOT confirmed"*) ;; *) fail "the missing success line was not reported: $out" ;; esac
case "$out" in *"outcome of the upload is UNKNOWN"*) ;; *) fail "the missing success line was not reported as an unknown outcome: $out" ;; esac
case "$out" in *"lock retained at"*) ;; *) fail "the lock was not retained without a success line: $out" ;; esac
[ -e "$LOCK_DIR/upload.pending" ] || fail "the unconfirmed upload left no marker under the lock"
[ ! -e "$LOCK_DIR/upload.confirmed" ] || fail "an upload with no success line left a confirmation behind"
out="$(tenant unlock 2>&1)"; rc=$?
[ "$rc" = 0 ] || fail "unlock exited $rc once the unconfirmed upload was gone: $out"
[ ! -d "$LOCK_DIR" ] || fail "unlock left the lock directory behind"
ok "an exit 0 without wrangler's success line is refused, keeps the lock, and unlock clears it"

# (g3) if the upload cannot be recorded under the lock, nothing is uploaded at all. The lock
# here is this run's own — the owner token matches — and only the marker is unwritable: a
# directory sits where the file has to go, which fails the write for any user, root included.
mkdir -p "$WORK/lock-nowrite/upload.pending"
printf '%s\n' aaaa > "$WORK/lock-nowrite/owner"
out="$(printf '{"acme":{}}' | env PATH="$SHIM:$PATH" MARKER="$WORK/marker-nolock" MARKER_BODY="$WORK/body-nolock" \
  TENANT_LOCK_DIR="$WORK/lock-nowrite" TENANT_LOCK_TOKEN=aaaa node "$SCRIPT_DIR/tenants-put.mjs" --env=lockcheck 2>&1)"; rc=$?
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

# (g6) an interrupt that arrives before the map has finished coming down the pipe is deferred
# too. The handlers go on first thing, ahead of stdin: installed any later, a TERM in that
# window would kill the put stage outright — no upload started, no marker, and an exit code
# upstream that looks like an interrupt over an upload that never existed.
mkdir -p "$WORK/lock-early"
printf '%s\n' early-token > "$WORK/lock-early/owner"
( sleep 2; printf '{"acme":{}}' ) | env PATH="$SHIM:$PATH" \
    MARKER="$WORK/marker-early" MARKER_BODY="$WORK/body-early" SHIM_SLEEP=1 \
    TENANT_LOCK_DIR="$WORK/lock-early" TENANT_LOCK_TOKEN=early-token \
    node "$SCRIPT_DIR/tenants-put.mjs" --env=lockcheck \
    > "$WORK/early.log" 2>&1 &
BG=$!
sleep 0.5
kill -0 "$BG" 2>/dev/null || fail "the put stage was gone before its input arrived: $(cat "$WORK/early.log")"
kill -TERM "$BG" || fail "could not signal the put stage (pid $BG)"
wait "$BG"; rc=$?
BG=""
[ "$rc" = 143 ] || fail "the put stage exited $rc after a TERM that arrived before its input, expected 143: $(cat "$WORK/early.log")"
grep -q "received; the upload in flight runs to completion first" "$WORK/early.log" \
  || fail "the early interrupt was not deferred: $(cat "$WORK/early.log")"
[ -e "$WORK/marker-early" ] || fail "the upload never started after the early interrupt: $(cat "$WORK/early.log")"
[ "$(tail -n 1 "$WORK/marker-early")" = "done" ] || fail "the upload did not finish: $(cat "$WORK/marker-early")"
[ -e "$WORK/lock-early/upload.confirmed" ] || fail "the completed upload was not recorded as confirmed"
[ ! -e "$WORK/lock-early/upload.pending" ] || fail "a confirmed upload left its pending marker behind"
ok "a TERM that lands before the map does is deferred, and the upload still runs and is confirmed"

# (g7) wrangler's log level is pinned on the child alongside its log sanitizing. At warn, error
# or none wrangler uploads and lands the secret exactly as before — the only thing that changes
# is that the success line is suppressed, so an inherited WRANGLER_LOG would turn every good
# upload into an unconfirmed one and keep the lock over it.
ENVPIN="$WORK/envpin"
mkdir -p "$ENVPIN"
printf '#!/bin/sh\necho "SANITIZE=$WRANGLER_LOG_SANITIZE WRITE_LOGS=$WRANGLER_WRITE_LOGS LOG=$WRANGLER_LOG"\necho "Success! Uploaded secret TENANTS"\n' > "$ENVPIN/npx"
chmod +x "$ENVPIN/npx"
out="$(printf '{"acme":{}}' | env PATH="$ENVPIN:$PATH" WRANGLER_LOG_SANITIZE=false WRANGLER_WRITE_LOGS=true \
  WRANGLER_LOG=none node "$SCRIPT_DIR/tenants-put.mjs" --env=lockcheck 2>&1)"; rc=$?
[ "$rc" = 0 ] || fail "the put stage exited $rc against the environment stand-in: $out"
case "$out" in *"SANITIZE=true WRITE_LOGS=false LOG=log"*) ;; *) fail "wrangler's environment was not pinned: $out" ;; esac
ok "wrangler's log sanitizing and its log level are pinned on the child whatever the operator's shell sets"

# (g8) the success line is matched over everything that arrives, not just the last bytes of it.
# wrangler writes its own notices right behind the confirmation, and output that carries both in
# ONE write is what a short tail window silently drops: a landed upload reported as unconfirmed,
# with the lock kept over it and a re-sync asked for that was never needed.
COALESCE="$WORK/coalesce"
mkdir -p "$COALESCE" "$WORK/lock-coalesce"
cat > "$COALESCE/npx" <<'SHIM_COALESCE'
#!/usr/bin/env bash
cat >/dev/null
printf '\xe2\x9c\xa8 Success! Uploaded secret TENANTS\n%s\n' "$(head -c 600 /dev/zero | tr '\0' x)"
exit 0
SHIM_COALESCE
chmod +x "$COALESCE/npx"
printf '%s\n' coalesce-token > "$WORK/lock-coalesce/owner"
out="$(printf '{"acme":{}}' | env PATH="$COALESCE:$PATH" TENANT_LOCK_DIR="$WORK/lock-coalesce" \
  TENANT_LOCK_TOKEN=coalesce-token node "$SCRIPT_DIR/tenants-put.mjs" --env=lockcheck 2>&1)"; rc=$?
[ "$rc" = 0 ] || fail "a success line with 600 bytes behind it in one write exited $rc: $out"
[ -e "$WORK/lock-coalesce/upload.confirmed" ] || fail "the coalesced confirmation was not recorded"
ok "a success line coalesced into one write with 600 bytes behind it is still read as confirmation"

# (g9) the third outcome, and the only one that may say this run changed nothing: the pipeline
# refuses before the put stage starts an upload at all. It is a claim about THIS RUN and
# nothing more — what the Worker is actually serving cannot be read back, so a refusal must
# not promise that the previous map is still accepted. The uploader must not have been
# reached: the marker written under the lock at startup is removed again on the refusal, and
# neither the invocation count nor the body the last upload carried may move.
npx_before="$(grep -c '^npx ' "$MARKER")"
done_before="$(grep -c '^done$' "$MARKER")"
cp "$MARKER_BODY" "$WORK/body-before-refusal"
printf '%s\n' '{"org_id":"badkey","status":"active","trustedOperators":["not-a-key"]}' > "$TENANTS_DIR/badkey.json"
out="$(tenant sync 2>&1)"; rc=$?
rm -f "$TENANTS_DIR/badkey.json"
[ "$rc" != 0 ] || fail "a sync the validator refused reported success: $out"
case "$out" in *"started no upload and changed nothing"*) ;; *) fail "the refusal did not report that this run started no upload: $out" ;; esac
case "$out" in *"STILL ACCEPTED"*) fail "the refusal claimed the previous map is still accepted, which the write-only secret cannot establish: $out" ;; *) ;; esac
case "$out" in *"outcome of the upload is UNKNOWN"*) fail "a refusal that started no upload was reported as an unknown outcome: $out" ;; *) ;; esac
[ "$(grep -c '^npx ' "$MARKER")" = "$npx_before" ] || fail "a refusal that started no upload still invoked the uploader: $out"
[ "$(grep -c '^done$' "$MARKER")" = "$done_before" ] || fail "a refusal that started no upload still completed an upload: $out"
cmp -s "$WORK/body-before-refusal" "$MARKER_BODY" || fail "a refusal that started no upload changed the map the last upload carried"
[ ! -e "$LOCK_DIR/upload.pending" ] || fail "a refusal that started no upload left a marker under the lock"
[ ! -e "$LOCK_DIR/upload.confirmed" ] || fail "a refusal that started no upload left a confirmation under the lock"
[ ! -d "$LOCK_DIR" ] || fail "the lock was not released after a refusal that started no upload"
ok "a validator refusal starts no upload, leaves the uploader untouched, and says only that this run changed nothing"

# (g10) the launcher is not the upload. Kill it — here it exits on its own the instant the
# uploader exists — and a pid-based check sees nothing left to wait for while the process that
# is actually talking to Cloudflare runs on. The put stage gets an exit 0 with no success line
# behind it, so the outcome is UNKNOWN and the lock is retained; and `unlock` must refuse for
# as long as the upload's PROCESS GROUP has any member alive, which is the only thing that
# still answers for the survivor.
rm -f "$MARKER.pid" "$MARKER.uploader.pid"
out="$(env "${TENANT_ENV[@]}" SHIM_LAUNCHER_DIES=1 SHIM_SLEEP=6 bash "$TENANT" sync 2>&1)"; rc=$?
UPLOADER="$(uploader_pid)"
[ "$rc" != 0 ] || fail "a sync whose launcher died before the upload reported success: $out"
case "$out" in *"upload NOT confirmed"*) ;; *) fail "the dead launcher was not reported as unconfirmed: $out" ;; esac
case "$out" in *"outcome of the upload is UNKNOWN"*) ;; *) fail "the dead launcher was not reported as an unknown outcome: $out" ;; esac
[ -e "$LOCK_DIR/upload.pending" ] || fail "the surviving upload left no marker under the lock"
grep -q '^pgid ' "$LOCK_DIR/upload.pending" || fail "the upload's process group was not recorded: $(cat "$LOCK_DIR/upload.pending")"
require_live "$UPLOADER" uploader
out="$(tenant unlock 2>&1)"; rc=$?
[ "$rc" = 1 ] || fail "unlock while the uploader outlived its launcher exited $rc, expected 1: $out"
case "$out" in *"process group"*"is still alive"*) ;; *) fail "unlock was refused for the wrong reason: $out" ;; esac
[ -d "$LOCK_DIR" ] || fail "unlock cleared the lock while the uploader was still alive"
wait_for_gone "$UPLOADER" || fail "the surviving uploader never finished"
UPLOADER=""
out="$(tenant unlock 2>&1)"; rc=$?
[ "$rc" = 0 ] || fail "unlock exited $rc once the upload's process group was empty: $out"
[ ! -d "$LOCK_DIR" ] || fail "unlock left the lock directory behind"
ok "an uploader that outlives its launcher keeps the lock, and unlock refuses until its process group is empty"

# (g11) two unlocks are their own race: both would pass the checks, one pauses, the other
# clears the lock and a waiting sync takes a NEW one at the same path — and the paused unlock
# then deletes that new owner's lock and the evidence under it. unlock serialises against
# itself so the second never gets as far as looking.
mkdir -p "$LOCK_DIR"
printf '%s\n' held-token > "$LOCK_DIR/owner"
mkdir "$TENANTS_DIR/.unlock"
out="$(tenant unlock 2>&1)"; rc=$?
[ "$rc" = 1 ] || fail "a second concurrent unlock exited $rc, expected 1: $out"
case "$out" in *"another unlock is running"*) ;; *) fail "the second unlock was refused for the wrong reason: $out" ;; esac
[ -d "$LOCK_DIR" ] || fail "a second concurrent unlock cleared the lock anyway"
[ -e "$LOCK_DIR/owner" ] || fail "a second concurrent unlock removed the lock owner"
rmdir "$TENANTS_DIR/.unlock"
out="$(tenant unlock 2>&1)"; rc=$?
[ "$rc" = 0 ] || fail "unlock exited $rc once no other unlock was running: $out"
[ ! -d "$LOCK_DIR" ] || fail "unlock left the lock directory behind"
ok "a second concurrent unlock is refused while the first holds the mutex, and goes through once it does not"

# (g12) a replacement lock is a different lock. `unlock` followed by a new `sync` puts a fresh
# directory at exactly the same path, so a stage still holding the old path must not write into
# it, let alone start an upload under it. The owner token is checked before stdin is read.
mkdir -p "$WORK/lock-replaced"
printf '%s\n' aaaa > "$WORK/lock-replaced/owner"
out="$(printf '{"acme":{}}' | env PATH="$SHIM:$PATH" MARKER="$WORK/marker-replaced" MARKER_BODY="$WORK/body-replaced" \
  TENANT_LOCK_DIR="$WORK/lock-replaced" TENANT_LOCK_TOKEN=bbbb node "$SCRIPT_DIR/tenants-put.mjs" --env=lockcheck 2>&1)"; rc=$?
[ "$rc" = 1 ] || fail "the put stage exited $rc against a lock it does not own, expected 1: $out"
case "$out" in *"owner mismatch"*) ;; *) fail "the replacement lock was not reported as a mismatch: $out" ;; esac
case "$out" in *"nothing was started"*) ;; *) fail "the refusal did not say that nothing was started: $out" ;; esac
[ ! -e "$WORK/lock-replaced/upload.pending" ] || fail "a run that does not own the lock still wrote a marker into it"
[ ! -e "$WORK/marker-replaced" ] || fail "a run that does not own the lock still reached the uploader"
[ "$(cat "$WORK/lock-replaced/owner")" = aaaa ] || fail "a run that does not own the lock overwrote its owner"
ok "a put stage whose lock was replaced under it refuses before it reads the map, and touches nothing"

# (g13) tracking that was never completed is not permission to clear the lock. A marker with no
# process group in it means an upload may be running that nothing here can see — the put stage
# died between recording itself and starting the upload, or the rewrite that records the group
# failed — so only an operator who has looked may say otherwise, with --force.
deadpid=999999
while kill -0 "$deadpid" 2>/dev/null; do deadpid=$((deadpid + 1)); done
mkdir -p "$LOCK_DIR"
printf '%s\n' stale-token > "$LOCK_DIR/owner"
printf 'owner stale-token\nstarting\nput %s\n' "$deadpid" > "$LOCK_DIR/upload.pending"
out="$(tenant unlock 2>&1)"; rc=$?
[ "$rc" = 1 ] || fail "unlock over incomplete tracking exited $rc, expected 1: $out"
case "$out" in *"process group was never recorded"*) ;; *) fail "incomplete tracking was refused for the wrong reason: $out" ;; esac
case "$out" in *"--force"*) ;; *) fail "the refusal did not name --force: $out" ;; esac
[ -d "$LOCK_DIR" ] || fail "unlock cleared a lock whose tracking was never completed"
out="$(tenant unlock --force 2>&1)"; rc=$?
[ "$rc" = 0 ] || fail "unlock --force exited $rc over incomplete tracking: $out"
case "$out" in *"lock cleared"*) ;; *) fail "unlock --force did not report clearing the lock: $out" ;; esac
[ ! -d "$LOCK_DIR" ] || fail "unlock --force left the lock directory behind"
out="$(tenant unlock --nonsense 2>&1)"; rc=$?
[ "$rc" = 1 ] || fail "unlock with an unknown argument exited $rc, expected 1: $out"
case "$out" in *"unknown argument"*) ;; *) fail "unlock accepted an unknown argument: $out" ;; esac
ok "a lock whose upload was never fully recorded is cleared only with --force, and unlock refuses any other argument"

# (g14) the window the owner token in the MARKER closes: the put stage reads the lock's owner,
# and only then writes its marker. In between, its shell being dead, an `unlock` can clear the
# lock and a fresh `sync` can take a replacement at the same path — and the orphan, already
# past its check, drops a stale marker into the new owner's lock. Tracking that names a run
# nobody is waiting for must never read as the new owner's own, or its `unlock` would clear a
# lock on the strength of pids that prove nothing.
mkdir -p "$LOCK_DIR"
printf '%s\n' bbbb > "$LOCK_DIR/owner"
printf 'owner aaaa\nstarting\nput %s\npgid %s\n' "$deadpid" "$deadpid" > "$LOCK_DIR/upload.pending"
out="$(tenant unlock 2>&1)"; rc=$?
[ "$rc" = 1 ] || fail "unlock over a marker belonging to another run exited $rc, expected 1: $out"
case "$out" in *"belongs to another run"*) ;; *) fail "the stale marker was refused for the wrong reason: $out" ;; esac
case "$out" in *"--force"*) ;; *) fail "the refusal did not name --force: $out" ;; esac
[ -d "$LOCK_DIR" ] || fail "unlock cleared a lock on the strength of another run's marker"
out="$(tenant unlock --force 2>&1)"; rc=$?
[ "$rc" = 0 ] || fail "unlock --force exited $rc over a stale marker: $out"
[ ! -d "$LOCK_DIR" ] || fail "unlock --force left the lock directory behind"
ok "a marker stamped with another lock's token is refused as stale and cleared only with --force"

# (g15) and the other side of the same window: a marker is created EXCLUSIVELY, so a put stage
# arriving at a lock that already has one starts nothing rather than overwriting the tracking
# that is there.
mkdir -p "$WORK/lock-taken"
printf '%s\n' g15-token > "$WORK/lock-taken/owner"
printf 'owner g15-token\nstarting\nput %s\npgid %s\n' "$deadpid" "$deadpid" > "$WORK/lock-taken/upload.pending"
cp "$WORK/lock-taken/upload.pending" "$WORK/lock-taken-marker.before"
out="$(printf '{"acme":{}}' | env PATH="$SHIM:$PATH" MARKER="$WORK/marker-taken" MARKER_BODY="$WORK/body-taken" \
  TENANT_LOCK_DIR="$WORK/lock-taken" TENANT_LOCK_TOKEN=g15-token node "$SCRIPT_DIR/tenants-put.mjs" --env=lockcheck 2>&1)"; rc=$?
[ "$rc" = 1 ] || fail "the put stage exited $rc against a lock that already has a marker, expected 1: $out"
case "$out" in *"already recorded"*) ;; *) fail "the existing marker was not reported: $out" ;; esac
case "$out" in *"nothing was started"*) ;; *) fail "the refusal did not say that nothing was started: $out" ;; esac
[ ! -e "$WORK/marker-taken" ] || fail "a put stage that found a marker already there still reached the uploader"
cmp -s "$WORK/lock-taken-marker.before" "$WORK/lock-taken/upload.pending" || fail "the existing marker was overwritten: $(cat "$WORK/lock-taken/upload.pending")"
ok "a marker already under the lock is never overwritten, and the put stage starts nothing"

echo "tenant-lock-check: all checks passed"
