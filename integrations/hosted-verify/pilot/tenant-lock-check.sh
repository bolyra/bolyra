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
# unknown, or never started. A retained lock has no automatic recovery at all: it blocks every
# later run for this environment, whatever its age, until an operator has established local
# quiescence and removed it by hand (pilot/RUNBOOK.md, "Recovering a retained lock"). That
# manual removal is what the checks below perform where a recovery is needed.
#
# Self-contained and offline: shims for `security`, `npx` and `wrangler` go FIRST on PATH, so
# no keychain item is read or written on any machine, no network call is made, and wrangler is
# never reached. The `npx` shim is shaped like the real launcher AND the process it launches:
# a launcher that ignores interrupts, and a separate uploader that drains the map off stdin,
# takes its time, and can OUTLIVE the launcher. wrangler's success line is printed only when
# what arrived is a JSON object (`{}` included: whether an empty map may go up at all is the
# put stage's decision, under --allow-empty, and the E13 checks below assert it). The
# registry lives in a temp directory under HOSTED_VERIFY_ENV=lockcheck.
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
# The check has to reach INTO a running sync to signal one of its processes, so it needs that
# process's pid — and it only ever signals a pid it was TOLD, never one it guessed from a
# process list: any ancestor or bystander whose command line happens to mention these files
# matches a name search too, and the signal lands on the wrong process (in a container the
# `sh -c` at pid 1 matched first, ignored the kill, and the check passed vacuously). Two
# sources only: `$!` for something this check started itself, and files the check's own shims
# write. The launcher shim is spawned by the put stage, so its $PPID IS the put stage.
put_pid()  { cat "$MARKER.put.pid" 2>/dev/null; }
wait_for_put() {  # echo the put stage's pid, as its launcher recorded it — poll for up to 5 s
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

KEYCHAIN="$WORK/keychain"
mkdir -p "$SHIM" "$TENANTS_DIR" "$KEYCHAIN"

# A fake `security`: tokens are derived from the account name, so they are deterministic,
# distinct per role (the validator refuses a repeated token) and never touch a keychain. The
# keychain itself is a directory ($SHIM_KEYCHAIN) holding one empty file per account, so a check
# can assert which items exist after a run: find answers 44 (errSecItemNotFound) for an account
# with no file, add creates it, delete removes it. Knobs, all off by default:
#   SHIM_FIND_SLEEP=<s>   a presence lookup (find without -w) touches $SHIM_KEYCHAIN.find-started
#                         and sleeps first — a window in which the shell is running `security`
#   SHIM_FINDW_SLEEP=<s>  a token read (find -w) touches $SHIM_KEYCHAIN.findw-started and sleeps
#                         first — a window inside the sync pipeline, before the put stage has input
#   SHIM_DELETE_FAIL=1    delete fails (the keychain refusing it) and removes nothing
#   SHIM_DELETE_MISSING=1 the item vanishes just before the delete (someone else removed it),
#                         so delete answers 44 (errSecItemNotFound)
cat > "$SHIM/security" <<'SHIM_SECURITY'
#!/usr/bin/env bash
: "${SHIM_KEYCHAIN:?tenant-lock-check: SHIM_KEYCHAIN must be set}"
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
[ -n "$acct" ] || exit 1
case "$cmd" in
  find-generic-password)
    if [ "$want_w" = 1 ]; then
      if [ -n "${SHIM_FINDW_SLEEP:-}" ]; then : > "$SHIM_KEYCHAIN.findw-started"; sleep "$SHIM_FINDW_SLEEP"; fi
    else
      if [ -n "${SHIM_FIND_SLEEP:-}" ]; then : > "$SHIM_KEYCHAIN.find-started"; sleep "$SHIM_FIND_SLEEP"; fi
    fi
    [ -e "$SHIM_KEYCHAIN/$acct" ] || exit 44
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
    : > "$SHIM_KEYCHAIN/$acct"
    exit 0 ;;
  delete-generic-password)
    if [ "${SHIM_DELETE_FAIL:-0}" = 1 ]; then
      echo "security: SecKeychainItemDelete: shim: the keychain refused the delete" >&2
      exit 1
    fi
    if [ "${SHIM_DELETE_MISSING:-0}" = 1 ]; then rm -f "$SHIM_KEYCHAIN/$acct"; fi
    if [ ! -e "$SHIM_KEYCHAIN/$acct" ]; then
      echo "security: SecKeychainSearchCopyNext: The specified item could not be found in the keychain." >&2
      exit 44
    fi
    rm -f "$SHIM_KEYCHAIN/$acct"
    exit 0 ;;
esac
exit 1
SHIM_SECURITY

# A fake `npx`, shaped like the real launcher AND the uploader it launches. The launcher
# records its argv, its own pid and its PARENT's (the put stage that spawned it — the check
# signals nothing it has not been told the pid of), IGNORES INT/TERM the way the real one
# swallows its child's signal death, and starts a background UPLOADER: a separate process, in
# the launcher's process group, which drains the map off stdin into $MARKER_BODY (so the check
# can assert WHAT was uploaded) and stays busy long enough to be observed mid-flight. Only a
# JSON object earns wrangler's success line — the one thing the put stage accepts as
# confirmation. SHIM_NO_SUCCESS=1 finishes without printing it.
#
# The split matters because the uploader can outlive its launcher: its own streams go to
# /dev/null and its output is left in files that the launcher relays to ITS stdout on the way
# out, so the launcher holds the only copies of the pipes the put stage reads.
cat > "$SHIM/npx" <<'SHIM_NPX'
#!/usr/bin/env bash
: "${MARKER:?tenant-lock-check: MARKER must be set}"
: "${MARKER_BODY:?tenant-lock-check: MARKER_BODY must be set}"
trap '' INT TERM
printf '%s\n' "$$" > "$MARKER.pid"
printf '%s\n' "$PPID" > "$MARKER.put.pid"
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
if(typeof m!=="object"||m===null||Array.isArray(m))process.exit(1)' "$MARKER_BODY"; then
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
kc_seed() { : > "$KEYCHAIN/tenant-$1-admin"; : > "$KEYCHAIN/tenant-$1-verifier"; }
kc_seed acme

# Every tenant.sh call in this check runs with the shims first on PATH and with the temp
# registry; nothing reads the operator's own environment.
TENANT_ENV=(PATH="$SHIM:$PATH" SHIM_KEYCHAIN="$KEYCHAIN" HOSTED_VERIFY_ENV=lockcheck TENANTS_DIR="$TENANTS_DIR" MARKER="$MARKER" MARKER_BODY="$MARKER_BODY" SHIM_SLEEP="$SHIM_SLEEP")
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
require_live "$BG" sync
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

# (g1) the lock is retained when the put stage is killed outright: the upload it started is
# orphaned, not cancelled, and may already have been accepted, so the honest answer is that
# the outcome is unknown. The put stage is run DIRECTLY here, under a lock this check holds
# for it, because a SIGKILL has to land on that process and nothing else. What follows is the
# whole of the recovery: the retained lock refuses the next run whatever its age, and it is
# removed by hand — as the runbook says, once nothing can still be uploading — before the
# re-sync goes through.
mkdir -p "$LOCK_DIR"
printf '{"acme":{}}' | env PATH="$SHIM:$PATH" MARKER="$WORK/marker-kill" MARKER_BODY="$WORK/body-kill" \
  SHIM_SLEEP=6 TENANT_LOCK_DIR="$LOCK_DIR" node "$SCRIPT_DIR/tenants-put.mjs" --env=lockcheck \
  > "$WORK/kill.log" 2>&1 &
BG=$!
wait_for_file "$WORK/body-kill" || fail "the upload never started: $(cat "$WORK/kill.log")"
wait_for_file "$WORK/marker-kill.uploader.pid" || fail "could not determine the upload pid: the upload recorded none"
ORPHAN="$(cat "$WORK/marker-kill.uploader.pid" 2>/dev/null)"
require_live "$ORPHAN" upload
require_live "$BG" put
[ -e "$LOCK_DIR/upload.pending" ] || fail "the upload was not recorded under the lock before it started"
kill -9 "$BG" || fail "could not kill the put stage (pid $BG)"
# The shell announces a background job that died from a signal, echoing the whole command
# line back at the operator. That report is the expected outcome here, not news.
{ wait "$BG"; rc=$?; } 2>/dev/null
BG=""
[ "$rc" = 0 ] && fail "a put stage that was killed reported success: $(cat "$WORK/kill.log")"
[ -e "$LOCK_DIR/upload.pending" ] || fail "the unconfirmed upload left no marker under the lock"
[ ! -e "$LOCK_DIR/upload.confirmed" ] || fail "a put that never confirmed left a confirmation behind"
# The retained lock blocks the next run, with no regard for how old it is.
out="$(tenant sync 2>&1)"; rc=$?
[ "$rc" = 1 ] || fail "a sync against a retained lock exited $rc, expected 1: $out"
case "$out" in *"another tenant.sh is running"*) ;; *) fail "the sync was refused for the wrong reason: $out" ;; esac
case "$out" in *'Recovering a retained lock'*) ;; *) fail "the refusal did not name the runbook's recovery section: $out" ;; esac
[ -d "$LOCK_DIR" ] || fail "a refused run removed the retained lock"
# The orphan is still sleeping: the recovery must not start until it cannot be uploading.
wait_for_gone "$ORPHAN" || fail "the orphaned upload never finished"
ORPHAN=""
rm -rf "$LOCK_DIR"
out="$(tenant sync 2>&1)"; rc=$?
[ "$rc" = 0 ] || fail "the re-sync after the lock was removed by hand exited $rc: $out"
case "$out" in *"done. Secrets take effect"*) ;; *) fail "the re-sync did not report a confirmed upload: $out" ;; esac
[ ! -e "$LOCK_DIR/upload.confirmed" ] || fail "the re-sync left its confirmation behind"
[ ! -d "$LOCK_DIR" ] || fail "the re-sync left its lock behind"
ok "a killed put keeps the lock and its evidence, the lock then refuses every later run, and the hand recovery plus re-sync goes through"

# (g2) an upload that ends 0 WITHOUT wrangler's success line is not a success: the exit code of
# the launcher is not evidence, and the lock stays.
out="$(env "${TENANT_ENV[@]}" SHIM_NO_SUCCESS=1 bash "$TENANT" sync 2>&1)"; rc=$?
[ "$rc" != 0 ] || fail "a sync with no success line reported success: $out"
case "$out" in *"upload NOT confirmed"*) ;; *) fail "the missing success line was not reported: $out" ;; esac
case "$out" in *"outcome of the upload is UNKNOWN"*) ;; *) fail "the missing success line was not reported as an unknown outcome: $out" ;; esac
case "$out" in *"lock retained at"*) ;; *) fail "the lock was not retained without a success line: $out" ;; esac
case "$out" in *'Recovering a retained lock'*) ;; *) fail "the retained lock did not name the runbook's recovery section: $out" ;; esac
[ -e "$LOCK_DIR/upload.pending" ] || fail "the unconfirmed upload left no marker under the lock"
[ ! -e "$LOCK_DIR/upload.confirmed" ] || fail "an upload with no success line left a confirmation behind"
rm -rf "$LOCK_DIR"
ok "an exit 0 without wrangler's success line is refused and keeps the lock until it is removed by hand"

# (g3) if the upload cannot be recorded under the lock, nothing is uploaded at all. Only the
# marker is unwritable: a directory sits where the file has to go, which fails the write for
# any user, root included.
mkdir -p "$WORK/lock-nowrite/upload.pending"
out="$(printf '{"acme":{}}' | env PATH="$SHIM:$PATH" MARKER="$WORK/marker-nolock" MARKER_BODY="$WORK/body-nolock" \
  TENANT_LOCK_DIR="$WORK/lock-nowrite" node "$SCRIPT_DIR/tenants-put.mjs" --env=lockcheck 2>&1)"; rc=$?
[ "$rc" = 1 ] || fail "the put stage exited $rc with an unusable lock directory, expected 1: $out"
case "$out" in *"cannot record the upload under the lock"*) ;; *) fail "the unusable lock directory was not reported: $out" ;; esac
[ ! -e "$WORK/marker-nolock" ] || fail "the upload started even though it could not be recorded"
ok "an upload that cannot be recorded under the lock is never started"

# (g4) what the operator asked for is what went up: the quarantine reached the upload body.
body_says "$WORK/body-after-disable" disabled || fail "the pushed map did not quarantine acme: $(cat "$WORK/body-after-disable")"
ok "the map the disable pushed carries the quarantine"

# (g5) an interrupt aimed at the put stage itself is deferred there too: the upload finishes,
# is confirmed, and only then does the run exit 143 — with the lock released.
rm -f "$MARKER.put.pid"
env "${TENANT_ENV[@]}" SHIM_SLEEP=6 bash "$TENANT" sync > "$WORK/sync-put-term.log" 2>&1 &
BG=$!
put="$(wait_for_put)" || fail "could not determine the put pid: its launcher recorded none: $(cat "$WORK/sync-put-term.log")"
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

# (g6) an interrupt that arrives before the map has finished coming down the pipe CANCELS the
# upload rather than deferring it: nothing has been started yet, so the only honest outcome is
# "not started" — wrangler is never spawned, no marker is written under the lock, and the put
# stage exits 75 (EX_TEMPFAIL), which tenant.sh reads as "interrupted before the upload started".
# The handlers still go on first thing, ahead of stdin: installed any later, a signal in that
# window would kill the put stage outright with no report at all.
mkdir -p "$WORK/lock-early"
( sleep 2; printf '{"acme":{}}' ) | env PATH="$SHIM:$PATH" \
    MARKER="$WORK/marker-early" MARKER_BODY="$WORK/body-early" SHIM_SLEEP=1 \
    TENANT_LOCK_DIR="$WORK/lock-early" \
    node "$SCRIPT_DIR/tenants-put.mjs" --env=lockcheck \
    > "$WORK/early.log" 2>&1 &
BG=$!
sleep 0.5
require_live "$BG" put
kill -INT "$BG" || fail "could not signal the put stage (pid $BG)"
wait "$BG"; rc=$?
BG=""
[ "$rc" = 75 ] || fail "the put stage exited $rc after a SIGINT that arrived before its input, expected 75: $(cat "$WORK/early.log")"
grep -q "interrupted before the upload started; wrangler was NOT started" "$WORK/early.log" \
  || fail "the early interrupt was not reported as a cancelled upload: $(cat "$WORK/early.log")"
[ ! -e "$WORK/marker-early" ] || fail "wrangler was spawned after an interrupt that arrived before the map: $(cat "$WORK/marker-early")"
[ ! -e "$WORK/lock-early/upload.pending" ] || fail "a cancelled upload left a pending marker under the lock"
[ ! -e "$WORK/lock-early/upload.confirmed" ] || fail "a cancelled upload left a confirmation under the lock"
ok "a SIGINT that lands before the map does cancels the upload: exit 75, wrangler never spawned, no marker"

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
out="$(printf '{"acme":{}}' | env PATH="$COALESCE:$PATH" TENANT_LOCK_DIR="$WORK/lock-coalesce" \
  node "$SCRIPT_DIR/tenants-put.mjs" --env=lockcheck 2>&1)"; rc=$?
[ "$rc" = 0 ] || fail "a success line with 600 bytes behind it in one write exited $rc: $out"
[ -e "$WORK/lock-coalesce/upload.confirmed" ] || fail "the coalesced confirmation was not recorded"
ok "a success line coalesced into one write with 600 bytes behind it is still read as confirmation"

# (g9) the third outcome, and the only one that may say this run changed nothing: the pipeline
# refuses before the put stage starts an upload at all. It is a claim about THIS RUN and
# nothing more — what the Worker is actually serving cannot be read back, so a refusal must
# not promise that the previous map is still accepted. The uploader must not have been
# reached: no marker is written under the lock at all, and neither the invocation count nor
# the body the last upload carried may move.
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

# ---- remove (T10): tokens are deleted only after the upload that drops the tenant is
# confirmed. A second tenant, beta, is the one removed — acme stays, so the map is never empty.
status_of() { node -e 'process.stdout.write(String(JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")).status))' "$TENANTS_DIR/$1.json"; }
kc_count() { local n=0; [ ! -e "$KEYCHAIN/tenant-$1-admin" ] || n=$((n + 1)); [ ! -e "$KEYCHAIN/tenant-$1-verifier" ] || n=$((n + 1)); echo "$n"; }
reset_beta() {
  printf '%s\n' '{"org_id":"beta","status":"active","trustedOperators":["3:4"],"updated":"2000-01-01"}' > "$TENANTS_DIR/beta.json"
  cp "$TENANTS_DIR/beta.json" "$WORK/beta.before"
  kc_seed beta
  rm -f "$KEYCHAIN.find-started" "$KEYCHAIN.findw-started" "$KEYCHAIN.status-slowed"
}
expect_untouched() {  # $1 scenario, $2 output — record byte-identical, both tokens kept, lock released
  [ "$(status_of beta)" = active ] || fail "$1: beta's status was not restored (is $(status_of beta)): $2"
  cmp -s "$WORK/beta.before" "$TENANTS_DIR/beta.json" || fail "$1: beta's record file changed although nothing was uploaded: $(cat "$TENANTS_DIR/beta.json")"
  [ "$(kc_count beta)" = 2 ] || fail "$1: beta's tokens were not both kept ($(kc_count beta) of 2 left): $2"
  [ ! -d "$LOCK_DIR" ] || fail "$1: the lock was not released although no upload started: $2"
}
# A `node` wrapper, put on PATH only for the runs that need it: it slows the FIRST registry
# write that sets status=removed (the file the harness watches is $SHIM_KEYCHAIN.status-slowed),
# so a signal can be aimed at the moment `remove` mutates the registry. Every other node call
# goes straight through. SHIM_STATUS_PHASE=before sleeps before the write, after sleeps once the
# write has landed (the process is still running, so it is still "during" the mutation).
NODESHIM="$WORK/nodeshim"
mkdir -p "$NODESHIM"
{
  printf '#!/usr/bin/env bash\nreal=%q\n' "$(command -v node)"
  cat <<'SHIM_NODE'
if [ -n "${SHIM_STATUS_SLEEP:-}" ] && [ "${1:-}" = -e ] && [ "${4:-}" = removed ] \
    && [ ! -e "$SHIM_KEYCHAIN.status-slowed" ]; then
  case "${2:-}" in
    *'f.status=process.argv[2]'*)
      : > "$SHIM_KEYCHAIN.status-slowed"
      if [ "${SHIM_STATUS_PHASE:-before}" = before ]; then
        sleep "$SHIM_STATUS_SLEEP"
        exec "$real" "$@"
      fi
      "$real" "$@"; rc=$?
      sleep "$SHIM_STATUS_SLEEP"
      exit "$rc" ;;
  esac
fi
exec "$real" "$@"
SHIM_NODE
} > "$NODESHIM/node"
chmod +x "$NODESHIM/node"

reset_beta
# A background job started WITHOUT job control begins with SIGINT ignored, and a signal ignored
# on entry cannot be trapped — so every run that is sent SIGINT below is launched with job
# control on (`set -m`), in its own process group, exactly as a terminal's foreground job is.

# (r1) a validator refusal during remove: nothing was uploaded, so nothing local may change —
# the status goes back to what it was and both tokens stay in the keychain.
: > "$KEYCHAIN/tenant-badkey-admin"; : > "$KEYCHAIN/tenant-badkey-verifier"
printf '%s\n' '{"org_id":"badkey","status":"active","trustedOperators":["not-a-key"]}' > "$TENANTS_DIR/badkey.json"
out="$(env "${TENANT_ENV[@]}" MARKER="$WORK/marker-r1" bash "$TENANT" remove beta 2>&1)"; rc=$?
rm -f "$TENANTS_DIR/badkey.json" "$KEYCHAIN/tenant-badkey-admin" "$KEYCHAIN/tenant-badkey-verifier"
[ "$rc" != 0 ] || fail "(r1) a remove the validator refused exited 0: $out"
[ ! -e "$WORK/marker-r1" ] || fail "(r1) a refused remove reached the uploader: $out"
case "$out" in *"nothing changed"*) ;; *) fail "(r1) the refusal did not say nothing changed: $out" ;; esac
expect_untouched r1 "$out"
ok "(r1) a validator refusal during remove restores the status and keeps both tokens"

# (r2) SIGINT to the shell while `remove` writes status=removed: the write finishes (bash
# defers the trap until it returns), the trap records the signal, the pre-assembly check turns
# it into "not started", the record is restored byte for byte, the tokens stay, exit 130.
reset_beta
set -m
env "${TENANT_ENV[@]}" PATH="$NODESHIM:$SHIM:$PATH" MARKER="$WORK/marker-r2" SHIM_STATUS_SLEEP=1 SHIM_STATUS_PHASE=before \
  bash "$TENANT" remove beta > "$WORK/r2.log" 2>&1 &
BG=$!
set +m
wait_for_file "$KEYCHAIN.status-slowed" || fail "(r2) the registry write never started: $(cat "$WORK/r2.log")"
require_live "$BG" remove
kill -INT "$BG" || fail "(r2) could not signal the remove"
wait "$BG"; rc=$?
BG=""
out="$(cat "$WORK/r2.log")"
[ "$rc" = 130 ] || fail "(r2) the interrupted remove exited $rc, expected 130: $out"
[ ! -e "$WORK/marker-r2" ] || fail "(r2) the interrupted remove reached the uploader: $out"
case "$out" in *"interrupted by SIGINT before the upload started"*) ;; *) fail "(r2) the interrupt was not reported as before the upload: $out" ;; esac
expect_untouched r2 "$out"
ok "(r2) SIGINT to the shell during the registry write: not started, record restored byte for byte, tokens kept, exit 130"

# (r2b) a terminal Ctrl-C (the whole process group) DURING that write kills the node doing it.
# errexit must not end the run there: the record goes back (or, at worst, stays removed), both
# tokens stay, nothing is uploaded, the lock is released — and a re-run of remove completes.
reset_beta
set -m
env "${TENANT_ENV[@]}" PATH="$NODESHIM:$SHIM:$PATH" MARKER="$WORK/marker-r2b" SHIM_STATUS_SLEEP=2 SHIM_STATUS_PHASE=after \
  bash "$TENANT" remove beta > "$WORK/r2b.log" 2>&1 &
BG=$!
set +m
wait_for_file "$KEYCHAIN.status-slowed" || fail "(r2b) the registry write never started: $(cat "$WORK/r2b.log")"
sleep 0.5
require_live "$BG" remove
kill -INT -- "-$BG" || fail "(r2b) could not signal the remove's process group"
wait "$BG"; rc=$?
BG=""
out="$(cat "$WORK/r2b.log")"
[ "$rc" = 130 ] || fail "(r2b) the remove interrupted during the registry write exited $rc, expected 130: $out"
[ ! -e "$WORK/marker-r2b" ] || fail "(r2b) the interrupted remove reached the uploader: $out"
case "$(status_of beta)" in active|removed) ;; *) fail "(r2b) beta's status is neither the previous one nor removed: $(status_of beta)" ;; esac
[ "$(kc_count beta)" = 2 ] || fail "(r2b) beta's tokens were not both kept ($(kc_count beta) of 2 left): $out"
[ ! -d "$LOCK_DIR" ] || fail "(r2b) the lock was not released although nothing was uploaded: $out"
case "$out" in *"could not update the registry file; nothing was uploaded"*) ;; *) fail "(r2b) the failed registry write was not reported: $out" ;; esac
out="$(env "${TENANT_ENV[@]}" MARKER="$WORK/marker-r2b2" SHIM_SLEEP=1 bash "$TENANT" remove beta 2>&1)"; rc=$?
[ "$rc" = 0 ] || fail "(r2b) re-running remove exited $rc: $out"
[ "$(status_of beta)" = removed ] || fail "(r2b) beta is not removed after the re-run: $out"
[ "$(kc_count beta)" = 0 ] || fail "(r2b) the re-run did not delete beta's tokens: $out"
ok "(r2b) a terminal SIGINT during the registry write: tokens kept, nothing uploaded, lock released, exit 130; a re-run completes"

# (r3) a Ctrl-C in the terminal reaches the WHOLE foreground process group — the shell and
# every pipeline stage, including the put stage while it is still buffering the map. The run
# is started in its own process group (job control on for just this launch) so the check can
# signal that group the way a terminal does; the signal lands while a token is being read.
reset_beta
set -m
env "${TENANT_ENV[@]}" MARKER="$WORK/marker-r3" SHIM_FINDW_SLEEP=2 bash "$TENANT" remove beta > "$WORK/r3.log" 2>&1 &
BG=$!
set +m
wait_for_file "$KEYCHAIN.findw-started" || fail "(r3) the token read never started: $(cat "$WORK/r3.log")"
# Every stage has long been running by now (the pipeline starts them together, and the token
# read comes after the registry parse); the sleep only keeps the signal off the process start-up.
sleep 0.5
require_live "$BG" remove
kill -INT -- "-$BG" || fail "(r3) could not signal the remove's process group"
wait "$BG"; rc=$?
BG=""
out="$(cat "$WORK/r3.log")"
[ "$rc" = 130 ] || fail "(r3) the remove interrupted mid-pipeline exited $rc, expected 130: $out"
[ ! -e "$WORK/marker-r3" ] || fail "(r3) wrangler was spawned after the interrupt: $out"
case "$out" in *"interrupted before the upload started"*) ;; *) fail "(r3) the interrupt was not reported as before the upload: $out" ;; esac
expect_untouched r3 "$out"
ok "(r3) a terminal SIGINT while the put stage buffers: wrangler never spawned, status restored, tokens kept, exit 130"

# (r4) SIGINT after the put has spawned: the upload runs to completion and is confirmed, the
# tokens are then deleted, and only then does the deferred exit 130 happen.
reset_beta
set -m
env "${TENANT_ENV[@]}" MARKER="$WORK/marker-r4" SHIM_SLEEP=1 bash "$TENANT" remove beta > "$WORK/r4.log" 2>&1 &
BG=$!
set +m
wait_for_file "$WORK/marker-r4" || fail "(r4) the upload never started: $(cat "$WORK/r4.log")"
require_live "$BG" remove
kill -INT "$BG" || fail "(r4) could not signal the remove"
wait "$BG"; rc=$?
BG=""
out="$(cat "$WORK/r4.log")"
[ "$rc" = 130 ] || fail "(r4) the remove interrupted mid-upload exited $rc, expected 130: $out"
[ "$(tail -n 1 "$WORK/marker-r4")" = "done" ] || fail "(r4) the upload did not finish: $(cat "$WORK/marker-r4")"
case "$out" in *"ran to completion and was confirmed"*) ;; *) fail "(r4) the confirmed upload was not reported: $out" ;; esac
[ "$(status_of beta)" = removed ] || fail "(r4) beta is not removed (is $(status_of beta)): $out"
[ "$(kc_count beta)" = 0 ] || fail "(r4) beta's tokens were not deleted after a confirmed upload ($(kc_count beta) left): $out"
[ ! -d "$LOCK_DIR" ] || fail "(r4) the lock survived a confirmed upload: $out"
ok "(r4) SIGINT after the put spawned: the upload is confirmed, tokens deleted, then exit 130"

# (r5) an unknown outcome keeps everything: the lock (upload.pending), both tokens, and the
# removed status — the tokens are the only way back if the old map is still live. Finishing the
# half-removed tenant is the runbook's recovery (lock removed by hand) plus the same remove.
reset_beta
out="$(env "${TENANT_ENV[@]}" MARKER="$WORK/marker-r5" SHIM_SLEEP=1 SHIM_NO_SUCCESS=1 bash "$TENANT" remove beta 2>&1)"; rc=$?
[ "$rc" != 0 ] || fail "(r5) a remove with an unconfirmed upload exited 0: $out"
[ -e "$LOCK_DIR/upload.pending" ] || fail "(r5) the lock was not retained over an unknown outcome: $out"
[ "$(status_of beta)" = removed ] || fail "(r5) beta's status changed after an unknown outcome (is $(status_of beta)): $out"
[ "$(kc_count beta)" = 2 ] || fail "(r5) beta's tokens were deleted after an unknown outcome ($(kc_count beta) of 2 left): $out"
case "$out" in *'Recovering a retained lock'*) ;; *) fail "(r5) the unknown outcome did not name the runbook's recovery section: $out" ;; esac
case "$out" in *"tokens are KEPT"*) ;; *) fail "(r5) the unknown outcome did not say the tokens were kept: $out" ;; esac
rm -rf "$LOCK_DIR"
out="$(env "${TENANT_ENV[@]}" MARKER="$WORK/marker-r5b" SHIM_SLEEP=1 bash "$TENANT" remove beta 2>&1)"; rc=$?
[ "$rc" = 0 ] || fail "(r5) re-running remove after the recovery exited $rc: $out"
[ "$(status_of beta)" = removed ] || fail "(r5) beta is not removed after the re-run: $out"
[ "$(kc_count beta)" = 0 ] || fail "(r5) the re-run did not delete beta's tokens ($(kc_count beta) left): $out"
[ ! -d "$LOCK_DIR" ] || fail "(r5) the re-run left its lock behind: $out"
ok "(r5) an unknown outcome retains the lock, both tokens and status=removed; recovery plus a re-run finishes the removal"

# (r6) a keychain delete that fails after a confirmed upload is reported by account and fails
# the run — the tenant is gone from the map, so the record stays removed; the lock is released.
reset_beta
out="$(env "${TENANT_ENV[@]}" MARKER="$WORK/marker-r6" SHIM_SLEEP=1 SHIM_DELETE_FAIL=1 bash "$TENANT" remove beta 2>&1)"; rc=$?
[ "$rc" != 0 ] || fail "(r6) a remove whose token delete failed exited 0: $out"
[ "$(tail -n 1 "$WORK/marker-r6")" = "done" ] || fail "(r6) the upload did not finish: $out"
case "$out" in *"tenant-beta-admin"*) ;; *) fail "(r6) the stale admin account was not named: $out" ;; esac
case "$out" in *"tenant-beta-verifier"*) ;; *) fail "(r6) the stale verifier account was not named: $out" ;; esac
[ "$(status_of beta)" = removed ] || fail "(r6) beta is not removed (is $(status_of beta)): $out"
[ "$(kc_count beta)" = 2 ] || fail "(r6) the fake keychain lost items it refused to delete: $out"
[ ! -d "$LOCK_DIR" ] || fail "(r6) the lock survived a confirmed upload: $out"
ok "(r6) a failed token delete after a confirmed upload names the stale accounts and exits non-zero; the record stays removed"

# (r6b) a failed delete AND a recorded interrupt: the stale tokens decide the exit code (1),
# not the interrupt — 130 would read as "interrupted" and hide the half-finished cleanup.
reset_beta
set -m
env "${TENANT_ENV[@]}" MARKER="$WORK/marker-r6b" SHIM_SLEEP=1 SHIM_DELETE_FAIL=1 bash "$TENANT" remove beta > "$WORK/r6b.log" 2>&1 &
BG=$!
set +m
wait_for_file "$WORK/marker-r6b" || fail "(r6b) the upload never started: $(cat "$WORK/r6b.log")"
require_live "$BG" remove
kill -INT "$BG" || fail "(r6b) could not signal the remove"
wait "$BG"; rc=$?
BG=""
out="$(cat "$WORK/r6b.log")"
[ "$rc" = 1 ] || fail "(r6b) a remove with stale tokens and an interrupt exited $rc, expected 1: $out"
case "$out" in *"tenant-beta-admin"*"tenant-beta-verifier"*) ;; *) fail "(r6b) the stale accounts were not named: $out" ;; esac
case "$out" in *"SIGINT"*) ;; *) fail "(r6b) the interrupt was not reported: $out" ;; esac
[ "$(status_of beta)" = removed ] || fail "(r6b) beta is not removed: $out"
ok "(r6b) stale tokens plus an interrupt: both reported, exit 1"

# (r7) a token someone else deleted between the presence check and the delete (44,
# errSecItemNotFound) is already gone — not a STALE alarm.
reset_beta
out="$(env "${TENANT_ENV[@]}" MARKER="$WORK/marker-r7" SHIM_SLEEP=1 SHIM_DELETE_MISSING=1 bash "$TENANT" remove beta 2>&1)"; rc=$?
[ "$rc" = 0 ] || fail "(r7) a remove whose tokens were already gone exited $rc: $out"
case "$out" in *STALE*) fail "(r7) an already-deleted token was reported stale: $out" ;; *) ;; esac
[ "$(kc_count beta)" = 0 ] || fail "(r7) beta's tokens are still present: $out"
[ "$(status_of beta)" = removed ] || fail "(r7) beta is not removed: $out"
ok "(r7) a token already deleted by someone else (44) counts as gone: exit 0, no stale alarm"

# ---- the last tenant (E13): `{}` is a valid, deliberately EMPTY map, and every boundary that can
# emit it demands a flag that says so. A disabled tenant still occupies the map, so it counts.
is_empty_body() { [ "$(cat "$1" 2>/dev/null)" = '{}' ]; }

# (u1) the put stage refuses `{}` without --allow-empty: wrangler is never started.
out="$(printf '{}' | env PATH="$SHIM:$PATH" MARKER="$WORK/marker-u1" MARKER_BODY="$WORK/body-u1" \
  node "$SCRIPT_DIR/tenants-put.mjs" --env=lockcheck 2>&1)"; rc=$?
[ "$rc" = 1 ] || fail "(u1) the put stage exited $rc on {} without --allow-empty, expected 1: $out"
case "$out" in *"refusing to push an EMPTY map without --allow-empty"*) ;; *) fail "(u1) the refusal did not name --allow-empty: $out" ;; esac
[ ! -e "$WORK/marker-u1" ] || fail "(u1) wrangler was started for an empty map without --allow-empty"
ok "(u1) the put stage refuses {} without --allow-empty and starts nothing"

# (u2) with --allow-empty it goes up — and the flag is the put stage's, never wrangler's.
out="$(printf '{}' | env PATH="$SHIM:$PATH" MARKER="$WORK/marker-u2" MARKER_BODY="$WORK/body-u2" SHIM_SLEEP=0 \
  node "$SCRIPT_DIR/tenants-put.mjs" --env=lockcheck --allow-empty 2>&1)"; rc=$?
[ "$rc" = 0 ] || fail "(u2) the put stage exited $rc on {} with --allow-empty: $out"
is_empty_body "$WORK/body-u2" || fail "(u2) the upload did not carry exactly {}: $(cat "$WORK/body-u2" 2>/dev/null)"
grep -q -- '--env=lockcheck' "$WORK/marker-u2" || fail "(u2) the environment did not reach wrangler: $(cat "$WORK/marker-u2")"
grep -q -- '--allow-empty' "$WORK/marker-u2" && fail "(u2) --allow-empty leaked into wrangler's argv: $(cat "$WORK/marker-u2")"
ok "(u2) --allow-empty lets {} through; wrangler gets --env but never --allow-empty"

# (e5) a DISABLED tenant counts: with acme disabled and beta active, removing beta leaves a
# non-empty map (acme quarantined), so it is not the last tenant. Removing it plain is covered
# by (r2b)-(r7); here --last is given anyway: it is noted and NOT turned into --allow-empty.
reset_beta
[ "$(status_of acme)" = disabled ] || fail "(e5) precondition: acme should be disabled here (is $(status_of acme))"
out="$(env "${TENANT_ENV[@]}" MARKER="$WORK/marker-e5" MARKER_BODY="$WORK/body-e5" SHIM_SLEEP=0 bash "$TENANT" remove beta --last 2>&1)"; rc=$?
[ "$rc" = 0 ] || fail "(e5) removing beta beside a disabled acme exited $rc: $out"
case "$out" in *"note: --last given, but 'beta' is not the last tenant; the map stays non-empty"*) ;; *) fail "(e5) a --last on a non-last tenant was not noted: $out" ;; esac
grep -q -- '--allow-empty' "$WORK/marker-e5" && fail "(e5) --allow-empty reached the put stage for a non-empty map: $(cat "$WORK/marker-e5")"
[ "$(status_of beta)" = removed ] || fail "(e5) beta is not removed: $out"
body_says "$WORK/body-e5" disabled || fail "(e5) the upload did not keep the disabled acme: $(cat "$WORK/body-e5")"
ok "(e5) a disabled tenant occupies the map: beta is not the last one, and a --last on it is noted, not forwarded"

# (e1) acme is now the only record that is active or disabled. Without --last its removal is
# refused before anything changes: status untouched, tokens kept, no upload, lock released.
node -e 'const fs=require("fs");const p=process.argv[1];const f=JSON.parse(fs.readFileSync(p,"utf8"));f.status="active";fs.writeFileSync(p,JSON.stringify(f,null,2)+"\n")' "$TENANTS_DIR/acme.json"
cp "$TENANTS_DIR/acme.json" "$WORK/acme.before"
out="$(env "${TENANT_ENV[@]}" MARKER="$WORK/marker-e1" bash "$TENANT" remove acme 2>&1)"; rc=$?
[ "$rc" = 1 ] || fail "(e1) removing the last tenant without --last exited $rc, expected 1: $out"
case "$out" in *"remove: 'acme' is the last tenant; removing it leaves an EMPTY map (every request denied). Re-run with --last to confirm"*) ;; *) fail "(e1) the refusal did not ask for --last: $out" ;; esac
cmp -s "$WORK/acme.before" "$TENANTS_DIR/acme.json" || fail "(e1) acme's record changed although the remove was refused: $(cat "$TENANTS_DIR/acme.json")"
[ "$(kc_count acme)" = 2 ] || fail "(e1) acme's tokens were not both kept: $out"
[ ! -e "$WORK/marker-e1" ] || fail "(e1) a refused remove reached the uploader: $out"
[ ! -d "$LOCK_DIR" ] || fail "(e1) the lock was not released: $out"
ok "(e1) removing the last tenant without --last is refused: nothing changes, nothing is uploaded"

# (e2) with --last the empty map goes up deliberately: exactly {}, tokens deleted, status removed.
out="$(env "${TENANT_ENV[@]}" MARKER="$WORK/marker-e2" MARKER_BODY="$WORK/body-e2" SHIM_SLEEP=0 bash "$TENANT" remove acme --last 2>&1)"; rc=$?
[ "$rc" = 0 ] || fail "(e2) remove acme --last exited $rc: $out"
is_empty_body "$WORK/body-e2" || fail "(e2) the upload did not carry exactly {}: $(cat "$WORK/body-e2" 2>/dev/null)"
grep -q -- '--allow-empty' "$WORK/marker-e2" && fail "(e2) --allow-empty leaked into wrangler's argv: $(cat "$WORK/marker-e2")"
case "$out" in *"empty map: every request will be denied"*) ;; *) fail "(e2) the validator's empty-map warning was not shown: $out" ;; esac
[ "$(status_of acme)" = removed ] || fail "(e2) acme is not removed: $out"
[ "$(kc_count acme)" = 0 ] || fail "(e2) acme's tokens were not deleted after the confirmed upload: $out"
[ ! -d "$LOCK_DIR" ] || fail "(e2) the lock survived a confirmed upload: $out"
ok "(e2) remove --last uploads exactly {} (confirmed), deletes the tokens and records status=removed"

# (e3) every record is removed now: a plain sync (or dry run) refuses to push {} — nothing starts.
for args in "" "--dry-run"; do
  out="$(env "${TENANT_ENV[@]}" MARKER="$WORK/marker-e3" bash "$TENANT" sync $args 2>&1)"; rc=$?
  [ "$rc" != 0 ] || fail "(e3) sync $args with every tenant removed exited 0: $out"
  case "$out" in *"sync: the assembled map is empty (every tenant is removed); pass --allow-empty to push it deliberately"*) ;; *) fail "(e3) sync $args did not ask for --allow-empty: $out" ;; esac
  [ ! -e "$WORK/marker-e3" ] || fail "(e3) sync $args reached the uploader: $out"
  [ ! -d "$LOCK_DIR" ] || fail "(e3) sync $args left its lock behind: $out"
done
ok "(e3) sync and sync --dry-run refuse an all-removed registry without --allow-empty; nothing is uploaded"

# (e4) --allow-empty pushes it deliberately (either order with --dry-run is accepted).
out="$(env "${TENANT_ENV[@]}" MARKER="$WORK/marker-e4d" bash "$TENANT" sync --allow-empty --dry-run 2>&1)"; rc=$?
[ "$rc" = 0 ] || fail "(e4) sync --allow-empty --dry-run exited $rc: $out"
[ ! -e "$WORK/marker-e4d" ] || fail "(e4) a dry run reached the uploader: $out"
out="$(env "${TENANT_ENV[@]}" MARKER="$WORK/marker-e4" MARKER_BODY="$WORK/body-e4" SHIM_SLEEP=0 bash "$TENANT" sync --allow-empty 2>&1)"; rc=$?
[ "$rc" = 0 ] || fail "(e4) sync --allow-empty exited $rc: $out"
case "$out" in *"done. Secrets take effect"*) ;; *) fail "(e4) sync --allow-empty did not report a confirmed upload: $out" ;; esac
is_empty_body "$WORK/body-e4" || fail "(e4) the upload did not carry exactly {}: $(cat "$WORK/body-e4" 2>/dev/null)"
[ ! -d "$LOCK_DIR" ] || fail "(e4) the lock survived a confirmed upload: $out"
out="$(tenant sync --allow-empty --bogus 2>&1)"; rc=$?
[ "$rc" != 0 ] || fail "(e4) sync with an unknown argument beside --allow-empty exited 0: $out"
ok "(e4) sync --allow-empty uploads exactly {} (confirmed); --dry-run beside it pushes nothing; unknown flags still refuse"

# (e6) bringing a removed tenant back after `remove --last` (the RUNBOOK path): rotate stores
# the new token and SKIPS the sync — the tenant is removed, so the map would not change, and
# an all-removed registry would refuse the sync anyway. Then status=active plus sync brings it back.
[ "$(status_of acme)" = removed ] && [ "$(status_of beta)" = removed ] || fail "(e6) precondition: every record should be removed here"
for role in admin verifier; do
  out="$(env "${TENANT_ENV[@]}" MARKER="$WORK/marker-e6" bash "$TENANT" rotate acme "$role" 2>&1)"; rc=$?
  [ "$rc" = 0 ] || fail "(e6) rotate acme $role on a removed tenant exited $rc: $out"
  case "$out" in *"tenant is removed; the map is unchanged — set status active and run sync to bring it back"*) ;; *) fail "(e6) rotate did not say the sync was skipped: $out" ;; esac
  case "$out" in *"changed nothing"*|*"--allow-empty"*) fail "(e6) rotate reported a refused sync: $out" ;; *) ;; esac
  [ -e "$KEYCHAIN/tenant-acme-$role" ] || fail "(e6) rotate acme $role stored no token"
  [ ! -e "$WORK/marker-e6" ] || fail "(e6) rotate on a removed tenant reached the uploader: $out"
  [ ! -d "$LOCK_DIR" ] || fail "(e6) rotate left its lock behind: $out"
done
node -e 'const fs=require("fs");const p=process.argv[1];const f=JSON.parse(fs.readFileSync(p,"utf8"));f.status="active";fs.writeFileSync(p,JSON.stringify(f,null,2)+"\n")' "$TENANTS_DIR/acme.json"
out="$(env "${TENANT_ENV[@]}" MARKER="$WORK/marker-e6s" MARKER_BODY="$WORK/body-e6" SHIM_SLEEP=0 bash "$TENANT" sync 2>&1)"; rc=$?
[ "$rc" = 0 ] || fail "(e6) the sync that brings acme back exited $rc: $out"
body_says "$WORK/body-e6" active || fail "(e6) the upload did not carry acme active: $(cat "$WORK/body-e6")"
[ "$(node -e 'process.stdout.write(Object.keys(JSON.parse(require("fs").readFileSync(process.argv[1],"utf8"))).join(","))' "$WORK/body-e6")" = acme ] \
  || fail "(e6) the upload did not carry exactly acme: $(cat "$WORK/body-e6")"
ok "(e6) rotate on a removed tenant stores the token and skips the sync; status=active plus sync brings it back"

# (e0) a directory with NO record files is still refused, --allow-empty or not: that is a wrong
# TENANTS_DIR / HOSTED_VERIFY_ENV far more often than a deliberate empty map.
# The directory holds only what is NOT a record — the same decoys the assembler's own test
# uses — and the shell and tenants-assemble.mjs must both see zero records in it.
mkdir -p "$WORK/tenants-empty/dir.json"
printf 'not json' > "$WORK/tenants-empty/.hidden.json"
printf 'not json' > "$WORK/tenants-empty/x.policy.json"
printf 'ignored' > "$WORK/tenants-empty/notes.txt"
out="$(env "${TENANT_ENV[@]}" TENANTS_DIR="$WORK/tenants-empty" MARKER="$WORK/marker-e0" bash "$TENANT" sync --allow-empty 2>&1)"; rc=$?
[ "$rc" != 0 ] || fail "(e0) sync --allow-empty over a directory with no record files exited 0: $out"
case "$out" in *"no tenant registry files"*) ;; *) fail "(e0) the refusal did not name the missing record files: $out" ;; esac
[ ! -e "$WORK/marker-e0" ] || fail "(e0) an empty registry directory reached the uploader: $out"
out="$(env "${TENANT_ENV[@]}" TENANTS_DIR="$WORK/tenants-empty" bash "$TENANT" show 2>&1)"; rc=$?
[ "$rc" = 0 ] || fail "(e0) show over the decoys exited $rc: $out"
case "$out" in *"(no tenants in "*) ;; *) fail "(e0) show did not report zero tenants over the decoys: $out" ;; esac
out="$(printf '' | node "$SCRIPT_DIR/tenants-assemble.mjs" "$WORK/tenants-empty" 2>&1)"; rc=$?
[ "$rc" = 1 ] || fail "(e0) the assembler exited $rc over the decoys, expected 1: $out"
case "$out" in *"no registry record files"*) ;; *) fail "(e0) the assembler did not refuse the decoys as zero records: $out" ;; esac
ok "(e0) decoys only (dotfile, *.policy.json, a directory, a .txt): shell and assembler agree there are no records; refused even with --allow-empty"

echo "tenant-lock-check: all checks passed"
