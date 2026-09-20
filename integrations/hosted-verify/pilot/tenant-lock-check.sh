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
# what arrived is a non-empty JSON object. The registry lives in a temp directory under
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
# records its argv, its own pid and its PARENT's (the put stage that spawned it — the check
# signals nothing it has not been told the pid of), IGNORES INT/TERM the way the real one
# swallows its child's signal death, and starts a background UPLOADER: a separate process, in
# the launcher's process group, which drains the map off stdin into $MARKER_BODY (so the check
# can assert WHAT was uploaded) and stays busy long enough to be observed mid-flight. Only a
# non-empty JSON object earns wrangler's success line — the one thing the put stage accepts as
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

# (g6) an interrupt that arrives before the map has finished coming down the pipe is deferred
# too. The handlers go on first thing, ahead of stdin: installed any later, a TERM in that
# window would kill the put stage outright — no upload started, no marker, and an exit code
# upstream that looks like an interrupt over an upload that never existed.
mkdir -p "$WORK/lock-early"
( sleep 2; printf '{"acme":{}}' ) | env PATH="$SHIM:$PATH" \
    MARKER="$WORK/marker-early" MARKER_BODY="$WORK/body-early" SHIM_SLEEP=1 \
    TENANT_LOCK_DIR="$WORK/lock-early" \
    node "$SCRIPT_DIR/tenants-put.mjs" --env=lockcheck \
    > "$WORK/early.log" 2>&1 &
BG=$!
sleep 0.5
require_live "$BG" put
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

echo "tenant-lock-check: all checks passed"
