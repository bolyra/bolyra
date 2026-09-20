#!/usr/bin/env bash
#
# tenant.sh — tenant lifecycle for the hosted-verify preview (the per-tenant TENANTS model).
#
# Thin wrapper over existing mechanisms — no new infra:
#   * the two bearer tokens per tenant live in the macOS keychain
#       service: bolyra-hosted-verify   (bolyra-hosted-verify-<env> when HOSTED_VERIFY_ENV is set)
#       account: tenant-<org_id>-admin / tenant-<org_id>-verifier
#   * the tenant registry is pilot/tenants/<org_id>.json at the repo root (one file per
#     tenant; template pilot/partner-config.example.json). Files contain NO secrets — the
#     org id, status, the tenant's trusted operator keys, and human contact fields.
#   * the Worker reads the TENANTS wrangler secret: one JSON object mapping org_id to
#     { admin_token, verifier_token, trusted_operators, disabled }. `sync` assembles it
#     from the registry + keychain, validates it with tenants-check.mjs (the rules the
#     Worker applies — any defect would fail EVERY tenant closed), and re-puts it.
#
# IMPORTANT: `wrangler secret put TENANTS` REPLACES the whole map. Never put it by hand —
# always go through `sync`, which includes every tenant whose status is active or disabled.
#
# Usage:
#   ./tenant.sh add <org_id> <x:y>[,<x:y>...] [--with-fixture-key]
#                                     mint both tokens, store them, create the registry file
#                                     trusting ONLY the keys given, then sync; seeds the repo
#                                     conformance fixture key only with --with-fixture-key
#                                     (preview-only: its private half is public)
#   ./tenant.sh rotate <org_id> admin|verifier
#                                     mint a NEW token for that role, then sync
#   ./tenant.sh disable <org_id>      quarantine — the entry stays with "disabled": true and
#                                     the tenant is served on NO route (verify: 500
#                                     internal_error verdict; registry routes: 503
#                                     tenant_disabled), then sync
#   ./tenant.sh enable <org_id> --keys-retired
#                                     lift the quarantine; refuses without the flag, which
#                                     records that any operator key the quarantine was
#                                     about has been retired or re-issued
#   ./tenant.sh remove <org_id>       delete both tokens from the keychain and drop the
#                                     tenant from the map (status=removed; the registry
#                                     file is kept; the tenant's Durable Object and its
#                                     history are NOT deleted), then sync
#   ./tenant.sh sync [--dry-run]      rebuild TENANTS from registry + keychain, validate,
#                                     re-put (dry-run: validate and report, push nothing)
#   ./tenant.sh show                  list tenants, status, keychain presence
#   ./tenant.sh unlock [--force]      clear a retained lock once no upload can still be
#                                     running (then sync); --force only after confirming with
#                                     `pgrep -fl wrangler` that no wrangler process remains
#   Every command except show and unlock takes a per-environment lock ($TENANTS_DIR/.lock); an
#   interrupt (Ctrl-C/TERM) takes effect only after the in-flight put has finished, so a
#   half-pushed map cannot be raced. The lock carries an owner token that the put stage
#   re-checks immediately before it starts an upload, so a run can never push under a lock
#   that was cleared and re-taken underneath it, and the upload runs in its own process group
#   so that what is still alive can be asked about afterwards. The lock is released only when
#   wrangler confirms the upload; otherwise it stays, and what is live is UNKNOWN — the secret
#   is write-only, so no command can look it up, a dry run only re-validates the map that was
#   INTENDED, and whether an already-submitted request completed cannot be established from
#   here at all. That is why the resolution is to re-sync: unlock (it refuses while the
#   upload's process group is alive, and refuses without --force when that group was never
#   recorded), then sync to re-put the intended map, then confirm on the Worker.
#
# Environment:
#   HOSTED_VERIFY_ENV=<name>    target that named Worker environment (`--env=<name>`; keychain
#                               service bolyra-hosted-verify-<name>; registry directory
#                               pilot/tenants-<name>); must match ^[a-z][a-z0-9-]{0,31}$
#   TENANTS_DIR=<dir>           override the registry directory
#
# Tokens are NEVER printed by this script. To hand a token to a partner over a secure
# channel, run (yourself, deliberately):
#   security find-generic-password -s bolyra-hosted-verify -a tenant-<org_id>-verifier -w
set -euo pipefail

die() { echo "error: $*" >&2; exit 1; }
usage() { awk 'NR>1 && /^set -euo pipefail/{exit} NR>1' "$0" | sed 's/^# \{0,1\}//'; exit 2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKER_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$WORKER_DIR/../.." && pwd)"
ENV_NAME="${HOSTED_VERIFY_ENV:-}"
if [ -n "$ENV_NAME" ]; then
  # The name becomes a keychain service, a directory, and a wrangler `--env=` — validate it
  # here rather than discover it as a mis-targeted push or a stray directory.
  [[ "$ENV_NAME" =~ ^[a-z][a-z0-9-]{0,31}$ ]] || die "HOSTED_VERIFY_ENV must match ^[a-z][a-z0-9-]{0,31}\$ (got '$ENV_NAME')"
  KEYCHAIN_SERVICE="bolyra-hosted-verify-$ENV_NAME"
  TENANTS_DIR="${TENANTS_DIR:-$REPO_ROOT/pilot/tenants-$ENV_NAME}"
  WRANGLER_ENV=("--env=$ENV_NAME")
else
  KEYCHAIN_SERVICE="bolyra-hosted-verify"
  TENANTS_DIR="${TENANTS_DIR:-$REPO_ROOT/pilot/tenants}"
  # Production is the top-level environment. Named explicitly (`--env=`) so that a
  # CLOUDFLARE_ENV in the shell can never redirect a production sync to staging, and
  # wrangler does not warn about an unspecified environment.
  WRANGLER_ENV=("--env=")
fi
# The lock path is exported to the put stage, which runs after `cd "$WORKER_DIR"` — a relative
# TENANTS_DIR would resolve there instead of here, so make it absolute before anything uses it.
case "$TENANTS_DIR" in
  /*) ;;
  *) TENANTS_DIR="$PWD/$TENANTS_DIR" ;;
esac
# One tenant.sh at a time per environment. Every mutating command ends in a full rebuild of
# TENANTS from the registry + keychain, so two overlapping runs can interleave: the one that
# paused inside wrangler puts its OLDER map last and silently undoes the other (a quarantine
# comes back re-enabled). The lock is taken before the first registry or keychain mutation
# and held through the final `wrangler secret put`. mkdir is atomic on every filesystem here,
# which flock (not on macOS) and lockfile helpers are not.
LOCK_DIR="$TENANTS_DIR/.lock"
LOCK_HELD=0
release_lock() {
  # Only ever remove a lock this process created — a failed acquire must leave the holder's.
  [ "$LOCK_HELD" = 1 ] || return 0
  LOCK_HELD=0
  # The upload can outlive this shell: a `kill -9`, a closed terminal, or a wrangler still
  # talking to the API leaves the put running with no one to wait for it. Releasing the lock
  # then is exactly the interleaving the lock exists to prevent — a second operator's sync
  # would land FIRST and this one's older map would overwrite it, silently undoing a
  # quarantine. The put stage writes upload.pending BEFORE wrangler starts and renames it to
  # upload.confirmed only once wrangler has confirmed the upload, so a marker still under its
  # pending name is the one honest answer to "could a put still be in flight, or have landed
  # unseen?" — keep the lock and say so.
  if [ -e "$LOCK_DIR/upload.pending" ]; then
    echo "error: lock retained at $LOCK_DIR: the last upload was not confirmed complete (see $LOCK_DIR/upload.pending) and what is live is unknown; recover with: pilot/tenant.sh unlock, then pilot/tenant.sh sync" >&2
    return 0
  fi
  # The confirmation marker has reported what it had to report by the time the lock goes; it
  # must not outlive the lock it sits in, or a later run could read a stale confirmation as
  # the answer for its own upload.
  # `owner` is the lock's identity, so it goes with the lock and never before it: while the
  # retain branch above holds the lock the token must stay readable, or a put stage still
  # running under it would read a missing owner as a lock that is not its own.
  rm -f "$LOCK_DIR/upload.confirmed" "$LOCK_DIR/pid" "$LOCK_DIR/owner"
  rmdir "$LOCK_DIR" 2>/dev/null || true
}
# True when the marker at $1 was NOT written under the lock that is there now. The put stage
# stamps the lock's owner token into the first line of every marker it writes. Between its
# startup check and that write there is a window — this shell dead, no marker yet to stop an
# unlock — in which the lock can be cleared and re-taken at the same path, and the orphaned put
# stage would then leave its stale marker in the new lock: tracking that names a run nobody
# here is waiting for. A marker whose token is not the current lock's is that marker, and
# neither the sync's report nor unlock's clearing may be based on it.
marker_is_foreign() {  # $1 marker path
  local m l
  m="$(awk '/^owner /{print $2; exit}' "$1" 2>/dev/null)" || m=""
  l="$(cat "$LOCK_DIR/owner" 2>/dev/null)" || l=""
  [ -n "$m" ] && [ -n "$l" ] && [ "$m" = "$l" ] && return 1
  return 0
}
on_signal() {  # $1 the signal name, INT or TERM
  # Bash defers a trapped signal that arrives while a FOREGROUND command is running until that
  # command returns, and the last stage of the sync pipeline does not return until wrangler has
  # exited. So by the time this body runs the in-flight put has either landed or failed, with
  # the lock held for all of it — an interrupt cannot leave a half-pushed map open to a race.
  echo "error: interrupted by SIG$1 after the in-flight command finished; whether the upload it was running was confirmed is reported above" >&2
  # Exit with the conventional 128+signal code, and through the EXIT trap, so release_lock
  # still runs and still applies the retain rule above.
  case "$1" in
    INT) exit 130 ;;
    *)   exit 143 ;;
  esac
}
acquire_lock() {
  mkdir -p "$TENANTS_DIR" || die "could not create the registry directory $TENANTS_DIR"
  mkdir "$LOCK_DIR" 2>/dev/null || die "another tenant.sh is running for this environment (lock $LOCK_DIR); if none is, run: pilot/tenant.sh unlock"
  LOCK_HELD=1
  # Installed only once the lock is ours. `die` exits, so every refusal path releases it too.
  trap 'release_lock' EXIT
  # Ctrl-C and TERM are taken with the lock, not left to the default disposition: the default
  # kills this shell the moment the in-flight command returns, running the EXIT trap while the
  # upload child is still alive. Handled, the interrupt is reported after that command has
  # finished and still leaves through the EXIT trap.
  trap 'on_signal INT' INT
  trap 'on_signal TERM' TERM
  echo "$$" > "$LOCK_DIR/pid" 2>/dev/null || true
  # The lock's IDENTITY, not just its path. `unlock` can clear a retained lock and the next
  # run then creates a fresh lock directory at exactly this path, so a stage that recognised
  # the lock by path alone could write its marker — or start an upload — under somebody
  # else's lock. The put stage compares this token against `owner` at startup and again in the
  # instant before the upload exists, and refuses when it does not match. The token identifies
  # a lock; it is not a credential and guards nothing but this directory.
  LOCK_TOKEN="$(openssl rand -hex 16)" || die "could not generate a lock owner token (openssl)"
  printf '%s\n' "$LOCK_TOKEN" > "$LOCK_DIR/owner" || die "could not record the lock owner in $LOCK_DIR"
  # The put stage records the upload in the lock directory before it starts one, so
  # release_lock can tell a confirmed upload from one that may still be in flight.
  export TENANT_LOCK_DIR="$LOCK_DIR"
  export TENANT_LOCK_TOKEN="$LOCK_TOKEN"
}

# The repo conformance-fixture operator key (its private half is public). Seeded into a
# preview tenant ONLY on --with-fixture-key, so the quickstart and examples/managed-revocation
# verify before the partner's own key issues anything. Preview-only; never in a real deployment.
FIXTURE_KEY="15617329766995256858590222302430068383949745072531974464084158078905448850943:20201653676552407165606319978171745645181779505176156736762229713293662347780"

require_org() {
  [[ "$1" =~ ^[a-z0-9][a-z0-9-]{1,62}$ ]] || die "org_id '$1' must match ^[a-z0-9][a-z0-9-]{1,62}$"
  [ "$1" != "unauthenticated" ] || die "'unauthenticated' is the reserved analytics label"
}
require_keys() {  # comma-separated x:y decimal pairs
  local key _keys
  [ -n "$1" ] || die "at least one operator key (x:y) is required"
  # Match the WHOLE list in one anchored test before anything is created: a per-entry loop
  # misses a trailing comma (bash 3.2 `read -a` drops a trailing empty field), and a
  # half-provisioned tenant blocks every later sync.
  [[ "$1" =~ ^[0-9]+:[0-9]+(,[0-9]+:[0-9]+)*$ ]] || die "operator keys must be comma-separated x:y decimal pairs with no empty entries (got '$1')"
  IFS=',' read -r -a _keys <<< "$1"
  for key in "${_keys[@]}"; do
    [[ "$key" =~ ^[0-9]+:[0-9]+$ ]] || die "operator key '$key' must be an x:y decimal pair"
  done
}
have_security() { command -v security >/dev/null 2>&1; }
require_security() { have_security || die "the macOS keychain (security) is required for tokens"; }
kc_account() { echo "tenant-$1-$2"; }
kc_has() { have_security && security find-generic-password -s "$KEYCHAIN_SERVICE" -a "$(kc_account "$1" "$2")" >/dev/null 2>&1; }
kc_get() { security find-generic-password -s "$KEYCHAIN_SERVICE" -a "$(kc_account "$1" "$2")" -w; }
kc_put() {  # $1 org, $2 role, $3 token — -U updates in place
  # No token may reach an xtrace log; restore tracing on the way out.
  local _xt rc=0 err
  case "$-" in *x*) _xt=1; set +x ;; *) _xt=0 ;; esac
  # -w LAST and the token on stdin: as `-w <token>` it would sit in argv, where `ps` sees it.
  # `security` reads the password TWICE in this mode — a single line stores an EMPTY password.
  # With the token on stdin, `security` prints its interactive retype prompt to stderr even
  # though nothing is actually waiting on a terminal; captured here and shown only on failure
  # so a real keychain error is never lost in that noise. `err` holds prompt/error text only —
  # never the token, which never touches stderr.
  err="$(printf '%s\n%s\n' "$3" "$3" | security add-generic-password -U -s "$KEYCHAIN_SERVICE" \
      -a "$(kc_account "$1" "$2")" -j "bolyra hosted-verify tenant token: $1 ($2)" -w 2>&1 >/dev/null)" || rc=$?
  if [ "$rc" != 0 ]; then printf '%s\n' "$err" >&2; fi
  if [ "$_xt" = 1 ]; then set -x; fi
  return "$rc"
}
kc_put_minted() {  # $1 org, $2 role — mint a fresh token and store it
  # The guard has to sit OUT here, not only inside kc_put: under `bash -x` the caller traces
  # both the `t=$(mint)` assignment and the kc_put call line itself before the callee's own
  # guard can run.
  local _xt rc=0 t
  case "$-" in *x*) _xt=1; set +x ;; *) _xt=0 ;; esac
  t="$(mint)" && kc_put "$1" "$2" "$t" || rc=$?
  unset t
  if [ "$_xt" = 1 ]; then set -x; fi
  return "$rc"
}
kc_delete() { security delete-generic-password -s "$KEYCHAIN_SERVICE" -a "$(kc_account "$1" "$2")" >/dev/null 2>&1 || true; }
mint() { openssl rand -hex 32; }

registry_file() { echo "$TENANTS_DIR/$1.json"; }
reg_field() {  # $1 org, $2 field → the field as a string (empty when absent)
  node -e '
const fs=require("fs");const p=process.argv[1];const raw=fs.readFileSync(p,"utf8");
let f;try{f=JSON.parse(raw)}catch(e){process.stderr.write("tenant.sh: "+p+": not valid JSON\n");process.exit(1)}
const v=f[process.argv[2]];process.stdout.write(v===undefined?"":(typeof v==="string"?v:JSON.stringify(v)))' "$(registry_file "$1")" "$2"
}
reg_set_status() {  # $1 org, $2 status — preserves every other field
  # Written to a sibling temp file and renamed over the target: a crash or a full disk
  # mid-write must never leave a truncated registry file that fails the next sync.
  node -e '
const fs=require("fs");const p=process.argv[1];const raw=fs.readFileSync(p,"utf8");
let f;try{f=JSON.parse(raw)}catch(e){process.stderr.write("tenant.sh: "+p+": not valid JSON\n");process.exit(1)}
f.status=process.argv[2];f.updated=new Date().toISOString().slice(0,10);
const tmp=p+".tmp."+process.pid;fs.writeFileSync(tmp,JSON.stringify(f,null,2)+"\n");fs.renameSync(tmp,p)' "$(registry_file "$1")" "$2"
}
require_registry() { [ -f "$(registry_file "$1")" ] || die "no registry file for '$1' at $(registry_file "$1") (run: add)"; }

cmd_add() {
  local org="${1:-}" keys="${2:-}" flag="${3:-}" extra="${4:-}"
  [ -n "$org" ] && [ -n "$keys" ] || usage
  # Opt in to the fixture key; a misspelling must not silently trust a key nobody asked for.
  case "$flag" in
    "" | --with-fixture-key) ;;
    *) die "add: unknown argument '$flag' (only --with-fixture-key is accepted)" ;;
  esac
  [ -z "$extra" ] || die "add: unexpected extra argument '$extra'"
  require_org "$org"; require_keys "$keys"; require_security
  [ ! -e "$(registry_file "$org")" ] || die "tenant '$org' already has a registry file at $(registry_file "$org") (to re-mint its tokens: rotate $org admin|verifier; to change keys: edit trustedOperators and sync)"
  local list="$keys"
  [ "$flag" != "--with-fixture-key" ] || list="$keys,$FIXTURE_KEY"
  mkdir -p "$TENANTS_DIR"
  node -e '
const fs=require("fs");const [p,org,list]=process.argv.slice(1);
const f={org_id:org,status:"active",displayName:"",contact:"",trustedOperators:list.split(","),tierCaps:{maxTier:"medium"},created:new Date().toISOString().slice(0,10),notes:""};
const tmp=p+".tmp."+process.pid;fs.writeFileSync(tmp,JSON.stringify(f,null,2)+"\n");fs.renameSync(tmp,p)' "$(registry_file "$org")" "$org" "$list"
  kc_put_minted "$org" admin
  kc_put_minted "$org" verifier
  echo "tenant '$org': registry file $(registry_file "$org"); tokens stored (keychain service $KEYCHAIN_SERVICE, accounts $(kc_account "$org" admin) / $(kc_account "$org" verifier))"
  cmd_sync
}

cmd_rotate() {
  local org="${1:-}" role="${2:-}" extra="${3:-}"
  [ -n "$org" ] || usage
  case "$role" in admin|verifier) ;; *) usage ;; esac
  [ -z "$extra" ] || die "rotate: unexpected extra argument '$extra'"
  require_org "$org"; require_registry "$org"; require_security
  kc_put_minted "$org" "$role"
  echo "tenant '$org': new $role token stored; the old one dies when the sync lands"
  cmd_sync
}

cmd_disable() {
  local org="${1:-}" extra="${2:-}"
  [ -n "$org" ] || usage
  [ -z "$extra" ] || die "disable: unexpected extra argument '$extra'"
  require_org "$org"; require_registry "$org"
  reg_set_status "$org" disabled
  echo "tenant '$org': quarantined (served on no route until enable); tell them it is deliberate"
  cmd_sync
}

cmd_enable() {
  local org="${1:-}" flag="${2:-}" extra="${3:-}"
  [ -n "$org" ] || usage
  [ -z "$extra" ] || die "enable: unexpected extra argument '$extra'"
  require_org "$org"; require_registry "$org"
  [ "$flag" = "--keys-retired" ] || die "enable refuses without --keys-retired: a quarantine usually exists because a key or a token was in question; confirm you retired or re-issued it (rotate / edit trustedOperators) before lifting it"
  reg_set_status "$org" active
  echo "tenant '$org': re-enabled"
  cmd_sync
}

cmd_remove() {
  local org="${1:-}" extra="${2:-}"
  [ -n "$org" ] || usage
  [ -z "$extra" ] || die "remove: unexpected extra argument '$extra'"
  require_org "$org"; require_registry "$org"; require_security
  reg_set_status "$org" removed
  kc_delete "$org" admin; kc_delete "$org" verifier
  echo "tenant '$org': tokens deleted, status=removed (registry file kept; the tenant's Durable Object and history are retained)"
  cmd_sync
}

# Print "<org> <role> <token>" for every active/disabled tenant — consumed on a pipe only.
tokens_for_sync() {
  local f b org status role token _xt
  # No token may reach an xtrace log; restore tracing on the way out.
  case "$-" in *x*) _xt=1; set +x ;; *) _xt=0 ;; esac
  for f in "$TENANTS_DIR"/*.json; do
    [ -e "$f" ] || die "no tenant registry files in $TENANTS_DIR — never push an empty map (the Worker rejects {}); add a tenant, or quarantine the remaining ones instead"
    # A directory named x.json, or an AppleDouble ._x.json, must not block every sync.
    [ -f "$f" ] || continue
    b="$(basename "$f")"
    case "$b" in .*) continue ;; esac
    case "$f" in *.policy.json) continue ;; esac
    org="$(basename "$f" .json)"; require_org "$org"
    status="$(reg_field "$org" status)"
    case "$status" in
      removed) continue ;;
      active|disabled) ;;
      *) die "$f: status must be active, disabled, or removed" ;;
    esac
    for role in admin verifier; do
      kc_has "$org" "$role" || die "no keychain token for '$org' ($role): run rotate $org $role"
      # Capture first: a failing $(kc_get …) inside printf does not trip set -e, and the
      # tenant would silently sync with an empty token.
      token="$(kc_get "$org" "$role")" || die "could not read the $role token for '$org' from the keychain (denied or locked?)"
      [ -n "$token" ] || die "the keychain returned an empty $role token for '$org'"
      printf '%s %s %s\n' "$org" "$role" "$token"
    done
  done
  if [ "$_xt" = 1 ]; then set -x; fi
  return 0
}

cmd_sync() {
  local arg="${1:-}" extra="${2:-}" dry=0
  # Parse positively: anything that is not exactly --dry-run must refuse, never push live.
  case "$arg" in
    "") ;;
    --dry-run) dry=1 ;;
    *) die "sync: unknown argument '$arg' (only --dry-run is accepted)" ;;
  esac
  [ -z "$extra" ] || die "sync: unexpected extra argument '$extra'"
  require_security
  echo "assembling TENANTS from $TENANTS_DIR (tokens from keychain service $KEYCHAIN_SERVICE)…" >&2
  if [ "$dry" = 1 ]; then
    tokens_for_sync | node "$SCRIPT_DIR/tenants-assemble.mjs" "$TENANTS_DIR" | node "$SCRIPT_DIR/tenants-check.mjs"
    echo "(dry run: not pushing)" >&2
    return 0
  fi
  # The map is assembled in node, validated, and STREAMED into wrangler — it never touches
  # disk or a shell variable. `wrangler secret put` has NO empty-value guard, so it must
  # never be the last stage of this pipeline: on a validator refusal it would read EOF and
  # put an EMPTY TENANTS (every tenant fails closed). tenants-put.mjs starts wrangler only
  # after a non-empty validated map has arrived. pipefail is set, so a failure anywhere
  # (keychain, assembly, validation, guard, wrangler) is loud.
  local rc=0
  tokens_for_sync | node "$SCRIPT_DIR/tenants-assemble.mjs" "$TENANTS_DIR" | node "$SCRIPT_DIR/tenants-check.mjs" --pass \
      | (cd "$WORKER_DIR" && node "$SCRIPT_DIR/tenants-put.mjs" "${WRANGLER_ENV[@]}") || rc=$?
  # What happened to the upload is read from what the put stage RECORDED, never from $rc. An
  # exit code cannot tell these three apart: the launcher reports a signalled child as exit 0,
  # a 130/143 can equally be a TERM that arrived before any uploader existed, and a
  # confirmation lost with the terminal looks exactly like a failure. Nothing can be looked up
  # afterwards either — `wrangler secret put` is write-only. So the put stage leaves a marker
  # under the lock: upload.confirmed only after wrangler said the upload landed, upload.pending
  # for as long as that is unknown, and neither when it never started an upload at all.
  if [ -e "$LOCK_DIR/upload.confirmed" ]; then
    case "$rc" in
      130|143) echo "done (an interrupt arrived after the put completed); secrets take effect on the next request" >&2 ;;
      *)       echo "done. Secrets take effect on the next request (no redeploy)." >&2 ;;
    esac
    exit "$rc"
  fi
  if [ -e "$LOCK_DIR/upload.pending" ] && marker_is_foreign "$LOCK_DIR/upload.pending"; then
    # Not this run's marker: some earlier run's put stage outlived its shell and recorded
    # itself here after this lock was taken. Nothing under it describes THIS sync, so it
    # cannot be reported as this sync's outcome — and the lock stays until someone has looked.
    echo "error: the upload marker under this lock belongs to another run (stale); the lock is retained — run: pilot/tenant.sh unlock" >&2
    [ "$rc" != 0 ] || rc=1
    exit "$rc"
  fi
  if [ -e "$LOCK_DIR/upload.pending" ]; then
    echo "error: the outcome of the upload is UNKNOWN — the intended map may or may not be live; the lock is retained. Recovery: pilot/tenant.sh unlock (refuses while the upload can still be running), then pilot/tenant.sh sync to re-put the intended map, then confirm on the Worker (/health tenants \"ok\" and one authenticated request)." >&2
    [ "$rc" != 0 ] || rc=1
    exit "$rc"
  fi
  # No marker at all: the pipeline stopped before the put stage started an upload (keychain,
  # assembly, or the validator refusing). That is a fact about THIS RUN and it is the only
  # thing that can be claimed here. What the Worker is serving is whatever the last upload put
  # there, which may have been days ago or may be a map whose own outcome was never confirmed;
  # `wrangler secret put` is write-only, so no command can check. Saying the previous map is
  # "still accepted" would assert exactly that unreadable thing — and would be flatly wrong
  # where the live secret is empty or was never configured.
  die "this run started no upload and changed nothing; the map the Worker holds is whatever was pushed last. Fix the error and re-run: pilot/tenant.sh sync"
}

# The unlock mutex. `unlock` must not take the registry lock — the registry lock is exactly
# what it is here to remove — but two unlocks running at once are their own race: both read a
# lock that looks clearable, one pauses, the other clears it and a waiting `sync` takes a NEW
# lock at the same path, and the one that paused then deletes that new owner's lock and the
# evidence under it. This second, much shorter mutex closes that: it is held from before the
# first check to after the directory is gone, so two unlocks serialise and a `sync` can only
# acquire once the whole clearing has finished.
UNLOCK_DIR="$TENANTS_DIR/.unlock"
UNLOCK_HELD=0
release_unlock() {
  [ "$UNLOCK_HELD" = 1 ] || return 0
  UNLOCK_HELD=0
  rm -f "$UNLOCK_DIR/pid"
  rmdir "$UNLOCK_DIR" 2>/dev/null || true
}

# Clear a lock that a previous run retained. Takes NO registry lock, and refuses while
# anything it can still see could be uploading.
cmd_unlock() {
  local force=0 foreign=0 p pgid putpid
  while [ $# -gt 0 ]; do
    case "$1" in
      --force) force=1 ;;
      *) die "unlock: unknown argument '$1' (only --force is accepted)" ;;
    esac
    shift
  done
  # A lock cannot exist without its registry directory, so there is nothing to serialise
  # against either.
  if [ ! -d "$TENANTS_DIR" ]; then
    echo "nothing to unlock: no lock directory at $LOCK_DIR"
    return 0
  fi
  mkdir "$UNLOCK_DIR" 2>/dev/null || die "another unlock is running for this environment (mutex $UNLOCK_DIR, pid $(cat "$UNLOCK_DIR/pid" 2>/dev/null)); wait for it — it removes that directory on its way out"
  UNLOCK_HELD=1
  trap 'release_unlock' EXIT
  echo "$$" > "$UNLOCK_DIR/pid" 2>/dev/null || true
  if [ ! -d "$LOCK_DIR" ]; then
    echo "nothing to unlock: no lock directory at $LOCK_DIR"
    return 0
  fi
  if [ -e "$LOCK_DIR/upload.pending" ]; then
    foreign=0
    marker_is_foreign "$LOCK_DIR/upload.pending" && foreign=1
    # `pgid` covers the WHOLE upload: the launcher, wrangler, and anything either started.
    # A group id answers for all of them at once and stays valid while any member lives,
    # which a launcher pid does not — kill the launcher and its uploader carries on talking
    # to Cloudflare with nothing recorded still alive.
    pgid="$(awk '/^pgid /{print $2}' "$LOCK_DIR/upload.pending" 2>/dev/null)"
    case "$pgid" in ''|*[!0-9]*) pgid="" ;; esac
    if [ -n "$pgid" ] && kill -0 -- -"$pgid" 2>/dev/null; then
      die "the upload's process group (pgid $pgid) is still alive; wait for it to finish, then re-run unlock"
    fi
    putpid="$(awk '/^put /{print $2}' "$LOCK_DIR/upload.pending" 2>/dev/null)"
    case "$putpid" in ''|*[!0-9]*) putpid="" ;; esac
    if [ -n "$putpid" ] && kill -0 "$putpid" 2>/dev/null; then
      die "the put stage (pid $putpid) is still alive; wait for it to finish, then re-run unlock"
    fi
    if [ "$foreign" = 1 ]; then
      # A marker stamped with a different token than the lock it sits in. Whatever it records
      # belongs to a run this lock knows nothing about, so its pids prove nothing either way
      # about whether an upload is in flight — the same position as tracking that was never
      # completed, and the same answer.
      [ "$force" = 1 ] || die "the upload marker under this lock belongs to another run (marker owner does not match $LOCK_DIR/owner); confirm no wrangler process is running (pgrep -fl wrangler), then run: pilot/tenant.sh unlock --force"
    elif [ -z "$pgid" ]; then
      # The marker exists but the group was never written into it: either the put stage died
      # between writing the marker and starting the upload, or the rewrite that records the
      # group failed. An upload may therefore be running that nothing here can see, and an
      # empty list of recorded pids is not permission to clear the lock — it is the one case
      # where only a person can look.
      [ "$force" = 1 ] || die "the upload's process group was never recorded; confirm no wrangler process is running (pgrep -fl wrangler), then run: pilot/tenant.sh unlock --force"
    fi
  fi
  # Always, marker or no marker: a live tenant.sh holds this lock legitimately and is about to
  # start an upload of its own. Skipping this check whenever a marker happened to exist is how
  # a lock gets cleared out from under a run that is still working.
  p="$(cat "$LOCK_DIR/pid" 2>/dev/null)" || p=""
  case "$p" in ''|*[!0-9]*) p="" ;; esac
  if [ -n "$p" ] && kill -0 "$p" 2>/dev/null; then
    die "another tenant.sh (pid $p) holds the lock"
  fi
  rm -f "$LOCK_DIR/upload.pending" "$LOCK_DIR/upload.confirmed" "$LOCK_DIR/owner" "$LOCK_DIR/pid"
  rmdir "$LOCK_DIR" 2>/dev/null || die "could not remove the lock directory $LOCK_DIR"
  echo "lock cleared; the live map is UNKNOWN until you re-sync — run: pilot/tenant.sh sync, then confirm on the Worker"
}

cmd_show() {
  local extra="${1:-}" f b org status a v
  [ -z "$extra" ] || die "show: unexpected extra argument '$extra'"
  printf '%-24s %-10s %-8s %s\n' "org_id" "status" "admin" "verifier"
  for f in "$TENANTS_DIR"/*.json; do
    [ -e "$f" ] || { echo "(no tenants in $TENANTS_DIR)"; return 0; }
    [ -f "$f" ] || continue
    b="$(basename "$f")"
    case "$b" in .*) continue ;; esac
    case "$f" in *.policy.json) continue ;; esac
    org="$(basename "$f" .json)"
    status="$(reg_field "$org" status)"
    if have_security; then
      a="$(kc_has "$org" admin && echo yes || echo no)"; v="$(kc_has "$org" verifier && echo yes || echo no)"
    else
      a="n/a"; v="n/a"
    fi
    printf '%-24s %-10s %-8s %s\n' "$org" "$status" "$a" "$v"
  done
}

cmd="${1:-}"
if [ $# -gt 0 ]; then shift; fi
# One positional past what each subcommand uses, so an unexpected extra argument is seen
# and refused rather than silently ignored.
# Every command but `show` and `unlock` mutates or assembles the map, so each takes the lock
# first — `sync --dry-run` included: it reads the registry and the keychain, and is only worth
# reporting if nothing was rewriting them underneath. `show` is read-only and never waits;
# `unlock` exists to remove a lock, so taking one would be a deadlock against itself.
case "$cmd" in
  add)     acquire_lock; cmd_add "${1:-}" "${2:-}" "${3:-}" "${4:-}" ;;
  rotate)  acquire_lock; cmd_rotate "${1:-}" "${2:-}" "${3:-}" ;;
  disable) acquire_lock; cmd_disable "${1:-}" "${2:-}" ;;
  enable)  acquire_lock; cmd_enable "${1:-}" "${2:-}" "${3:-}" ;;
  remove)  acquire_lock; cmd_remove "${1:-}" "${2:-}" ;;
  sync)    acquire_lock; cmd_sync "${1:-}" "${2:-}" ;;
  show)    cmd_show "${1:-}" ;;
  unlock)  cmd_unlock "$@" ;;
  *)       usage ;;
esac
