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
#   Every command except show takes a per-environment lock ($TENANTS_DIR/.lock); a stale lock
#   names itself; an interrupt (Ctrl-C/TERM) takes effect only after the in-flight put has
#   finished, so a half-pushed map cannot be raced.
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
  # quarantine. So when the recorded upload pid is still alive, keep the lock and say so.
  local _upload=""
  [ ! -f "$LOCK_DIR/upload.pid" ] || _upload="$(cat "$LOCK_DIR/upload.pid" 2>/dev/null || true)"
  if [ -n "$_upload" ] && kill -0 "$_upload" 2>/dev/null; then
    echo "error: lock retained at $LOCK_DIR: the upload (pid $_upload) may still be running; when it is gone, remove that directory and run: pilot/tenant.sh sync --dry-run" >&2
    return 0
  fi
  rm -f "$LOCK_DIR/upload.pid"
  rm -f "$LOCK_DIR/pid"
  rmdir "$LOCK_DIR" 2>/dev/null || true
}
on_signal() {  # $1 the signal name, INT or TERM
  # Bash defers a trapped signal that arrives while a FOREGROUND command is running until that
  # command returns, and the last stage of the sync pipeline does not return until wrangler has
  # exited. So by the time this body runs the in-flight put has either landed or failed, with
  # the lock held for all of it — an interrupt cannot leave a half-pushed map open to a race.
  echo "error: interrupted by SIG$1 after the in-flight command finished; run: pilot/tenant.sh sync --dry-run to see the state that was pushed" >&2
  # Exit with the conventional 128+signal code, and through the EXIT trap, so release_lock
  # still runs and still applies the retain rule above.
  case "$1" in
    INT) exit 130 ;;
    *)   exit 143 ;;
  esac
}
acquire_lock() {
  mkdir -p "$TENANTS_DIR" || die "could not create the registry directory $TENANTS_DIR"
  mkdir "$LOCK_DIR" 2>/dev/null || die "another tenant.sh is running for this environment (lock $LOCK_DIR); if none is, remove that directory and re-run"
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
  # The put stage records wrangler's pid in the lock directory, so release_lock can tell an
  # upload that has finished from one that may still be in flight.
  export TENANT_LOCK_DIR="$LOCK_DIR"
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
  if ! tokens_for_sync | node "$SCRIPT_DIR/tenants-assemble.mjs" "$TENANTS_DIR" | node "$SCRIPT_DIR/tenants-check.mjs" --pass \
      | (cd "$WORKER_DIR" && node "$SCRIPT_DIR/tenants-put.mjs" "${WRANGLER_ENV[@]}"); then
    die "the TENANTS map was NOT updated; the previous map (including any token you just rotated or removed) is STILL ACCEPTED by the Worker. Fix the error and re-run: $0 sync"
  fi
  echo "done. Secrets take effect on the next request (no redeploy)." >&2
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
# Every command but `show` mutates or assembles the map, so each takes the lock first —
# `sync --dry-run` included: it reads the registry and the keychain, and is only worth
# reporting if nothing was rewriting them underneath. `show` is read-only and never waits.
case "$cmd" in
  add)     acquire_lock; cmd_add "${1:-}" "${2:-}" "${3:-}" "${4:-}" ;;
  rotate)  acquire_lock; cmd_rotate "${1:-}" "${2:-}" "${3:-}" ;;
  disable) acquire_lock; cmd_disable "${1:-}" "${2:-}" ;;
  enable)  acquire_lock; cmd_enable "${1:-}" "${2:-}" "${3:-}" ;;
  remove)  acquire_lock; cmd_remove "${1:-}" "${2:-}" ;;
  sync)    acquire_lock; cmd_sync "${1:-}" "${2:-}" ;;
  show)    cmd_show "${1:-}" ;;
  *)       usage ;;
esac
