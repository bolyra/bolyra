#!/usr/bin/env bash
#
# tenant.sh — tenant lifecycle for the hosted-verify preview (the per-tenant TENANTS model).
#
# Thin wrapper over existing mechanisms — no new infra:
#   * the two bearer tokens per tenant live in the macOS keychain
#       service: bolyra-hosted-verify   (bolyra-hosted-verify-<env> when HOSTED_VERIFY_ENV is set)
#       account: tenant-<org_id>-admin / tenant-<org_id>-verifier
#   * the tenant registry is $TENANTS_DIR/<org_id>.json, OFF the git checkout: by default
#     $HOME/.bolyra/tenants-production, or $HOME/.bolyra/tenants-<env> under HOSTED_VERIFY_ENV
#     (one file per tenant; template pilot/partner-config.example.json at the repo root).
#     Files contain NO secrets — the org id, status, the tenant's trusted operator keys, and
#     human contact fields. A registry is usable only once it is initialized (the
#     $TENANTS_DIR/.initialized marker, written by `init` or `migrate`); every command that
#     changes it refuses until then.
#   * the Worker reads the TENANTS wrangler secret: one JSON object mapping org_id to
#     { admin_token, verifier_token, trusted_operators, disabled }. `sync` assembles it
#     from the registry + keychain, validates it with tenants-check.mjs (the rules the
#     Worker applies — any defect would fail EVERY tenant closed), and re-puts it.
#
# IMPORTANT: `wrangler secret put TENANTS` REPLACES the whole map. Never put it by hand —
# always go through `sync`, which includes every tenant whose status is active or disabled.
#
# Usage:
#   ./tenant.sh init                  initialize an EMPTY registry for a new environment
#                                     (refuses one that holds records, a .candidate/, or is
#                                     already initialized)
#   ./tenant.sh migrate --from <absolute dir>
#                                     bring an existing registry (e.g. the legacy checkout
#                                     directory pilot/tenants) into $TENANTS_DIR: copies every
#                                     <org_id>.json and *.policy.json into .candidate/,
#                                     validates the whole candidate (status, both keychain
#                                     tokens of every active/disabled record, the assembled
#                                     map), then renames each file in and writes the marker
#                                     LAST. Refuses a destination with records or a marker;
#                                     never modifies the source (delete it by hand afterwards)
#   ./tenant.sh add <org_id> <x:y>[,<x:y>...] [--with-fixture-key]
#                                     mint both tokens, store them, create the registry file
#                                     trusting ONLY the keys given, then sync; seeds the repo
#                                     conformance fixture key only with --with-fixture-key
#                                     (preview-only: its private half is public)
#   ./tenant.sh rotate <org_id> admin|verifier --confirm
#                                     mint a NEW token for that role, then sync (a REMOVED
#                                     tenant: store it and skip the sync — the map would not
#                                     change; set status active and sync to bring it back).
#                                     There is NO overlap window (one token per role): from
#                                     that sync on, the partner's requests under the old
#                                     token are 401 until they deploy the new one — so it
#                                     refuses without --confirm, which records that the
#                                     switch-over has been scheduled with the partner
#   ./tenant.sh disable <org_id>      quarantine — the entry stays with "disabled": true and
#                                     the tenant is served on NO route (verify: 500
#                                     internal_error verdict; registry routes: 503
#                                     tenant_disabled), then sync
#   ./tenant.sh enable <org_id> --keys-retired
#                                     lift the quarantine; refuses without the flag, which
#                                     records that any operator key the quarantine was
#                                     about has been retired or re-issued
#   ./tenant.sh remove <org_id> [--last]
#                                     drop the tenant from the map (status=removed, then
#                                     sync) and delete both tokens from the keychain ONLY
#                                     once that upload is confirmed. No upload started: the
#                                     status is restored and the tokens kept. Outcome unknown:
#                                     lock, tokens and status=removed all stay; recover the
#                                     lock and re-run remove. The registry file is kept; the
#                                     tenant's Durable Object and its history are NOT deleted.
#                                     Removing the LAST tenant (no other record is active or
#                                     disabled — a quarantined tenant still occupies the map)
#                                     pushes the EMPTY map {}: every request is denied (401)
#                                     and /health reports tenant_count 0. It is refused
#                                     unless --last is given (a --last on a tenant that is
#                                     not the last one is noted and runs a plain sync)
#   ./tenant.sh sync [--dry-run] [--allow-empty]
#                                     rebuild TENANTS from registry + keychain, validate,
#                                     re-put (dry-run: validate and report, push nothing).
#                                     When every record is removed the map is {} and sync
#                                     refuses unless --allow-empty is given; a directory with
#                                     NO record files is always refused
#   ./tenant.sh show                  the registry directory and whether it is initialized;
#                                     tenants, status, keychain presence
#   Every command except show takes a per-environment lock ($TENANTS_DIR/.lock) for its whole
#   run. An interrupt (Ctrl-C/TERM aimed at the shell or the put stage) takes effect only
#   after the in-flight put has finished; one that reaches the put stage before it has
#   started wrangler cancels the upload instead (nothing is sent). The lock is released only when wrangler confirms the
#   upload or no upload was started; otherwise it stays and the outcome is unknown — there is
#   no automatic unlock; see pilot/RUNBOOK.md, "Recovering a retained lock".
#
# Environment:
#   HOSTED_VERIFY_ENV=<name>    target that named Worker environment (`--env=<name>`; keychain
#                               service bolyra-hosted-verify-<name>; registry directory
#                               $HOME/.bolyra/tenants-<name>); must match ^[a-z][a-z0-9-]{0,31}$
#                               and must not be `production` (production is the default: unset)
#   TENANTS_DIR=<dir>           override the registry directory (the lock is <dir>/.lock)
#
# Tokens are NEVER printed by this script. To hand a token to a partner over a secure
# channel, run (yourself, deliberately):
#   security find-generic-password -s bolyra-hosted-verify -a tenant-<org_id>-verifier -w
set -euo pipefail

die() { echo "error: $*" >&2; exit 1; }
usage() { awk 'NR>1 && /^set -euo pipefail/{exit} NR>1' "$0" | sed 's/^# \{0,1\}//'; exit 2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKER_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
ENV_NAME="${HOSTED_VERIFY_ENV:-}"
if [ -n "$ENV_NAME" ]; then
  # The name becomes a keychain service, a directory, and a wrangler `--env=` — validate it
  # here rather than discover it as a mis-targeted push or a stray directory.
  [[ "$ENV_NAME" =~ ^[a-z][a-z0-9-]{0,31}$ ]] || die "HOSTED_VERIFY_ENV must match ^[a-z][a-z0-9-]{0,31}\$ (got '$ENV_NAME')"
  # The production registry is tenants-production; a named environment called "production"
  # would share its directory and lock while writing a different Worker and keychain service.
  [ "$ENV_NAME" != production ] || die "HOSTED_VERIFY_ENV=production is not a named environment: production is the default; leave HOSTED_VERIFY_ENV unset"
  KEYCHAIN_SERVICE="bolyra-hosted-verify-$ENV_NAME"
  WRANGLER_ENV=("--env=$ENV_NAME")
else
  KEYCHAIN_SERVICE="bolyra-hosted-verify"
  # Production is the top-level environment. Named explicitly (`--env=`) so that a
  # CLOUDFLARE_ENV in the shell can never redirect a production sync to staging, and
  # wrangler does not warn about an unspecified environment.
  WRANGLER_ENV=("--env=")
fi
# The registry lives OFF the git checkout (E2). Derived from the checkout, it followed whichever
# worktree ran the script: a removed worktree took the real records with it, and two worktrees
# took two different locks while writing the one Worker. One directory per environment under
# $HOME, overridable, and never created implicitly — see `init` / `migrate`.
if [ -z "${TENANTS_DIR:-}" ]; then
  [ -n "${HOME:-}" ] || die "HOME is not set; set TENANTS_DIR to the registry directory"
  TENANTS_DIR="$HOME/.bolyra/tenants-${ENV_NAME:-production}"
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
# The registry is usable only with this marker: written by `init` (a new, empty environment) or
# LAST by `migrate` (after every record has been committed). Records without it are an
# interrupted migrate, which nothing repairs automatically.
MARKER_FILE="$TENANTS_DIR/.initialized"
# `migrate` assembles the complete candidate here, INSIDE the registry directory, so that its
# commit is a same-filesystem rename per file (the directory itself — and the lock in it — is
# never replaced).
CANDIDATE_DIR="$TENANTS_DIR/.candidate"
# The .candidate/ this run created, removed on the way out (release_lock) while it is still
# only a candidate. Cleared the moment the commit starts: a half-committed candidate is the
# evidence the interrupted-migrate instruction relies on.
MIGRATE_CLEANUP=""
# INTERRUPTED records the first INT/TERM this run received (0 = none). CRITICAL=1 marks a
# section that must finish its local bookkeeping before the run may exit — `remove` between
# changing the registry and acting on the upload's outcome — so a signal there is recorded and
# acted on by deferred_exit at the end of the section instead of exiting halfway through it.
INTERRUPTED=0
CRITICAL=0
# `remove` keeps a byte-for-byte copy of the registry file it mutates, so an upload that never
# started leaves the tracked file exactly as it was. Removed on the way out (release_lock).
REMOVE_BACKUP=""
release_lock() {
  [ -z "$REMOVE_BACKUP" ] || rm -f "$REMOVE_BACKUP"
  [ -z "$MIGRATE_CLEANUP" ] || rm -rf "$MIGRATE_CLEANUP"
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
    echo "error: lock retained at $LOCK_DIR: the last upload was not confirmed complete (see $LOCK_DIR/upload.pending) and what is live is unknown; see pilot/RUNBOOK.md, \"Recovering a retained lock\"" >&2
    return 0
  fi
  # The confirmation marker has reported what it had to report by the time the lock goes; it
  # must not outlive the lock it sits in, or a later run could read a stale confirmation as
  # the answer for its own upload.
  rm -f "$LOCK_DIR/upload.confirmed"
  rmdir "$LOCK_DIR" 2>/dev/null || true
}
on_signal() {  # $1 the signal name, INT or TERM
  [ "$INTERRUPTED" != 0 ] || INTERRUPTED="$1"
  if [ "$CRITICAL" = 1 ]; then
    # Recorded, not acted on: the section in progress checks INTERRUPTED before it starts an
    # upload (and cancels if it has not), finishes whatever an upload that did start requires
    # locally, and then leaves through deferred_exit.
    echo "error: interrupted by SIG$1; finishing the current step first (nothing new is started)" >&2
    return 0
  fi
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
deferred_exit() {  # the exit a signal inside a CRITICAL section was owed; a no-op without one
  [ "$INTERRUPTED" != 0 ] || return 0
  echo "error: exiting because of the earlier SIG$INTERRUPTED" >&2
  case "$INTERRUPTED" in
    INT) exit 130 ;;
    *)   exit 143 ;;
  esac
}
# acquire_lock [create] — only `init` and `migrate` may create the registry directory; for every
# other command an absent directory is an uninitialized registry, refused before anything —
# the lock included — is created.
acquire_lock() {
  if [ "${1:-}" = create ]; then
    mkdir -p "$TENANTS_DIR" || die "could not create the registry directory $TENANTS_DIR"
  elif [ ! -d "$TENANTS_DIR" ]; then
    die "$(uninitialized_msg -)"
  fi
  # An existing lock blocks this run whatever its age: nothing local can tell a lock a live run
  # is holding from one a previous run retained because an upload's outcome is unknown, and
  # clearing either on a timer is how the interleaving the lock exists to prevent happens.
  mkdir "$LOCK_DIR" 2>/dev/null || die "another tenant.sh is running for this environment, or a previous run left its lock because an upload's outcome is unknown (lock $LOCK_DIR); see pilot/RUNBOOK.md, \"Recovering a retained lock\""
  LOCK_HELD=1
  # Installed only once the lock is ours. `die` exits, so every refusal path releases it too.
  trap 'release_lock' EXIT
  # Ctrl-C and TERM are taken with the lock, not left to the default disposition: the default
  # kills this shell the moment the in-flight command returns, running the EXIT trap while the
  # upload child is still alive. Handled, the interrupt is reported after that command has
  # finished and still leaves through the EXIT trap.
  trap 'on_signal INT' INT
  trap 'on_signal TERM' TERM
  # The put stage records the upload in the lock directory before it starts one, so
  # release_lock can tell a confirmed upload from one that may still be in flight.
  export TENANT_LOCK_DIR="$LOCK_DIR"
}

# has_registry_content — does the directory hold anything a migrate commits (any non-dot *.json
# regular file: a record or a policy file) or a .candidate/? Names only; never a token.
has_registry_content() {
  local f b
  [ ! -e "$CANDIDATE_DIR" ] || return 0
  for f in "$TENANTS_DIR"/*.json; do
    [ -f "$f" ] || continue
    b="$(basename "$f")"
    case "$b" in .*) continue ;; esac
    return 0
  done
  return 1
}
uninitialized_msg() {  # $1 the command, named only when the directory holds records
  if has_registry_content; then
    echo "$1: $TENANTS_DIR has records but no marker: it looks like an interrupted migrate; delete them and re-run migrate, or move them aside (pilot/RUNBOOK.md, \"Initializing or migrating the registry\")"
  else
    echo "registry $TENANTS_DIR is not initialized: run 'tenant.sh init' for a new environment or 'tenant.sh migrate --from <dir>' to bring existing records over"
  fi
}
# Checked with the lock HELD, so a concurrent init or migrate cannot interleave with the check.
require_initialized() {  # $1 the command
  [ -f "$MARKER_FILE" ] || die "$(uninitialized_msg "$1")"
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
# Fails when the keychain refuses (denied, locked): a token that was meant to be destroyed and
# was not must be reported, never swallowed. Exit 44 (errSecItemNotFound) means the item is
# already gone — someone removed it in the meantime — which is the outcome wanted, not a
# failure. security's own error text holds no secret and is shown for a real failure only.
kc_delete() {
  local rc=0 err
  err="$(security delete-generic-password -s "$KEYCHAIN_SERVICE" -a "$(kc_account "$1" "$2")" 2>&1 >/dev/null)" || rc=$?
  [ "$rc" != 44 ] || return 0
  if [ "$rc" != 0 ]; then printf '%s\n' "$err" >&2; fi
  return "$rc"
}
# Put a registry file back from a copy, atomically (sibling temp file + rename, as reg_set_status).
reg_restore() {  # $1 org, $2 the copy
  local f; f="$(registry_file "$1")"
  cp "$2" "$f.tmp.$$" && mv -f "$f.tmp.$$" "$f"
}
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
  [ ! -e "$(registry_file "$org")" ] || die "tenant '$org' already has a registry file at $(registry_file "$org") (to re-mint its tokens: rotate $org admin|verifier --confirm; to change keys: edit trustedOperators and sync)"
  local list="$keys"
  [ "$flag" != "--with-fixture-key" ] || list="$keys,$FIXTURE_KEY"
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
  local org="${1:-}" role="${2:-}" flag="${3:-}" extra="${4:-}" impact
  [ -n "$org" ] || usage
  case "$role" in admin|verifier) ;; *) usage ;; esac
  [ -z "$extra" ] || die "rotate: unexpected extra argument '$extra'"
  # E19: the Worker holds ONE token per role, so a rotation has no overlap window — the old
  # token stops working the moment the sync lands. Refused, before anything changes, until the
  # operator confirms the partner has been scheduled to deploy the new one.
  impact="requests under the $role token return 401 from the next sync until the partner deploys the new token"
  case "$flag" in
    --confirm) ;;
    "") die "rotate: $impact; re-run with --confirm after scheduling it with them" ;;
    *) die "rotate: unknown argument '$flag' (only --confirm is accepted)" ;;
  esac
  require_org "$org"; require_registry "$org"; require_security
  local status
  status="$(reg_field "$org" status)" || die "rotate: could not read $(registry_file "$org")"
  kc_put_minted "$org" "$role"
  echo "warning: $impact" >&2
  # A removed tenant is not in the map, so a sync would change nothing — and after
  # `remove --last` an all-removed registry would refuse it and blame a flag rotate does not
  # take. This is the RUNBOOK's bring-it-back path: re-mint, then set status active and sync.
  if [ "$status" = removed ]; then
    echo "tenant '$org': new $role token stored; tenant is removed; the map is unchanged — set status active and run sync to bring it back"
    exit 0
  fi
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
  local org="${1:-}" flag="${2:-}" extra="${3:-}" prev role outcome=0 present="" failed="" others
  [ -n "$org" ] || usage
  case "$flag" in
    "" | --last) ;;
    *) die "remove: unknown argument '$flag' (only --last is accepted)" ;;
  esac
  [ -z "$extra" ] || die "remove: unexpected extra argument '$extra'"
  require_org "$org"; require_registry "$org"; require_security
  # The tokens are the only local recovery material for this tenant: while the old map might
  # still be live, they are what re-syncs it. So they are deleted only once the upload that
  # drops the tenant is CONFIRMED, and the registry file is put back when no upload started.
  #
  # Read-only preparation first, OUTSIDE the critical section: nothing has changed yet, so an
  # interrupt or a refusal here may simply end the run.
  prev="$(reg_field "$org" status)"
  case "$prev" in
    active|disabled|removed) ;;
    *) die "$(registry_file "$org"): status must be active, disabled, or removed" ;;
  esac
  # The last tenant (E13): if no OTHER record is active or disabled (a quarantined tenant still
  # occupies the map), this removal pushes the EMPTY map {} and every request is denied. That
  # takes a deliberate --last, checked here, before anything has changed.
  count_records "$org" || die "remove: could not read the registry in $TENANTS_DIR; nothing changed"
  # Kept: do_sync recounts into the same globals.
  others="$LIVE_RECORDS"
  if [ "$others" = 0 ] && [ "$flag" != "--last" ]; then
    die "remove: '$org' is the last tenant; removing it leaves an EMPTY map (every request denied). Re-run with --last to confirm"
  fi
  if [ "$others" != 0 ] && [ "$flag" = "--last" ]; then
    echo "note: --last given, but '$org' is not the last tenant; the map stays non-empty" >&2
  fi
  # Which items exist now decides which deletes are owed afterwards: one already absent is
  # not a failure to delete.
  for role in admin verifier; do
    if kc_has "$org" "$role"; then present="$present $role"; fi
  done
  REMOVE_BACKUP="$(mktemp "${TMPDIR:-/tmp}/tenant-remove.XXXXXX")" || die "remove: could not create a temporary copy of the registry file"
  cp "$(registry_file "$org")" "$REMOVE_BACKUP" || die "remove: could not copy the registry file before changing it"
  CRITICAL=1
  # The one mutation. Errexit must not end the run here: a terminal Ctrl-C kills the node doing
  # the write (the trap only records it), and set -e would then exit before anything below put
  # the file back or reported. The write is atomic, so the file is either as it was or removed.
  if ! reg_set_status "$org" removed; then
    cmp -s "$REMOVE_BACKUP" "$(registry_file "$org")" || reg_restore "$org" "$REMOVE_BACKUP" || true
    CRITICAL=0
    echo "error: remove: could not update the registry file; nothing was uploaded and the tokens are kept (if show still says removed, re-run remove, or set \"status\" back by hand)" >&2
    deferred_exit
    exit 1
  fi
  # --allow-empty only for the empty map this removal actually produces (others = 0 implies
  # --last, or the run died above); a --last on a non-last tenant is a plain sync.
  if [ "$others" = 0 ]; then
    do_sync --allow-empty || outcome=$?
  else
    do_sync || outcome=$?
  fi
  case "$outcome" in
    0)
      for role in $present; do
        kc_delete "$org" "$role" || failed="$failed $(kc_account "$org" "$role")"
      done
      if [ -n "$failed" ]; then
        echo "error: tenant '$org' is out of the live map (status=removed), but these keychain items could not be deleted and are STALE — delete them by hand (security delete-generic-password -s $KEYCHAIN_SERVICE -a <account>):$failed" >&2
      elif [ -n "$present" ]; then
        echo "tenant '$org': removed from the map, tokens deleted, status=removed (registry file kept; the tenant's Durable Object and history are retained)"
      else
        echo "tenant '$org': removed from the map, status=removed; no tokens were left in the keychain to delete (registry file kept; the tenant's Durable Object and history are retained)"
      fi
      ;;
    2)
      # Byte for byte, `updated` included: a remove that uploaded nothing leaves no diff.
      reg_restore "$org" "$REMOVE_BACKUP" || echo "error: remove: could not put $(registry_file "$org") back; set \"status\" to $prev by hand (nothing was uploaded)" >&2
      echo "error: remove: nothing changed — this run started no upload, so tenant '$org' is back to status=$prev and its tokens are kept; the map the Worker holds is whatever was pushed last. Fix the error and re-run: pilot/tenant.sh remove $org" >&2
      ;;
    *)
      echo "error: remove: the upload's outcome is UNKNOWN, so tenant '$org' stays status=removed and its tokens are KEPT (the old map, with this tenant in it, may still be live). Follow pilot/RUNBOOK.md, \"Recovering a retained lock\", then re-run: pilot/tenant.sh remove $org" >&2
      ;;
  esac
  CRITICAL=0
  # Stale tokens decide the exit code over a recorded interrupt: 130 would read as "interrupted"
  # and hide the half-finished cleanup. The interrupt is still reported.
  if [ "$outcome" = 0 ] && [ -n "$failed" ]; then
    [ "$INTERRUPTED" = 0 ] || echo "error: SIG$INTERRUPTED also arrived during this run; exiting 1 for the stale keychain items above" >&2
    exit 1
  fi
  deferred_exit
  case "$outcome" in
    0) exit "$SYNC_RC" ;;
    2) exit 1 ;;
    *) [ "$SYNC_RC" != 0 ] || SYNC_RC=1; exit "$SYNC_RC" ;;
  esac
}

# registry_orgs — the ONE definition of a registry record: print one org id per line for every
# <org>.json in $TENANTS_DIR that is a regular file, not a dotfile (an AppleDouble ._x.json) and
# not a *.policy.json. A directory named x.json and any other file are not records either. The
# same filter as tenants-assemble.mjs (tenant-lock-check (e0) holds the two to it). Org ids only —
# never a token. Callers read the list on fd 3 so nothing in the loop body can drain it.
registry_orgs() {
  local f b
  for f in "$TENANTS_DIR"/*.json; do
    [ -f "$f" ] || continue
    b="$(basename "$f")"
    case "$b" in .*|*.policy.json) continue ;; esac
    printf '%s\n' "${b%.json}"
  done
}

# count_records [<org_to_exclude>] — count the registry's record files (RECORD_FILES) and those
# whose status is active or disabled (LIVE_RECORDS: the tenants the assembled map will hold; a
# quarantined tenant still occupies the map). Returns 1, with the reason on stderr, on a record
# it cannot read, and never dies — so that do_sync, called inside remove's critical section,
# returns 2 and remove restores the record. Registry files hold no secrets.
RECORD_FILES=0
LIVE_RECORDS=0
count_records() {
  local skip="${1:-}" orgs org status
  RECORD_FILES=0
  LIVE_RECORDS=0
  orgs="$(registry_orgs)"
  while IFS= read -r org <&3; do
    [ -n "$org" ] || continue
    RECORD_FILES=$((RECORD_FILES + 1))
    [ "$org" != "$skip" ] || continue
    status="$(reg_field "$org" status)" || return 1
    case "$status" in
      removed) ;;
      active|disabled) LIVE_RECORDS=$((LIVE_RECORDS + 1)) ;;
      *) echo "error: $(registry_file "$org"): status must be active, disabled, or removed" >&2; return 1 ;;
    esac
  done 3<<< "$orgs"
  return 0
}

# Print "<org> <role> <token>" for every active/disabled tenant — consumed on a pipe only.
tokens_for_sync() {
  local orgs org status role token _xt
  # No token may reach an xtrace log; restore tracing on the way out.
  case "$-" in *x*) _xt=1; set +x ;; *) _xt=0 ;; esac
  # Org ids only in this variable (registry_orgs); tokens go straight from kc_get to printf.
  orgs="$(registry_orgs)"
  # Backstop only: do_sync refuses zero record files before this pipeline starts (a `die`
  # here ends just this stage), and tenants-assemble.mjs refuses them inside it.
  [ -n "$orgs" ] || die "no tenant registry files in $TENANTS_DIR — refusing to build a map from an empty (or wrong) registry directory; check TENANTS_DIR / HOSTED_VERIFY_ENV, or add a tenant"
  while IFS= read -r org <&3; do
    [ -n "$org" ] || continue
    require_org "$org"
    status="$(reg_field "$org" status)"
    case "$status" in
      removed) continue ;;
      active|disabled) ;;
      *) die "$(registry_file "$org"): status must be active, disabled, or removed" ;;
    esac
    for role in admin verifier; do
      kc_has "$org" "$role" || die "no keychain token for '$org' ($role): run rotate $org $role --confirm"
      # Capture first: a failing $(kc_get …) inside printf does not trip set -e, and the
      # tenant would silently sync with an empty token.
      token="$(kc_get "$org" "$role")" || die "could not read the $role token for '$org' from the keychain (denied or locked?)"
      [ -n "$token" ] || die "the keychain returned an empty $role token for '$org'"
      printf '%s %s %s\n' "$org" "$role" "$token"
    done
  done 3<<< "$orgs"
  if [ "$_xt" = 1 ]; then set -x; fi
  return 0
}

# do_sync [--dry-run] [--allow-empty] — rebuild, validate and put TENANTS, and RETURN what
# happened to the upload so a caller can act on it (every message is printed here). An
# all-removed registry assembles to the EMPTY map {} (valid, but every request is denied): it is
# refused (2, not started) unless --allow-empty is given, which is then forwarded to the put
# stage — the put stage refuses {} on its own without it.
#   0  confirmed    wrangler confirmed the upload (upload.confirmed); SYNC_RC holds the
#                   pipeline's exit code (130/143 when the put stage deferred an interrupt)
#   2  not started  nothing was sent: the keychain, the assembler or the validator refused, or
#                   an interrupt arrived before the upload started
#   3  unknown      upload.pending: the lock is retained and what is live is unknown
# A dry run returns 0 or exits with the failing stage's code, as before. Callers invoke it as
# `do_sync || outcome=$?`, which turns errexit off inside it: every failure path below is
# therefore explicit (die, or a captured rc), none relies on set -e.
SYNC_RC=0
do_sync() {
  local arg dry=0 allow_empty=0 rc=0
  SYNC_RC=0
  # Parse positively: anything that is not exactly --dry-run or --allow-empty must refuse,
  # never push live. Each at most once; empty strings are the dispatcher's unused positionals.
  for arg in "$@"; do
    case "$arg" in
      "") ;;
      --dry-run) [ "$dry" = 0 ] || die "sync: unexpected extra argument '$arg'"; dry=1 ;;
      --allow-empty) [ "$allow_empty" = 0 ] || die "sync: unexpected extra argument '$arg'"; allow_empty=1 ;;
      *) die "sync: unknown argument '$arg' (only --dry-run and --allow-empty are accepted)" ;;
    esac
  done
  require_security
  # Cancellation point 1, before anything is assembled: an interrupt that has already been
  # recorded (possible only inside a CRITICAL section — elsewhere on_signal has exited) means
  # nothing new is started.
  if [ "$INTERRUPTED" != 0 ]; then
    echo "error: interrupted by SIG$INTERRUPTED before the upload started; nothing was assembled or uploaded" >&2
    return 2
  fi
  # The empty-map gate, decided from the RECORD FILES before anything is assembled (the map
  # itself never enters a shell variable).
  if ! count_records; then
    echo "error: sync: could not read the registry in $TENANTS_DIR; nothing was assembled or uploaded" >&2
    return 2
  fi
  # Zero record files is refused whatever the flags say — a wrong TENANTS_DIR far more often
  # than a deliberate empty map. Decided HERE, not only in tokens_for_sync: that one runs as a
  # pipeline stage, and its `die` ends only its own subshell while the stages after it carry on.
  if [ "$RECORD_FILES" = 0 ]; then
    echo "error: no tenant registry files in $TENANTS_DIR — refusing to build a map from an empty (or wrong) registry directory; check TENANTS_DIR / HOSTED_VERIFY_ENV, or add a tenant" >&2
    return 2
  fi
  if [ "$LIVE_RECORDS" = 0 ] && [ "$allow_empty" = 0 ]; then
    echo "error: sync: the assembled map is empty (every tenant is removed); pass --allow-empty to push it deliberately" >&2
    return 2
  fi
  local put_args=("${WRANGLER_ENV[@]}")
  [ "$allow_empty" = 0 ] || put_args+=(--allow-empty)
  echo "assembling TENANTS from $TENANTS_DIR (tokens from keychain service $KEYCHAIN_SERVICE)…" >&2
  if [ "$dry" = 1 ]; then
    tokens_for_sync | node "$SCRIPT_DIR/tenants-assemble.mjs" "$TENANTS_DIR" | node "$SCRIPT_DIR/tenants-check.mjs" || exit $?
    echo "(dry run: not pushing)" >&2
    return 0
  fi
  # Cancellation point 2, immediately before the pipeline that ends in the put stage. The
  # pipeline starts its stages together, so from here on an interrupt that reaches the put
  # stage while it is still reading the map is cancelled THERE (exit 75, no marker), and one
  # that reaches only this shell is deferred by bash until the pipeline has returned.
  if [ "$INTERRUPTED" != 0 ]; then
    echo "error: interrupted by SIG$INTERRUPTED before the upload started; nothing was uploaded" >&2
    return 2
  fi
  # The map is assembled in node, validated, and STREAMED into wrangler — it never touches
  # disk or a shell variable. `wrangler secret put` has NO empty-value guard, so it must
  # never be the last stage of this pipeline: on a validator refusal it would read EOF and
  # put an EMPTY TENANTS (every tenant fails closed). tenants-put.mjs starts wrangler only
  # after a validated map has arrived — and an empty one ({}) only with --allow-empty.
  # pipefail is set, so a failure anywhere
  # (keychain, assembly, validation, guard, wrangler) is loud.
  tokens_for_sync | node "$SCRIPT_DIR/tenants-assemble.mjs" "$TENANTS_DIR" | node "$SCRIPT_DIR/tenants-check.mjs" --pass \
      | (cd "$WORKER_DIR" && node "$SCRIPT_DIR/tenants-put.mjs" "${put_args[@]}") || rc=$?
  SYNC_RC="$rc"
  # What happened to the upload is read from what the put stage RECORDED, never from $rc. An
  # exit code cannot tell these three apart: the launcher reports a signalled child as exit 0,
  # a 130/143 can equally be a TERM that arrived before any uploader existed, and a
  # confirmation lost with the terminal looks exactly like a failure. Nothing can be looked up
  # afterwards either — `wrangler secret put` is write-only. So the put stage leaves a marker
  # under the lock: upload.confirmed only after wrangler said the upload landed, upload.pending
  # for as long as that is unknown, and neither when it never started an upload at all.
  if [ -e "$LOCK_DIR/upload.confirmed" ]; then
    # What is reported is what WRANGLER reported. Nothing here has observed the Worker, and
    # nothing here can establish when the request took effect relative to any other.
    if [ "$INTERRUPTED" != 0 ]; then
      echo "done (an interrupt arrived while the upload was under way; it ran to completion and was confirmed); secrets take effect on the next request" >&2
    else
      case "$rc" in
        130|143) echo "done (an interrupt arrived after the put completed); secrets take effect on the next request" >&2 ;;
        *)       echo "done. Secrets take effect on the next request (no redeploy)." >&2 ;;
      esac
    fi
    return 0
  fi
  if [ -e "$LOCK_DIR/upload.pending" ]; then
    echo "error: the outcome of the upload is UNKNOWN — the intended map may or may not be live; the lock is retained. Follow pilot/RUNBOOK.md, \"Recovering a retained lock\"." >&2
    return 3
  fi
  # No marker at all: the pipeline stopped before the put stage started an upload (keychain,
  # assembly, the validator refusing, or an interrupt the put stage cancelled on — exit 75).
  # That is a fact about THIS RUN and it is the only thing that can be claimed here. What the
  # Worker is serving is whatever the last upload put there, which may have been days ago or
  # may be a map whose own outcome was never confirmed; `wrangler secret put` is write-only, so
  # no command can check. Saying the previous map is "still accepted" would assert exactly
  # that unreadable thing — and would be flatly wrong where the live secret is empty or was
  # never configured.
  if [ "$INTERRUPTED" != 0 ] || [ "$rc" = 75 ]; then
    echo "error: interrupted before the upload started; nothing was uploaded" >&2
  fi
  return 2
}

cmd_sync() {
  local outcome=0
  do_sync "$@" || outcome=$?
  case "$outcome" in
    0) exit "$SYNC_RC" ;;
    3) [ "$SYNC_RC" != 0 ] || SYNC_RC=1; exit "$SYNC_RC" ;;
    *) die "this run started no upload and changed nothing; the map the Worker holds is whatever was pushed last. Fix the error and re-run: pilot/tenant.sh sync" ;;
  esac
}

cmd_show() {
  local extra="${1:-}" orgs org status a v
  [ -z "$extra" ] || die "show: unexpected extra argument '$extra'"
  # Read-only and lock-free, so it works on an uninitialized registry — and says so.
  if [ -f "$MARKER_FILE" ]; then
    echo "registry: $TENANTS_DIR (initialized)"
  elif has_registry_content; then
    echo "registry: $TENANTS_DIR (not initialized: has records but no marker, an interrupted migrate; see pilot/RUNBOOK.md, \"Initializing or migrating the registry\")"
  else
    echo "registry: $TENANTS_DIR (not initialized: run 'tenant.sh init' for a new environment or 'tenant.sh migrate --from <dir>')"
  fi
  printf '%-24s %-10s %-8s %s\n' "org_id" "status" "admin" "verifier"
  orgs="$(registry_orgs)"
  [ -n "$orgs" ] || { echo "(no tenants in $TENANTS_DIR)"; return 0; }
  while IFS= read -r org <&3; do
    [ -n "$org" ] || continue
    status="$(reg_field "$org" status)"
    if have_security; then
      a="$(kc_has "$org" admin && echo yes || echo no)"; v="$(kc_has "$org" verifier && echo yes || echo no)"
    else
      a="n/a"; v="n/a"
    fi
    printf '%-24s %-10s %-8s %s\n' "$org" "$status" "$a" "$v"
  done 3<<< "$orgs"
}

cmd_init() {
  local extra="${1:-}"
  [ -z "$extra" ] || die "init: unexpected extra argument '$extra'"
  acquire_lock create
  [ ! -f "$MARKER_FILE" ] || die "init: $TENANTS_DIR is already initialized"
  # Records without the marker are a migrate that did not finish: blessing them would make a
  # partial registry look complete. Only an empty directory (the lock aside) is initialized.
  if has_registry_content; then die "$(uninitialized_msg init)"; fi
  : > "$MARKER_FILE" || die "init: could not write $MARKER_FILE"
  echo "registry $TENANTS_DIR initialized (no tenants yet; add one with: pilot/tenant.sh add <org_id> <x:y>)"
}

# migrate_validate <source dir> — validate the COMPLETE candidate in $CANDIDATE_DIR before any of
# it is committed: every record's name and status, both keychain tokens of every active or
# disabled record (presence only), then the assembled map through the same assembler and
# validator `sync --dry-run` uses (tokens stream through the pipe; none enters a variable here,
# none is printed). Returns 1 with the reason on stderr, naming the SOURCE file.
migrate_validate() {
  local src="$1" dest="$TENANTS_DIR" orgs org status role rc=0
  TENANTS_DIR="$CANDIDATE_DIR"
  orgs="$(registry_orgs)"
  while IFS= read -r org <&3; do
    [ -n "$org" ] || continue
    if ! [[ "$org" =~ ^[a-z0-9][a-z0-9-]{1,62}$ ]] || [ "$org" = unauthenticated ]; then
      echo "error: migrate: $src/$org.json: the file name is not a valid org id" >&2; rc=1; break
    fi
    if ! status="$(reg_field "$org" status)"; then
      echo "error: migrate: $src/$org.json: not valid JSON" >&2; rc=1; break
    fi
    case "$status" in
      removed) continue ;;
      active|disabled) ;;
      *) echo "error: migrate: $src/$org.json: status must be active, disabled, or removed" >&2; rc=1; break ;;
    esac
    require_security
    for role in admin verifier; do
      if ! kc_has "$org" "$role"; then
        echo "error: migrate: $src/$org.json: no keychain token for '$org' ($role) in keychain service $KEYCHAIN_SERVICE; an active or disabled tenant needs both tokens before its record can be migrated" >&2
        rc=1; break 2
      fi
    done
  done 3<<< "$orgs"
  if [ "$rc" = 0 ]; then
    echo "validating the candidate map (tokens from keychain service $KEYCHAIN_SERVICE)…" >&2
    tokens_for_sync | node "$SCRIPT_DIR/tenants-assemble.mjs" "$CANDIDATE_DIR" | node "$SCRIPT_DIR/tenants-check.mjs" >&2 || rc=1
  fi
  TENANTS_DIR="$dest"
  return "$rc"
}

cmd_migrate() {
  local flag="${1:-}" from="${2:-}" extra="${3:-}" f b n_rec=0 n_pol=0
  [ "$flag" = --from ] && [ -n "$from" ] || die "migrate: usage: tenant.sh migrate --from <absolute path of the existing registry directory>"
  [ -z "$extra" ] || die "migrate: unexpected extra argument '$extra'"
  case "$from" in
    /*) ;;
    *) die "migrate: --from must be an absolute path (got '$from')" ;;
  esac
  [ -d "$from" ] || die "migrate: --from $from is not a directory"
  # Decided before the lock: taking it would create .lock inside the source.
  if [ -d "$TENANTS_DIR" ] && [ "$(cd "$from" && pwd -P)" = "$(cd "$TENANTS_DIR" && pwd -P)" ]; then
    die "migrate: --from $from is the destination registry ($TENANTS_DIR); point TENANTS_DIR / HOSTED_VERIFY_ENV at the new location"
  fi
  acquire_lock create
  # Never a merge: the destination is empty (its lock aside) and uninitialized, or nothing moves.
  [ ! -f "$MARKER_FILE" ] || die "migrate: $TENANTS_DIR is already initialized; migrate never merges into a registry"
  if has_registry_content; then die "$(uninitialized_msg migrate)"; fi
  mkdir "$CANDIDATE_DIR" || die "migrate: could not create $CANDIDATE_DIR"
  MIGRATE_CLEANUP="$CANDIDATE_DIR"
  # The same filter as registry_orgs and the assembler (regular, non-dot *.json), policy files
  # included. The source is only ever read.
  for f in "$from"/*.json; do
    [ -f "$f" ] || continue
    b="$(basename "$f")"
    case "$b" in .*) continue ;; esac
    cp -p "$f" "$CANDIDATE_DIR/$b" || die "migrate: could not copy $f; nothing was committed"
    case "$b" in
      *.policy.json) n_pol=$((n_pol + 1)) ;;
      *) n_rec=$((n_rec + 1)) ;;
    esac
  done
  [ "$n_rec" != 0 ] || die "migrate: $from holds no record files (<org_id>.json); nothing to migrate — for a new environment run: pilot/tenant.sh init"
  migrate_validate "$from" || die "migrate: the candidate failed validation (above); nothing was committed — $TENANTS_DIR has no records and no marker, and $from is untouched"
  # Commit: one same-filesystem rename per file, then the marker LAST, so a run stopped anywhere
  # in between leaves records without a marker — refused by every command until resolved by
  # hand. Signals are deferred to the end of this section; only a SIGKILL can split it.
  MIGRATE_CLEANUP=""
  CRITICAL=1
  for f in "$CANDIDATE_DIR"/*.json; do
    [ -f "$f" ] || continue
    b="$(basename "$f")"
    [ ! -e "$TENANTS_DIR/$b" ] || die "migrate: $TENANTS_DIR/$b already exists; refusing to overwrite it. The registry has records but no marker (pilot/RUNBOOK.md, \"Initializing or migrating the registry\")"
    mv "$f" "$TENANTS_DIR/$b" || die "migrate: could not move $b into $TENANTS_DIR. The registry has records but no marker (pilot/RUNBOOK.md, \"Initializing or migrating the registry\")"
  done
  : > "$MARKER_FILE" || die "migrate: every file was committed but $MARKER_FILE could not be written; the registry has records but no marker"
  rmdir "$CANDIDATE_DIR" 2>/dev/null || echo "warning: could not remove $CANDIDATE_DIR (it should be empty); remove it by hand" >&2
  CRITICAL=0
  echo "migrated $n_rec records and $n_pol policy files from $from into $TENANTS_DIR; the registry is initialized"
  echo "the source was left untouched: once pilot/tenant.sh show (same HOSTED_VERIFY_ENV / TENANTS_DIR) confirms the new location, delete $from by hand"
  deferred_exit
}

cmd="${1:-}"
if [ $# -gt 0 ]; then shift; fi
# One positional past what each subcommand uses, so an unexpected extra argument is seen
# and refused rather than silently ignored.
# Every command but `show` mutates or assembles the map, so each takes the lock first —
# `sync --dry-run` included: it reads the registry and the keychain, and is only worth
# reporting if nothing was rewriting them underneath. `show` is read-only and never waits.
# A mutating command checks the .initialized marker with the lock HELD (acquire_lock never
# creates the directory for these), so a concurrent init or migrate cannot interleave with it.
case "$cmd" in
  add)     acquire_lock; require_initialized add;     cmd_add "${1:-}" "${2:-}" "${3:-}" "${4:-}" ;;
  rotate)  acquire_lock; require_initialized rotate;  cmd_rotate "${1:-}" "${2:-}" "${3:-}" "${4:-}" ;;
  disable) acquire_lock; require_initialized disable; cmd_disable "${1:-}" "${2:-}" ;;
  enable)  acquire_lock; require_initialized enable;  cmd_enable "${1:-}" "${2:-}" "${3:-}" ;;
  remove)  acquire_lock; require_initialized remove;  cmd_remove "${1:-}" "${2:-}" "${3:-}" ;;
  sync)    acquire_lock; require_initialized sync;    cmd_sync "${1:-}" "${2:-}" "${3:-}" ;;
  init)    cmd_init "${1:-}" ;;
  migrate) cmd_migrate "${1:-}" "${2:-}" "${3:-}" ;;
  show)    cmd_show "${1:-}" ;;
  *)       usage ;;
esac
