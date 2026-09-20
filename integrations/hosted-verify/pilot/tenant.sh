#!/usr/bin/env bash
#
# tenant.sh — tenant lifecycle for the hosted-verify preview (the per-tenant TENANTS model).
#
# Thin wrapper over existing mechanisms — no new infra:
#   * the two bearer tokens per tenant live in the macOS keychain
#       service: bolyra-hosted-verify   (bolyra-hosted-verify-staging when HOSTED_VERIFY_ENV=staging)
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
#   ./tenant.sh add <org_id> <x:y>[,<x:y>...] [--no-fixture-key]
#                                     mint both tokens, store them, create the registry file
#                                     trusting the given keys (plus the repo fixture key
#                                     unless --no-fixture-key), then sync
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
#
# Environment:
#   HOSTED_VERIFY_ENV=staging   target the staging Worker (`--env=staging`; keychain
#                               service bolyra-hosted-verify-staging; registry directory
#                               pilot/tenants-staging)
#   TENANTS_DIR=<dir>           override the registry directory
#
# Tokens are NEVER printed by this script. To hand a token to a partner over a secure
# channel, run (yourself, deliberately):
#   security find-generic-password -s bolyra-hosted-verify -a tenant-<org_id>-verifier -w
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKER_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$WORKER_DIR/../.." && pwd)"
ENV_NAME="${HOSTED_VERIFY_ENV:-}"
if [ -n "$ENV_NAME" ]; then
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
# The repo conformance-fixture operator key (its private half is public). Seeded into
# preview tenants so the quickstart and examples/managed-revocation verify before the
# partner's own key issues anything. Preview-only; never in a real deployment.
FIXTURE_KEY="15617329766995256858590222302430068383949745072531974464084158078905448850943:20201653676552407165606319978171745645181779505176156736762229713293662347780"

die() { echo "error: $*" >&2; exit 1; }
usage() { sed -n '2,51p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }

require_org() {
  [[ "$1" =~ ^[a-z0-9][a-z0-9-]{1,62}$ ]] || die "org_id '$1' must match ^[a-z0-9][a-z0-9-]{1,62}$"
  [ "$1" != "unauthenticated" ] || die "'unauthenticated' is the reserved analytics label"
}
require_keys() {  # comma-separated x:y decimal pairs
  local key _keys
  [ -n "$1" ] || die "at least one operator key (x:y) is required"
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
  security add-generic-password -U -s "$KEYCHAIN_SERVICE" -a "$(kc_account "$1" "$2")" -w "$3" \
    -j "bolyra hosted-verify tenant token: $1 ($2)" >/dev/null
}
kc_delete() { security delete-generic-password -s "$KEYCHAIN_SERVICE" -a "$(kc_account "$1" "$2")" >/dev/null 2>&1 || true; }
mint() { openssl rand -hex 32; }

registry_file() { echo "$TENANTS_DIR/$1.json"; }
reg_field() {  # $1 org, $2 field → the field as a string (empty when absent)
  node -e 'const fs=require("fs");const f=JSON.parse(fs.readFileSync(process.argv[1],"utf8"));const v=f[process.argv[2]];process.stdout.write(v===undefined?"":(typeof v==="string"?v:JSON.stringify(v)))' "$(registry_file "$1")" "$2"
}
reg_set_status() {  # $1 org, $2 status — preserves every other field
  node -e 'const fs=require("fs");const p=process.argv[1];const f=JSON.parse(fs.readFileSync(p,"utf8"));f.status=process.argv[2];f.updated=new Date().toISOString().slice(0,10);fs.writeFileSync(p,JSON.stringify(f,null,2)+"\n")' "$(registry_file "$1")" "$2"
}
require_registry() { [ -f "$(registry_file "$1")" ] || die "no registry file for '$1' at $(registry_file "$1") (run: add)"; }

cmd_add() {
  local org="${1:-}" keys="${2:-}" flag="${3:-}"
  [ -n "$org" ] && [ -n "$keys" ] || usage
  require_org "$org"; require_keys "$keys"; require_security
  [ ! -e "$(registry_file "$org")" ] || die "tenant '$org' already has a registry file: $(registry_file "$org")"
  local list="$keys"
  [ "$flag" = "--no-fixture-key" ] || list="$keys,$FIXTURE_KEY"
  mkdir -p "$TENANTS_DIR"
  node -e 'const fs=require("fs");const [p,org,list]=process.argv.slice(1);const f={org_id:org,status:"active",displayName:"",contact:"",trustedOperators:list.split(","),tierCaps:{maxTier:"medium"},created:new Date().toISOString().slice(0,10),notes:""};fs.writeFileSync(p,JSON.stringify(f,null,2)+"\n")' "$(registry_file "$org")" "$org" "$list"
  local t
  t="$(mint)"; kc_put "$org" admin "$t"
  t="$(mint)"; kc_put "$org" verifier "$t"
  unset t
  echo "tenant '$org': registry file $(registry_file "$org"); tokens stored (keychain service $KEYCHAIN_SERVICE, accounts $(kc_account "$org" admin) / $(kc_account "$org" verifier))"
  cmd_sync
}

cmd_rotate() {
  local org="${1:-}" role="${2:-}"
  [ -n "$org" ] || usage
  case "$role" in admin|verifier) ;; *) usage ;; esac
  require_org "$org"; require_registry "$org"; require_security
  local t
  t="$(mint)"; kc_put "$org" "$role" "$t"; unset t
  echo "tenant '$org': new $role token stored; the old one dies when the sync lands"
  cmd_sync
}

cmd_disable() {
  local org="${1:-}"; [ -n "$org" ] || usage
  require_org "$org"; require_registry "$org"
  reg_set_status "$org" disabled
  echo "tenant '$org': quarantined (served on no route until enable); tell them it is deliberate"
  cmd_sync
}

cmd_enable() {
  local org="${1:-}" flag="${2:-}"
  [ -n "$org" ] || usage
  require_org "$org"; require_registry "$org"
  [ "$flag" = "--keys-retired" ] || die "enable refuses without --keys-retired: a quarantine usually exists because a key or a token was in question; confirm you retired or re-issued it (rotate / edit trustedOperators) before lifting it"
  reg_set_status "$org" active
  echo "tenant '$org': re-enabled"
  cmd_sync
}

cmd_remove() {
  local org="${1:-}"; [ -n "$org" ] || usage
  require_org "$org"; require_registry "$org"; require_security
  reg_set_status "$org" removed
  kc_delete "$org" admin; kc_delete "$org" verifier
  echo "tenant '$org': tokens deleted, status=removed (registry file kept; the tenant's Durable Object and history are retained)"
  cmd_sync
}

# Print "<org> <role> <token>" for every active/disabled tenant — consumed on a pipe only.
tokens_for_sync() {
  local f org status role
  for f in "$TENANTS_DIR"/*.json; do
    [ -e "$f" ] || die "no tenant registry files in $TENANTS_DIR — never push an empty map (the Worker rejects {}); add a tenant, or quarantine the remaining ones instead"
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
      printf '%s %s %s\n' "$org" "$role" "$(kc_get "$org" "$role")"
    done
  done
}

cmd_sync() {
  local dry="${1:-}"
  require_security
  echo "assembling TENANTS from $TENANTS_DIR (tokens from keychain service $KEYCHAIN_SERVICE)…" >&2
  if [ "$dry" = "--dry-run" ]; then
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
  local f org status a v
  printf '%-24s %-10s %-8s %s\n' "org_id" "status" "admin" "verifier"
  for f in "$TENANTS_DIR"/*.json; do
    [ -e "$f" ] || { echo "(no tenants in $TENANTS_DIR)"; return 0; }
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

case "${1:-}" in
  add)     cmd_add "${2:-}" "${3:-}" "${4:-}" ;;
  rotate)  cmd_rotate "${2:-}" "${3:-}" ;;
  disable) cmd_disable "${2:-}" ;;
  enable)  cmd_enable "${2:-}" "${3:-}" ;;
  remove)  cmd_remove "${2:-}" ;;
  sync)    cmd_sync "${2:-}" ;;
  show)    cmd_show ;;
  *)       usage ;;
esac
