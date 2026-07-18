#!/usr/bin/env bash
#
# partner-token.sh — pilot-partner token lifecycle for the hosted-verify preview.
#
# Thin wrapper over the EXISTING mechanisms — no new infra:
#   * tokens live in the macOS keychain
#       service: bolyra-hosted-verify
#       account: partner-token-<label>          (established convention;
#                theseus / internal already use it)
#   * the Worker reads the PARTNER_TOKENS wrangler secret — a single JSON
#     object mapping partner label -> bearer token. `sync` assembles that JSON
#     from the keychain + the partner registry and re-puts the secret.
#   * the partner registry is pilot/partners/<label>.json at the repo root
#     (one file per partner, template: pilot/partner-config.example.json).
#     Files contain NO secrets — only labels, status, and a token *reference*.
#
# IMPORTANT: `wrangler secret put PARTNER_TOKENS` REPLACES the whole map.
# Never put it by hand with a partial map — always go through `sync`, which
# includes every partner whose registry status is "active".
#
# Usage:
#   ./partner-token.sh add <label>        mint token, store in keychain,
#                                         create registry file if missing, sync
#   ./partner-token.sh rotate <label>     mint NEW token for existing partner, sync
#   ./partner-token.sh disable <label>    keep token in keychain, remove from
#                                         Worker (status=disabled), sync
#   ./partner-token.sh enable <label>     re-activate a disabled partner, sync
#   ./partner-token.sh revoke <label>     delete token from keychain AND Worker
#                                         (status=revoked), sync
#   ./partner-token.sh sync [--dry-run]   re-put PARTNER_TOKENS from registry+keychain
#   ./partner-token.sh show               list partners, status, keychain presence
#
# Tokens are NEVER printed by this script. To hand a token to a partner over a
# secure channel, run (yourself, deliberately):
#   security find-generic-password -s bolyra-hosted-verify -a partner-token-<label> -w
#
# The legacy shared PREVIEW_TOKEN (label "preview") is a separate wrangler
# secret and is NOT touched by this script. To kill it:
#   cd integrations/hosted-verify && npx wrangler secret delete PREVIEW_TOKEN

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKER_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"                  # integrations/hosted-verify
REPO_ROOT="$(cd "$WORKER_DIR/../.." && pwd)"
PARTNERS_DIR="${PARTNERS_DIR:-$REPO_ROOT/pilot/partners}"

KEYCHAIN_SERVICE="bolyra-hosted-verify"

die() { echo "ERROR: $*" >&2; exit 1; }

require_label() {
  local label="${1:-}"
  [ -n "$label" ] || die "a partner label is required"
  [[ "$label" =~ ^[a-z0-9][a-z0-9_-]{0,31}$ ]] \
    || die "label must match ^[a-z0-9][a-z0-9_-]{0,31}\$ (got: $label)"
  case "$label" in
    unauthenticated|preview) die "'$label' is a reserved label" ;;
  esac
}

keychain_account() { echo "partner-token-$1"; }

keychain_has() {
  security find-generic-password -s "$KEYCHAIN_SERVICE" -a "$(keychain_account "$1")" \
    >/dev/null 2>&1
}

keychain_get() {
  security find-generic-password -s "$KEYCHAIN_SERVICE" -a "$(keychain_account "$1")" -w
}

keychain_put() {
  # -U updates in place if the item already exists.
  local token
  token="$(openssl rand -hex 32)"
  security add-generic-password -U -s "$KEYCHAIN_SERVICE" \
    -a "$(keychain_account "$1")" -w "$token" \
    -j "bolyra hosted-verify pilot partner token: $1"
  unset token
}

keychain_delete() {
  security delete-generic-password -s "$KEYCHAIN_SERVICE" \
    -a "$(keychain_account "$1")" >/dev/null
}

partner_file() { echo "$PARTNERS_DIR/$1.json"; }

# Read a top-level string field from a partner JSON file.
partner_field() { # <file> <field>
  node -e '
    const fs = require("fs");
    const o = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
    const v = o[process.argv[2]];
    if (typeof v === "string") process.stdout.write(v);
  ' "$1" "$2"
}

set_status() { # <label> <status>
  local file; file="$(partner_file "$1")"
  [ -f "$file" ] || die "no registry file for '$1' at $file"
  node -e '
    const fs = require("fs");
    const [file, status] = process.argv.slice(1);
    const o = JSON.parse(fs.readFileSync(file, "utf8"));
    o.status = status;
    fs.writeFileSync(file, JSON.stringify(o, null, 2) + "\n");
  ' "$file" "$2"
  echo "registry: $file -> status=$2"
}

create_partner_file() { # <label>
  local file; file="$(partner_file "$1")"
  [ -f "$file" ] && return 0
  mkdir -p "$PARTNERS_DIR"
  node -e '
    const fs = require("fs");
    const [file, label] = process.argv.slice(1);
    const o = {
      label,
      status: "active",
      displayName: "",
      contact: "",
      tokenRef: `keychain service=bolyra-hosted-verify account=partner-token-${label}`,
      audience: "https://bolyra-hosted-verify.<account>.workers.dev",
      trustedOperators: [],
      tierCaps: { maxTier: "small" },
      created: new Date().toISOString().slice(0, 10),
      notes: "created by partner-token.sh add; fill in from pilot/partner-config.example.json",
    };
    fs.writeFileSync(file, JSON.stringify(o, null, 2) + "\n");
  ' "$file" "$1"
  echo "registry: created $file (fill in contact/operators per pilot/partner-config.example.json)"
}

active_labels() {
  # Every registry file with status=active. No files -> no labels.
  # Registry files are hand-editable, so re-validate everything: label charset
  # + reserved names (require_label), label==filename, and no duplicates —
  # a stale or malformed file must never push a wrong or reserved label.
  [ -d "$PARTNERS_DIR" ] || return 0
  local f label status seen=""
  for f in "$PARTNERS_DIR"/*.json; do
    [ -e "$f" ] || continue
    case "$f" in *.policy.json) continue ;; esac   # per-pilot policy records, not partners
    label="$(partner_field "$f" label)"
    status="$(partner_field "$f" status)"
    [ -n "$label" ] || die "registry file $f has no 'label' field"
    require_label "$label"
    [ "$(basename "$f" .json)" = "$label" ] \
      || die "registry file $f: label '$label' does not match its filename"
    case " $seen " in
      *" $label "*) die "duplicate label '$label' in $PARTNERS_DIR" ;;
    esac
    seen="$seen $label"
    if [ "$status" = "active" ]; then echo "$label"; fi
  done
}

cmd_sync() {
  local dry_run="${1:-}"
  local labels
  labels="$(active_labels)"

  if [ -z "$labels" ]; then
    # Zero active partners: still neutralize the live map, or a revoked
    # partner's old token would keep working. The Worker ignores the reserved
    # label "unauthenticated", so a map containing only that label (with a
    # random value) disables every partner token via the normal secret path.
    echo "no active partners — pushing an effectively-empty PARTNER_TOKENS map"
    if [ "$dry_run" = "--dry-run" ]; then
      echo "(dry run: not pushing)"
      return 0
    fi
    printf '{"unauthenticated":"%s"}' "$(openssl rand -hex 32)" \
      | (cd "$WORKER_DIR" && npx wrangler secret put PARTNER_TOKENS) \
      || die "wrangler secret put FAILED — the live PARTNER_TOKENS map was NOT updated; previously pushed tokens (including any you just revoked/rotated) are STILL ACCEPTED. Fix the wrangler error and re-run: $0 sync"
    echo "done. NOTE: the legacy shared PREVIEW_TOKEN (label 'preview') is a"
    echo "separate secret and may still be live. To kill it:"
    echo "  cd $WORKER_DIR && npx wrangler secret delete PREVIEW_TOKEN"
    return 0
  fi

  echo "PARTNER_TOKENS will contain these labels (tokens come from the keychain):"
  local label
  for label in $labels; do
    keychain_has "$label" \
      || die "active partner '$label' has no keychain token (service=$KEYCHAIN_SERVICE account=$(keychain_account "$label")). Run: $0 add $label  — or set its registry status to disabled."
    echo "  - $label"
  done

  if [ "$dry_run" = "--dry-run" ]; then
    echo "(dry run: not pushing)"
    return 0
  fi

  # Assemble {label: token, ...} in node (proper JSON escaping), tokens read
  # per label from the keychain, and STREAM it straight into wrangler — the
  # map never touches disk or a shell variable. pipefail is set, so a failure
  # anywhere in the pipeline (keychain read, JSON assembly, wrangler) is loud:
  # a silent failure here would leave revoked/rotated tokens live.
  echo "pushing PARTNER_TOKENS secret (wrangler, $WORKER_DIR)…"
  if ! for label in $labels; do
      printf '%s %s\n' "$label" "$(keychain_get "$label")"
    done | node -e '
      const lines = require("fs").readFileSync(0, "utf8").trim().split("\n");
      const map = {};
      for (const line of lines) {
        const sp = line.indexOf(" ");
        const label = line.slice(0, sp);
        const token = line.slice(sp + 1);
        if (!token || /\s/.test(token)) {
          console.error(`bad token for label ${label} (empty or contains whitespace)`);
          process.exit(1);
        }
        map[label] = token;
      }
      process.stdout.write(JSON.stringify(map));
    ' | (cd "$WORKER_DIR" && npx wrangler secret put PARTNER_TOKENS); then
    die "wrangler secret put FAILED — the live PARTNER_TOKENS map was NOT updated; the previous map (including any tokens you just revoked/rotated) is STILL ACCEPTED by the Worker. Fix the wrangler error and re-run: $0 sync"
  fi
  echo "done. Secrets take effect immediately (no redeploy needed)."
}

cmd_show() {
  [ -d "$PARTNERS_DIR" ] || { echo "(no partner registry at $PARTNERS_DIR)"; return 0; }
  local f label status kc
  printf '%-20s %-10s %s\n' "LABEL" "STATUS" "KEYCHAIN TOKEN"
  for f in "$PARTNERS_DIR"/*.json; do
    [ -e "$f" ] || continue
    case "$f" in *.policy.json) continue ;; esac   # per-pilot policy records, not partners
    label="$(partner_field "$f" label)"
    status="$(partner_field "$f" status)"
    if keychain_has "$label"; then kc="present"; else kc="MISSING"; fi
    printf '%-20s %-10s %s\n' "$label" "${status:-?}" "$kc"
  done
}

cmd="${1:-}"
case "$cmd" in
  add)
    require_label "${2:-}"
    keychain_has "$2" && die "keychain token for '$2' already exists — use rotate"
    create_partner_file "$2"
    set_status "$2" active
    keychain_put "$2"
    echo "minted token for '$2' (keychain service=$KEYCHAIN_SERVICE account=$(keychain_account "$2"))"
    cmd_sync
    echo
    echo "Hand the token to the partner over a secure channel. To read it yourself:"
    echo "  security find-generic-password -s $KEYCHAIN_SERVICE -a $(keychain_account "$2") -w"
    ;;
  rotate)
    require_label "${2:-}"
    keychain_has "$2" || echo "note: '$2' had no existing keychain token — minting fresh"
    keychain_put "$2"
    echo "rotated token for '$2'"
    cmd_sync
    echo "old token is now invalid. Send the new one over a secure channel:"
    echo "  security find-generic-password -s $KEYCHAIN_SERVICE -a $(keychain_account "$2") -w"
    ;;
  disable)
    require_label "${2:-}"
    set_status "$2" disabled
    cmd_sync
    echo "'$2' disabled — token kept in keychain for possible re-enable."
    ;;
  enable)
    require_label "${2:-}"
    keychain_has "$2" || die "'$2' has no keychain token — use add/rotate first"
    set_status "$2" active
    cmd_sync
    ;;
  revoke)
    require_label "${2:-}"
    set_status "$2" revoked
    if keychain_has "$2"; then keychain_delete "$2"; echo "keychain token for '$2' deleted"; fi
    cmd_sync
    ;;
  sync)
    cmd_sync "${2:-}"
    ;;
  show)
    cmd_show
    ;;
  *)
    sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'
    exit 2
    ;;
esac
