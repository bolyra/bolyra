#!/usr/bin/env bash
#
# Verify every committed lockfile can be installed with a clean `npm ci`.
#
# Why this exists: the integration CI jobs install with `npm install` after
# rewriting `@bolyra/sdk` to a `file:` path. That path tolerates an incomplete
# lockfile, so a lockfile `npm ci` would reject can still show green. Six
# packages on main were in exactly that state (issue #93), and the published
# `@bolyra/receipts` was one of them. A lockfile that cannot `npm ci` is one a
# consumer cannot reproducibly install.
#
# The recurring offender is the `@emnapi/*` optional wasm subtree reached via
# `@napi-rs/wasm-runtime`: it goes missing from the lock whenever a lockfile is
# regenerated on a platform other than the one installing it. See the related
# entries in tasks/lessons.md.
#
# Usage: scripts/verify-lockfiles.sh
# Exits non-zero if any checked manifest fails.

set -uo pipefail
cd "$(dirname "$0")/.."

# Manifests deliberately not checked. These depend on sibling packages through
# `file:` paths, so `npm ci` runs the sibling's `prepare` script (`tsc`) before
# the sibling's own devDependencies exist, and fails with code 127
# `tsc: not found`. That is a property of `file:` deps under `npm ci`, not a
# defect in the lockfile, and it cannot be fixed from the lockfile side.
# Keep this list SHORT and justified: every entry is a manifest whose lockfile
# nothing verifies.
EXCLUDED="
./demo
./examples/receipt-scoring-kit
./examples/stripe-acp-demo
./examples/stripe-ai-mandate-demo
./examples/verified-actions-demo
./examples/x402-evc-profile
./integrations/mpp-payments/examples/mandate-demo
"

is_excluded() {
  printf '%s\n' "$EXCLUDED" | grep -qx -- "$1"
}

# Only TRACKED lockfiles. A bare `find` also descends into nested git worktrees
# (this repo keeps some under .claude/worktrees/), whose lockfiles belong to a
# different checkout and are not ours to verify.
#
# Hard-fail rather than falling back to `find` when git is unusable: silently
# scanning a different file set would make this job report on something other
# than what we committed, which is worse than not running. Note `git ls-files`
# exits 128 in a linked worktree whose .git pointer is not resolvable, e.g. a
# worktree bind-mounted into a container without its parent.
list_lockfiles() {
  local out
  if ! out=$(git ls-files '*package-lock.json' 2>&1); then
    echo "ERROR: git ls-files failed; cannot determine committed lockfiles." >&2
    echo "  $out" >&2
    exit 2
  fi
  printf '%s\n' "$out" | sed 's|^|./|' | sort
}

failed=0
checked=0
skipped=0

while IFS= read -r lock; do
  dir="${lock%/package-lock.json}"
  [ "$dir" = "$lock" ] && dir="."

  if is_excluded "$dir"; then
    printf 'SKIP  %s (file: sibling build, see EXCLUDED)\n' "$dir"
    skipped=$((skipped + 1))
    continue
  fi

  checked=$((checked + 1))
  if ( cd "$dir" && rm -rf node_modules && npm ci --no-audit --no-fund ) >/tmp/lockcheck.log 2>&1; then
    printf 'PASS  %s\n' "$dir"
  else
    printf 'FAIL  %s\n' "$dir"
    sed -n '1,12p' /tmp/lockcheck.log | sed 's/^/      /'
    failed=$((failed + 1))
  fi
  # Reclaim disk between manifests. Best-effort and deliberately quiet: some
  # bind-mounted filesystems refuse partial removals, and a cleanup failure
  # must never change this job's verdict.
  rm -rf "$dir/node_modules" 2>/dev/null || true
done <<EOF
$(list_lockfiles)
EOF

echo
echo "checked=$checked skipped=$skipped failed=$failed"
[ "$failed" -eq 0 ] || exit 1
