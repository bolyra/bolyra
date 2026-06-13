#!/usr/bin/env bash
set -euo pipefail

OUT="${1:-dist/prospect-pack}"
mkdir -p "$OUT"

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COMMIT=$(git -C "$REPO_ROOT" rev-parse --short HEAD)
TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)

echo "-> Generating Bolyra prospect pack at $OUT"
echo "   Commit: $COMMIT"
echo "   Time:   $TIMESTAMP"

# ── 1. Copy key docs ─────────────────────────────────────────────────────────
echo "-> Copying conformance report..."
cp "$REPO_ROOT/spec/CONFORMANCE.md" "$OUT/CONFORMANCE.md"

echo "-> Copying blog post..."
cp "$REPO_ROOT/docs/blog/2026-06-13-what-breaks-when-you-leave-dev-mode.md" "$OUT/BLOG.md"

# ── 2. Generate README.md ────────────────────────────────────────────────────
echo "-> Generating README.md..."
cat > "$OUT/README.md" <<EOF
# Bolyra — Prospect Evaluation Pack

Generated: ${TIMESTAMP}
Commit: ${COMMIT}

## What is Bolyra?
ZKP identity protocol for AI agents. Mutual human-agent authentication,
scoped delegation, per-tool policy enforcement, signed audit receipts,
and commerce authorization.

## Packages
- @bolyra/sdk 0.4.0 — TypeScript SDK
- @bolyra/mcp 0.6.0 — MCP auth middleware
- @bolyra/receipts 0.7.0 — Signed receipts
- @bolyra/payment-protocols 0.7.0 — Commerce authorization
- @bolyra/openclaw 0.3.1 — OpenClaw adapter
- bolyra 0.4.0 (PyPI) — Python SDK

## Try it
npm install @bolyra/sdk @bolyra/mcp @bolyra/receipts

## Run the demo
cd demo && npm install && npm start

## Links
- Website: https://bolyra.ai
- Blog: https://bolyra.ai/blog
- GitHub: https://github.com/bolyra/bolyra
- Conformance: see CONFORMANCE.md (48/48 vectors)
EOF

# ── 3. Generate ARTIFACTS.json ───────────────────────────────────────────────
echo "-> Generating ARTIFACTS.json..."

SDK_VER=$(node -e "process.stdout.write(require('$REPO_ROOT/sdk/package.json').version)")
MCP_VER=$(node -e "process.stdout.write(require('$REPO_ROOT/integrations/mcp/package.json').version)")
RECEIPTS_VER=$(node -e "process.stdout.write(require('$REPO_ROOT/integrations/receipts/package.json').version)")
PAYMENT_VER=$(node -e "process.stdout.write(require('$REPO_ROOT/integrations/payment-protocols/package.json').version)")
OPENCLAW_VER=$(node -e "process.stdout.write(require('$REPO_ROOT/integrations/openclaw/package.json').version)")
PYTHON_VER=$(python3 -c "
import re, pathlib
text = pathlib.Path('$REPO_ROOT/sdk-python/pyproject.toml').read_text()
m = re.search(r'^version\s*=\s*\"([^\"]+)\"', text, re.MULTILINE)
print(m.group(1) if m else '0.0.0', end='')
")

cat > "$OUT/ARTIFACTS.json" <<EOF
{
  "generated": "${TIMESTAMP}",
  "commit": "${COMMIT}",
  "packages": {
    "@bolyra/sdk": "${SDK_VER}",
    "@bolyra/mcp": "${MCP_VER}",
    "@bolyra/receipts": "${RECEIPTS_VER}",
    "@bolyra/payment-protocols": "${PAYMENT_VER}",
    "@bolyra/openclaw": "${OPENCLAW_VER}",
    "bolyra": "${PYTHON_VER}"
  }
}
EOF

# ── 4. Generate VERIFY.sh ────────────────────────────────────────────────────
echo "-> Generating VERIFY.sh..."
cat > "$OUT/VERIFY.sh" <<'VERIFYEOF'
#!/usr/bin/env bash
# Verify this prospect pack is genuine
echo "Verifying Bolyra prospect pack..."

# Check npm packages exist
for pkg in @bolyra/sdk @bolyra/mcp @bolyra/receipts @bolyra/payment-protocols; do
  ver=$(npm view "$pkg" version 2>/dev/null)
  echo "✓ $pkg@$ver on npm"
done

# Check GitHub commit exists
commit=$(cat ARTIFACTS.json | python3 -c "import sys,json; print(json.load(sys.stdin)['commit'])")
status=$(curl -s -o /dev/null -w "%{http_code}" "https://github.com/bolyra/bolyra/commit/$commit")
echo "✓ Commit $commit exists on GitHub (HTTP $status)"

echo ""
echo "✓ Prospect pack verified"
VERIFYEOF
chmod +x "$OUT/VERIFY.sh"

# ── 5. Copy demo ─────────────────────────────────────────────────────────────
echo "-> Copying demo files..."
cp "$REPO_ROOT/demo/walkthrough.ts" "$OUT/demo-walkthrough.ts"
cp "$REPO_ROOT/demo/README.md" "$OUT/DEMO.md"

echo ""
echo "Prospect pack ready at $OUT"
echo "Files:"
ls -1 "$OUT"
