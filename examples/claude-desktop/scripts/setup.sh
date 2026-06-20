#!/usr/bin/env bash
set -euo pipefail

# Claude Desktop integration example -- setup script.
# Installs dependencies, builds TypeScript, verifies prerequisites.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXAMPLE_DIR="$(dirname "$SCRIPT_DIR")"
REPO_ROOT="$(cd "$EXAMPLE_DIR/../.." && pwd)"

echo "=== Bolyra Claude Desktop Example Setup ==="
echo ""
echo "Repo root: $REPO_ROOT"
echo "Example dir: $EXAMPLE_DIR"
echo ""

# Check Node version
NODE_VERSION=$(node -v 2>/dev/null | sed 's/v//' | cut -d. -f1)
if [ -z "$NODE_VERSION" ] || [ "$NODE_VERSION" -lt 18 ]; then
  echo "ERROR: Node.js 18+ required. Found: $(node -v 2>/dev/null || echo 'none')"
  exit 1
fi
echo "[OK] Node.js $(node -v)"

# Check if rapidsnark binary exists (optional but recommended)
RAPIDSNARK="$REPO_ROOT/circuits/build/rapidsnark_prover"
if [ -f "$RAPIDSNARK" ]; then
  echo "[OK] rapidsnark binary found (fast proving)"
else
  echo "[WARN] rapidsnark binary not found at $RAPIDSNARK"
  echo "       Tests will still work but proof generation will use snarkjs (slower)."
fi

# Build mcp-demo (bolyra-proxy.js)
echo ""
echo "Building mcp-demo (bolyra-proxy)..."
cd "$REPO_ROOT/examples/mcp-demo"
npm install --no-audit --no-fund 2>/dev/null
npm run build
echo "[OK] mcp-demo built"

# Install claude-desktop example deps
echo ""
echo "Installing claude-desktop example dependencies..."
cd "$EXAMPLE_DIR"
npm install --no-audit --no-fund 2>/dev/null
echo "[OK] Dependencies installed"

# Build TypeScript
echo ""
echo "Building TypeScript..."
npx tsc
echo "[OK] TypeScript compiled"

# Generate resolved proxy config
echo ""
RESOLVED_CONFIG="$EXAMPLE_DIR/configs/proxy-config-resolved.json"
cat > "$RESOLVED_CONFIG" << EOFCONFIG
{
  "mcpServers": {
    "bolyra-protected-fs": {
      "command": "node",
      "args": [
        "$REPO_ROOT/examples/mcp-demo/dist/bolyra-proxy.js"
      ],
      "env": {
        "BOLYRA_RAPIDSNARK": "$RAPIDSNARK"
      }
    }
  }
}
EOFCONFIG
echo "[OK] Generated resolved config: $RESOLVED_CONFIG"

echo ""
echo "=== Setup Complete ==="
echo ""
echo "Next steps:"
echo "  1. Run E2E tests:  npm test"
echo "  2. Try with Claude Desktop:"
echo "     Copy the contents of configs/proxy-config-resolved.json"
echo "     into your claude_desktop_config.json"
echo "     (Settings > Developer > MCP Servers)"
echo ""
