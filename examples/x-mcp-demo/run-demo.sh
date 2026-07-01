#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

echo ""
echo "============================================================"
echo "  Bolyra + X MCP Demo"
echo "  Shield wraps xurl MCP with per-tool ZKP authorization"
echo "============================================================"
echo ""

# Build dependencies (always rebuild to pick up changes)
echo "Building @bolyra/sdk..."
(cd ../../sdk && npm run build)
echo "Building @bolyra/mcp..."
(cd ../../integrations/mcp && npm run build)
echo "Building @bolyra/shield..."
(cd ../../integrations/shield && npm run build)

# Install deps if needed
if [ ! -d "node_modules" ]; then
  echo "Installing demo dependencies..."
  npm install
fi

echo ""
echo "Running 3 scenarios against mock X MCP server..."
echo "(Use 'xurl mcp' instead of mock for real X API calls)"
echo ""

# Scenario 1: Attacker
npx tsx src/attacker-client.ts

# Scenario 2: Legit agent
npx tsx src/legit-client.ts

# Scenario 3: Delegated agent
npx tsx src/delegated-client.ts

echo "============================================================"
echo "  Demo complete."
echo ""
echo "  Key takeaways:"
echo "  1. Without proof: all tools rejected (auth required)"
echo "  2. Full-permission agent: all tools allowed"
echo "  3. Delegated agent: only read tools allowed"
echo "  4. Unknown tools: rejected (defaultDeny)"
echo ""
echo "  To use with real X API:"
echo "    bolyra-shield --server 'xurl mcp' --config shield.yaml"
echo "============================================================"
