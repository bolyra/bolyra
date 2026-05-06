#!/usr/bin/env bash
# Runs the four scenes back-to-back. Pipe to `tee` to capture for the screencast.
#
#   ./run-demo.sh | tee demo-output.txt
#
# Beat 1 (0–20s): broken server + attacker → leaks ~/.ssh/id_rsa
# Beat 2 (20–45s): fixed server + attacker → REJECTED
# Beat 3 (45–75s): fixed server + legit → OK in ~100ms
# Beat 4 (75–90s): closing title (printed below)

set -u
cd "$(dirname "$0")"

banner() {
  echo
  echo "════════════════════════════════════════════════════════════"
  echo "  $1"
  echo "════════════════════════════════════════════════════════════"
}

banner "Scene 1 — BROKEN server + attacker (no auth, exfil succeeds)"
npx ts-node src/attacker-client.ts broken || true

banner "Scene 2 — FIXED server + attacker (no Bolyra credential, REJECTED)"
npx ts-node src/attacker-client.ts fixed || true

banner "Scene 3 — FIXED server + legit (Bolyra handshake, OK)"
npx ts-node src/legit-client.ts fixed || true

banner "Same server. Same MCP protocol. One line: withBolyraAuthStdio(...)"
echo
echo "  ~100ms proof overhead. Drop-in for any stdio MCP server."
echo "  HTTP transport: bolyraAuthMiddleware() — same idea, Authorization header."
echo
