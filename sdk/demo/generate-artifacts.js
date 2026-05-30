// demo/generate-artifacts.js
//
// Pre-generates the proof artifacts the demo plays back. Run this once,
// in-repo, after rebuilding circuits or bumping the SDK. The outputs
// (humanProof.json, agentProof.json, nonce.txt) are committed alongside
// demo.js so the runtime demo only has to VERIFY, not PROVE — keeping the
// recorded demo under 5 seconds.
//
// Run: node demo/generate-artifacts.js   (from sdk/ after `npm run build`)

const fs = require("fs");
const path = require("path");

const lib = require("../dist");
const { createHumanIdentity, createAgentCredential, Permission, proveHandshake } = lib;

const REPO_ROOT = path.resolve(__dirname, "../..");
const CIRCUIT_DIR = path.join(REPO_ROOT, "circuits/build");
const OUT_DIR = __dirname;

async function main() {
  console.log("Generating Bolyra handshake artifacts...");

  // Deterministic seeds so re-running produces stable artifacts.
  const humanSecret = 0xb0_17a0_0000_0000_0000_0000_0000_0000_0000n;
  const operatorKey = 0xb01_002an;
  const modelHash = 0x9774_4f4f_0042n; // hash("gpt-4o-2026")

  const human = await createHumanIdentity(humanSecret);
  const agent = await createAgentCredential(
    modelHash,
    operatorKey,
    [Permission.READ_DATA, Permission.FINANCIAL_SMALL],
    BigInt(Math.floor(Date.now() / 1000) + 86400),
  );

  console.log("  human.commitment:", human.commitment.toString().slice(0, 24) + "...");
  console.log("  agent.commitment:", agent.commitment.toString().slice(0, 24) + "...");

  const t0 = Date.now();
  const { humanProof, agentProof, nonce } = await proveHandshake(human, agent, {
    config: { circuitDir: CIRCUIT_DIR },
  });
  const elapsed = ((Date.now() - t0) / 1000).toFixed(2);
  console.log(`  proved in ${elapsed}s`);

  // BigInt isn't JSON-serializable; nonce stays as a decimal string.
  fs.writeFileSync(path.join(OUT_DIR, "humanProof.json"), JSON.stringify(humanProof, null, 2));
  fs.writeFileSync(path.join(OUT_DIR, "agentProof.json"), JSON.stringify(agentProof, null, 2));
  fs.writeFileSync(path.join(OUT_DIR, "nonce.txt"), nonce.toString());

  console.log("Wrote humanProof.json, agentProof.json, nonce.txt to demo/.");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
