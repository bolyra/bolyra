// demo/demo.js
//
// @bolyra/sdk runnable handshake demo. Two scenes:
//   1. Happy path:   real Groth16 verifyHandshake → ✓ VERIFIED
//   2. Tampered proof: same verify, one byte flipped → ✗ REJECTED
//
// Designed for visual recording (vhs / asciinema). Each step prints, pauses,
// then continues — so a viewer can read every line before the next appears.
//
// The proofs themselves are pre-recorded (see generate-artifacts.js) so this
// demo runs in <2s end-to-end. The verify step uses real snarkjs Groth16
// verification against the production vkey — no mocks.
//
// Run:  npm install @bolyra/sdk
//       node demo.js
// Or:   from this repo, after `npm run build` in sdk/:  node demo/demo.js
//
// Requires Node 18+.

const fs = require("fs");
const path = require("path");

let lib;
try {
  lib = require("@bolyra/sdk");
} catch {
  lib = require("../dist");
}
const { verifyHandshake } = lib;

const wait = (ms) => new Promise((r) => setTimeout(r, ms));
const C = {
  dim: (s) => `\x1b[2m${s}\x1b[0m`,
  bold: (s) => `\x1b[1m${s}\x1b[0m`,
  green: (s) => `\x1b[32m${s}\x1b[0m`,
  red: (s) => `\x1b[31m${s}\x1b[0m`,
  cyan: (s) => `\x1b[36m${s}\x1b[0m`,
  yellow: (s) => `\x1b[33m${s}\x1b[0m`,
  magenta: (s) => `\x1b[35m${s}\x1b[0m`,
};

function divider() {
  console.log(C.dim("─".repeat(64)));
}

function short(big) {
  const s = typeof big === "bigint" ? big.toString() : String(big);
  return s.slice(0, 18) + "…";
}

async function main() {
  console.log("");
  console.log(C.bold("@bolyra/sdk") + C.dim("  mutual ZKP handshake: human + AI agent"));
  divider();
  await wait(1200);

  // Demo dir contains the pre-recorded proofs and verification keys.
  const here = __dirname;
  const humanProof = JSON.parse(fs.readFileSync(path.join(here, "humanProof.json"), "utf8"));
  const agentProof = JSON.parse(fs.readFileSync(path.join(here, "agentProof.json"), "utf8"));
  const nonce = BigInt(fs.readFileSync(path.join(here, "nonce.txt"), "utf8").trim());

  // --- Step 1: show what was proved -----------------------------------------
  console.log("");
  console.log(C.cyan("[1/3]") + " Human proves " + C.bold("uniqueness") + " + Agent proves " + C.bold("signed credential"));
  await wait(500);
  console.log("      " + C.dim("Groth16 · nonce ") + C.dim(short(nonce)));
  await wait(700);
  console.log("      " + C.dim("humanProof  ") + C.magenta(humanProof.proof.pi_a[0].slice(0, 16) + "…"));
  await wait(400);
  console.log("      " + C.dim("agentProof  ") + C.magenta(agentProof.proof.pi_a[0].slice(0, 16) + "…"));
  await wait(1400);

  // --- Step 2: happy path verification --------------------------------------
  console.log("");
  console.log(C.cyan("[2/3]") + " Verifier checks both proofs (real Groth16, on-chain identical)");
  await wait(600);
  const t0 = Date.now();
  const result = await verifyHandshake(humanProof, agentProof, nonce, { circuitDir: here });
  const ms = Date.now() - t0;
  console.log(
    "      " +
      (result.verified ? C.green("✓ VERIFIED") : C.red("✗ REJECTED")) +
      "   " +
      C.dim(`(${ms}ms)`),
  );
  await wait(400);
  console.log("      " + C.dim("humanNullifier  ") + short(result.humanNullifier));
  await wait(300);
  console.log("      " + C.dim("agentNullifier  ") + short(result.agentNullifier));
  await wait(300);
  console.log("      " + C.dim("scopeCommitment ") + short(result.scopeCommitment));
  await wait(1800);

  // --- Step 3: tampered proof rejection -------------------------------------
  console.log("");
  console.log(C.cyan("[3/3]") + " Attacker flips one byte of the agent proof");
  await wait(700);
  // Deep clone, then mutate the first hex digit of pi_a[0]. Any single-bit
  // change in a Groth16 proof element invalidates the pairing check.
  const tampered = JSON.parse(JSON.stringify(agentProof));
  const orig = tampered.proof.pi_a[0];
  const flippedFirst = orig[0] === "1" ? "2" : "1";
  tampered.proof.pi_a[0] = flippedFirst + orig.slice(1);
  console.log("      " + C.dim("agentProof  ") + C.red(tampered.proof.pi_a[0].slice(0, 16) + "…  ← mutated"));
  await wait(900);
  const badResult = await verifyHandshake(humanProof, tampered, nonce, { circuitDir: here });
  console.log(
    "      " +
      (badResult.verified ? C.green("✓ VERIFIED") : C.red("✗ REJECTED")) +
      "   " +
      C.yellow("PROOF_INVALID"),
  );
  await wait(2000);

  // --- Outro ---------------------------------------------------------------
  console.log("");
  divider();
  console.log("");
  console.log("  " + C.bold("npm install @bolyra/sdk"));
  console.log("  " + C.dim("https://github.com/bolyra/bolyra"));
  console.log("");
  await wait(2000);
}

main()
  .then(() => process.exit(0))
  .catch((e) => {
    console.error(e);
    process.exit(1);
  });
