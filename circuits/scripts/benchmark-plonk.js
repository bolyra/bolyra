#!/usr/bin/env node

/**
 * PLONK Proof Benchmark for AgentPolicy circuit
 *
 * Measures:
 *   1. PLONK setup time (one-time, universal)
 *   2. Proof generation time (per-handshake)
 *   3. Proof verification time (per-handshake)
 *   4. Proof size
 *   5. Memory usage
 *
 * Phase 1 target: <30s per proof on M-series Mac
 */

const snarkjs = require("snarkjs");
const path = require("path");
const fs = require("fs");
const { buildPoseidon, buildEddsa } = require("circomlibjs");

const CIRCUIT_WASM = path.join(__dirname, "../build/AgentPolicy_js/AgentPolicy.wasm");
const CIRCUIT_R1CS = path.join(__dirname, "../build/AgentPolicy.r1cs");
const PTAU_PATH = path.join(__dirname, "../build/pot16.ptau");
const ZKEY_PATH = path.join(__dirname, "../build/AgentPolicy_plonk.zkey");
const VKEY_PATH = path.join(__dirname, "../build/AgentPolicy_vkey.json");

async function downloadPtau() {
  if (fs.existsSync(PTAU_PATH)) {
    console.log("  Powers of Tau file exists, skipping download");
    return;
  }

  // PLONK inflates constraints to ~37k, so pot16 (2^16 = 65536) is needed
  console.log("  Downloading Powers of Tau (pot16, ~72MB)...");
  const https = require("https");
  const url = "https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_16.ptau";

  return new Promise((resolve, reject) => {
    const file = fs.createWriteStream(PTAU_PATH);
    https.get(url, (response) => {
      if (response.statusCode === 301 || response.statusCode === 302) {
        https.get(response.headers.location, (res) => {
          res.pipe(file);
          file.on("finish", () => { file.close(); resolve(); });
        }).on("error", reject);
      } else {
        response.pipe(file);
        file.on("finish", () => { file.close(); resolve(); });
      }
    }).on("error", reject);
  });
}

async function setupPlonk() {
  if (fs.existsSync(ZKEY_PATH)) {
    console.log("  PLONK zkey exists, skipping setup");
    return;
  }

  console.log("  Running PLONK setup (universal, one-time)...");
  const setupStart = performance.now();

  await snarkjs.plonk.setup(CIRCUIT_R1CS, PTAU_PATH, ZKEY_PATH);

  const setupTime = ((performance.now() - setupStart) / 1000).toFixed(2);
  console.log(`  PLONK setup: ${setupTime}s`);

  // Export verification key
  const vKey = await snarkjs.zKey.exportVerificationKey(ZKEY_PATH);
  fs.writeFileSync(VKEY_PATH, JSON.stringify(vKey, null, 2));
  console.log("  Verification key exported");
}

async function createTestInput() {
  const poseidon = await buildPoseidon();
  const eddsa = await buildEddsa();
  const F = poseidon.F;

  const privateKey = Buffer.from(
    "0001020304050607080900010203040506070809000102030405060708090001",
    "hex"
  );
  const pubKey = eddsa.prv2pub(privateKey);

  const modelHash = 12345n;
  const permissionBitmask = 0b00000111n;
  const expiryTimestamp = BigInt(Math.floor(Date.now() / 1000) + 86400);
  const currentTimestamp = BigInt(Math.floor(Date.now() / 1000));
  const sessionNonce = 42n;
  const requiredScopeMask = 0b00000011n;

  // Credential commitment
  const credentialCommitment = poseidon([
    modelHash,
    F.toObject(pubKey[0]),
    permissionBitmask,
    expiryTimestamp,
  ]);

  // Sign
  const signature = eddsa.signPoseidon(privateKey, credentialCommitment);

  // Build simple Merkle tree (1 leaf, padded)
  const leaf = F.toObject(credentialCommitment);
  const depth = 1;
  const siblings = [0n];
  // Pad to MAX_DEPTH=20
  while (siblings.length < 20) siblings.push(0n);

  return {
    modelHash: modelHash.toString(),
    operatorPubkeyAx: F.toObject(pubKey[0]).toString(),
    operatorPubkeyAy: F.toObject(pubKey[1]).toString(),
    permissionBitmask: permissionBitmask.toString(),
    expiryTimestamp: expiryTimestamp.toString(),
    sigR8x: F.toObject(signature.R8[0]).toString(),
    sigR8y: F.toObject(signature.R8[1]).toString(),
    sigS: signature.S.toString(),
    merkleProofLength: depth.toString(),
    merkleProofIndex: "0",
    merkleProofSiblings: siblings.map(s => s.toString()),
    requiredScopeMask: requiredScopeMask.toString(),
    currentTimestamp: currentTimestamp.toString(),
    sessionNonce: sessionNonce.toString(),
  };
}

async function main() {
  console.log("╔══════════════════════════════════════════════╗");
  console.log("║  Bolyra — PLONK Proof Benchmark               ║");
  console.log("║  Circuit: AgentPolicy (depth 20)             ║");
  console.log("║  Target: <30s proof generation (M-series Mac) ║");
  console.log("╚══════════════════════════════════════════════╝\n");

  // Check circuit artifacts exist
  if (!fs.existsSync(CIRCUIT_WASM)) {
    console.error("ERROR: Circuit not compiled. Run: circom src/AgentPolicy.circom --r1cs --wasm --sym -o build/ -l node_modules/ -l node_modules/circomlib/circuits/");
    process.exit(1);
  }

  const r1csInfo = await snarkjs.r1cs.info(CIRCUIT_R1CS);
  console.log(`Circuit: ${r1csInfo.nConstraints} constraints, ${r1csInfo.nVars} wires\n`);

  // Step 1: Download Powers of Tau
  console.log("Step 1: Powers of Tau");
  await downloadPtau();

  // Step 2: PLONK Setup
  console.log("\nStep 2: PLONK Setup");
  await setupPlonk();

  // Step 3: Generate test input
  console.log("\nStep 3: Generating test input...");
  const input = await createTestInput();

  // Step 4: Proof generation (the main benchmark)
  console.log("\nStep 4: PLONK Proof Generation");
  const memBefore = process.memoryUsage();

  const proveStart = performance.now();
  const { proof, publicSignals } = await snarkjs.plonk.fullProve(
    input,
    CIRCUIT_WASM,
    ZKEY_PATH
  );
  const proveTime = ((performance.now() - proveStart) / 1000).toFixed(2);

  const memAfter = process.memoryUsage();
  const memDelta = ((memAfter.heapUsed - memBefore.heapUsed) / 1024 / 1024).toFixed(1);

  console.log(`  Proof generation: ${proveTime}s`);
  console.log(`  Memory delta: ${memDelta}MB`);
  console.log(`  Proof size: ${JSON.stringify(proof).length} bytes`);
  console.log(`  Public signals: ${publicSignals.length}`);

  // Step 5: Proof verification
  console.log("\nStep 5: PLONK Proof Verification");
  const vKey = JSON.parse(fs.readFileSync(VKEY_PATH, "utf-8"));

  const verifyStart = performance.now();
  const valid = await snarkjs.plonk.verify(vKey, publicSignals, proof);
  const verifyTime = ((performance.now() - verifyStart) / 1000).toFixed(2);

  console.log(`  Verification: ${verifyTime}s`);
  console.log(`  Valid: ${valid}`);

  // Step 6: Run 3 more proofs for average
  console.log("\nStep 6: Consistency check (3 more proofs)");
  const times = [parseFloat(proveTime)];
  for (let i = 0; i < 3; i++) {
    const start = performance.now();
    await snarkjs.plonk.fullProve(input, CIRCUIT_WASM, ZKEY_PATH);
    const t = (performance.now() - start) / 1000;
    times.push(t);
    console.log(`  Run ${i + 2}: ${t.toFixed(2)}s`);
  }

  const avg = (times.reduce((a, b) => a + b) / times.length).toFixed(2);
  const min = Math.min(...times).toFixed(2);
  const max = Math.max(...times).toFixed(2);

  // Summary
  console.log("\n╔══════════════════════════════════════════════╗");
  console.log("║  BENCHMARK RESULTS                            ║");
  console.log("╠══════════════════════════════════════════════╣");
  console.log(`║  Constraints:     ${r1csInfo.nConstraints.toString().padEnd(27)}║`);
  console.log(`║  Proof gen avg:   ${avg}s${" ".repeat(24 - avg.length)}║`);
  console.log(`║  Proof gen range: ${min}s - ${max}s${" ".repeat(18 - min.length - max.length)}║`);
  console.log(`║  Verification:    ${verifyTime}s${" ".repeat(24 - verifyTime.length)}║`);
  console.log(`║  Memory delta:    ${memDelta}MB${" ".repeat(23 - memDelta.length)}║`);
  console.log(`║  Proof valid:     ${valid.toString().padEnd(27)}║`);

  const target = 30;
  const status = parseFloat(avg) < target ? "✅ PASS" : "❌ FAIL";
  console.log(`║  Target (<${target}s):   ${status.padEnd(27)}║`);
  console.log("╚══════════════════════════════════════════════╝");

  if (parseFloat(avg) >= target) {
    console.log(`\n⚠️  Average proving time ${avg}s exceeds target of ${target}s.`);
    console.log("   Consider: reduce circuit complexity, switch to Groth16, or use a faster machine.");
    process.exit(1);
  }
}

main().catch((err) => {
  console.error("Benchmark failed:", err);
  process.exit(1);
});
