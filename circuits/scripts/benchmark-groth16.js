#!/usr/bin/env node

/**
 * Groth16 Proof Benchmark for HumanUniqueness circuit
 *
 * Dev-only trusted setup (NOT suitable for production).
 * Production will use Semaphore v4's ceremony artifacts.
 */

const snarkjs = require("snarkjs");
const path = require("path");
const fs = require("fs");
const { buildPoseidon, buildBabyjub } = require("circomlibjs");

const CIRCUIT_WASM = path.join(__dirname, "../build/HumanUniqueness_js/HumanUniqueness.wasm");
const CIRCUIT_R1CS = path.join(__dirname, "../build/HumanUniqueness.r1cs");
const PTAU_PATH = path.join(__dirname, "../build/pot16.ptau");
const ZKEY_0_PATH = path.join(__dirname, "../build/HumanUniqueness_0.zkey");
const ZKEY_FINAL_PATH = path.join(__dirname, "../build/HumanUniqueness_final.zkey");
const VKEY_PATH = path.join(__dirname, "../build/HumanUniqueness_vkey.json");

async function setupGroth16() {
  if (fs.existsSync(ZKEY_FINAL_PATH)) {
    console.log("  Groth16 zkey exists, skipping setup");
    return;
  }

  console.log("  Running Groth16 setup (dev-only, NOT for production)...");
  const setupStart = performance.now();

  // Phase 2: circuit-specific setup
  await snarkjs.zKey.newZKey(CIRCUIT_R1CS, PTAU_PATH, ZKEY_0_PATH);

  // Contribute entropy (dev-only, single contributor)
  await snarkjs.zKey.contribute(ZKEY_0_PATH, ZKEY_FINAL_PATH, "dev", "dev-entropy-not-for-production");

  const setupTime = ((performance.now() - setupStart) / 1000).toFixed(2);
  console.log(`  Groth16 setup: ${setupTime}s`);

  // Export verification key
  const vKey = await snarkjs.zKey.exportVerificationKey(ZKEY_FINAL_PATH);
  fs.writeFileSync(VKEY_PATH, JSON.stringify(vKey, null, 2));
  console.log("  Verification key exported");

  // Clean up intermediate zkey
  fs.unlinkSync(ZKEY_0_PATH);
}

async function createTestInput() {
  const poseidon = await buildPoseidon();
  const babyJub = await buildBabyjub();
  const F = poseidon.F;

  const secret = 123456789n;
  const pubKey = babyJub.mulPointEscalar(babyJub.Base8, secret);
  const Ax = F.toObject(pubKey[0]);
  const Ay = F.toObject(pubKey[1]);
  const commitment = F.toObject(poseidon([Ax, Ay]));

  const depth = 1;
  const siblings = [0n];
  while (siblings.length < 20) siblings.push(0n);

  return {
    secret: secret.toString(),
    merkleProofLength: depth.toString(),
    merkleProofIndex: "0",
    merkleProofSiblings: siblings.map((s) => s.toString()),
    scope: "1",
    sessionNonce: "42",
  };
}

async function main() {
  console.log("╔══════════════════════════════════════════════╗");
  console.log("║  Bolyra — Groth16 Proof Benchmark             ║");
  console.log("║  Circuit: HumanUniqueness (depth 20)         ║");
  console.log("║  Target: <10s proof generation (M-series Mac) ║");
  console.log("╚══════════════════════════════════════════════╝\n");

  if (!fs.existsSync(CIRCUIT_WASM)) {
    console.error("ERROR: Circuit not compiled.");
    process.exit(1);
  }

  const r1csInfo = await snarkjs.r1cs.info(CIRCUIT_R1CS);
  console.log(`Circuit: ${r1csInfo.nConstraints} constraints, ${r1csInfo.nVars} wires\n`);

  // Step 1: Groth16 Setup
  console.log("Step 1: Groth16 Setup (dev-only)");
  await setupGroth16();

  // Step 2: Generate test input
  console.log("\nStep 2: Generating test input...");
  const input = await createTestInput();

  // Step 3: Proof generation benchmark
  console.log("\nStep 3: Groth16 Proof Generation");
  const proveStart = performance.now();
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    input,
    CIRCUIT_WASM,
    ZKEY_FINAL_PATH
  );
  const proveTime = ((performance.now() - proveStart) / 1000).toFixed(2);

  console.log(`  Proof generation: ${proveTime}s`);
  console.log(`  Proof size: ${JSON.stringify(proof).length} bytes`);
  console.log(`  Public signals: ${publicSignals.length}`);

  // Step 4: Verification
  console.log("\nStep 4: Groth16 Proof Verification");
  const vKey = JSON.parse(fs.readFileSync(VKEY_PATH, "utf-8"));
  const verifyStart = performance.now();
  const valid = await snarkjs.groth16.verify(vKey, publicSignals, proof);
  const verifyTime = ((performance.now() - verifyStart) / 1000).toFixed(2);

  console.log(`  Verification: ${verifyTime}s`);
  console.log(`  Valid: ${valid}`);

  // Step 5: Consistency (3 more proofs)
  console.log("\nStep 5: Consistency check (3 more proofs)");
  const times = [parseFloat(proveTime)];
  for (let i = 0; i < 3; i++) {
    const start = performance.now();
    await snarkjs.groth16.fullProve(input, CIRCUIT_WASM, ZKEY_FINAL_PATH);
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
  console.log(`║  Proof valid:     ${valid.toString().padEnd(27)}║`);

  const target = 10;
  const status = parseFloat(avg) < target ? "✅ PASS" : "❌ FAIL";
  console.log(`║  Target (<${target}s):    ${status.padEnd(27)}║`);
  console.log("╚══════════════════════════════════════════════╝");

  // Comparison with AgentPolicy PLONK
  console.log("\n  COMPARISON:");
  console.log(`  HumanUniqueness (Groth16): ${avg}s avg`);
  console.log(`  AgentPolicy (PLONK):       16.32s avg`);
  console.log(`  Handshake wall-clock:      max(${avg}, 16.32) = ${Math.max(parseFloat(avg), 16.32).toFixed(2)}s (parallel)`);
}

main().catch((err) => {
  console.error("Benchmark failed:", err);
  process.exit(1);
});
