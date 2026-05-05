// End-to-end benchmark: witness gen (snarkjs WASM) + proof gen (rapidsnark native).
// Compares against snarkjs.groth16.fullProve.

const snarkjs = require("snarkjs");
const path = require("path");
const fs = require("fs");
const os = require("os");
const { execFileSync } = require("child_process");
const { buildPoseidon, buildEddsa, buildBabyjub } = require("circomlibjs");

const root = path.join(__dirname, "../build");
const PROVER = path.join(root, "rapidsnark_prover");

async function buildAgentInput() {
  const poseidon = await buildPoseidon();
  const eddsa = await buildEddsa();
  const F = poseidon.F;
  const privateKey = Buffer.from(
    "0001020304050607080900010203040506070809000102030405060708090001",
    "hex"
  );
  const pubKey = eddsa.prv2pub(privateKey);
  const Ax = F.toObject(pubKey[0]);
  const Ay = F.toObject(pubKey[1]);
  const modelHash = 12345n;
  const permissionBitmask = 0b00000111n;
  const expiryTimestamp = BigInt(Math.floor(Date.now() / 1000) + 86400);
  const currentTimestamp = BigInt(Math.floor(Date.now() / 1000));
  const credCommit = poseidon([modelHash, Ax, Ay, permissionBitmask, expiryTimestamp]);
  const sig = eddsa.signPoseidon(privateKey, credCommit);
  return {
    modelHash: modelHash.toString(),
    operatorPubkeyAx: Ax.toString(),
    operatorPubkeyAy: Ay.toString(),
    permissionBitmask: permissionBitmask.toString(),
    expiryTimestamp: expiryTimestamp.toString(),
    sigR8x: F.toObject(sig.R8[0]).toString(),
    sigR8y: F.toObject(sig.R8[1]).toString(),
    sigS: sig.S.toString(),
    merkleProofLength: "0",
    merkleProofIndex: "0",
    merkleProofSiblings: new Array(20).fill("0"),
    requiredScopeMask: "3",
    currentTimestamp: currentTimestamp.toString(),
    sessionNonce: "42",
  };
}

async function buildHumanInput() {
  const babyJub = await buildBabyjub();
  const poseidon = await buildPoseidon();
  const F = poseidon.F;
  const secret = 123456789n;
  const pubKey = babyJub.mulPointEscalar(babyJub.Base8, secret);
  return {
    secret: secret.toString(),
    merkleProofLength: "0",
    merkleProofIndex: "0",
    merkleProofSiblings: new Array(20).fill("0"),
    scope: "1",
    sessionNonce: "42",
  };
}

async function rapidsnarkProof(circuitName, input, N) {
  const wasmDir = path.join(root, `${circuitName}_js`);
  const zkey = path.join(root, `${circuitName}_final.zkey`);
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), `rs-${circuitName}-`));
  const wtnsPath = path.join(tmp, "witness.wtns");
  const proofPath = path.join(tmp, "proof.json");
  const publicPath = path.join(tmp, "public.json");

  // Witness generation via snarkjs (WASM)
  const wasmBuffer = fs.readFileSync(path.join(wasmDir, `${circuitName}.wasm`));

  // Warm
  await snarkjs.wtns.calculate(input, path.join(wasmDir, `${circuitName}.wasm`), wtnsPath);
  execFileSync(PROVER, [zkey, wtnsPath, proofPath, publicPath]);

  const wtnsTimes = [];
  const proveTimes = [];
  for (let i = 0; i < N; i++) {
    const t0 = performance.now();
    await snarkjs.wtns.calculate(input, path.join(wasmDir, `${circuitName}.wasm`), wtnsPath);
    const t1 = performance.now();
    execFileSync(PROVER, [zkey, wtnsPath, proofPath, publicPath]);
    const t2 = performance.now();
    wtnsTimes.push(t1 - t0);
    proveTimes.push(t2 - t1);
  }
  const wAvg = wtnsTimes.reduce((a, b) => a + b) / N;
  const pAvg = proveTimes.reduce((a, b) => a + b) / N;
  const total = wAvg + pAvg;
  return { wAvg, pAvg, total, wtnsTimes, proveTimes };
}

async function snarkjsProof(circuitName, input, N) {
  const wasm = path.join(root, `${circuitName}_js/${circuitName}.wasm`);
  const zkey = path.join(root, `${circuitName}_final.zkey`);
  // Warm
  await snarkjs.groth16.fullProve(input, wasm, zkey);
  const times = [];
  for (let i = 0; i < N; i++) {
    const t0 = performance.now();
    await snarkjs.groth16.fullProve(input, wasm, zkey);
    times.push(performance.now() - t0);
  }
  const avg = times.reduce((a, b) => a + b) / N;
  return { avg, times };
}

(async () => {
  const N = 5;

  console.log("== AgentPolicy ==");
  const agentInput = await buildAgentInput();
  const sjA = await snarkjsProof("AgentPolicy", agentInput, N);
  const rsA = await rapidsnarkProof("AgentPolicy", agentInput, N);
  console.log(`  snarkjs fullProve avg:    ${sjA.avg.toFixed(0)}ms`);
  console.log(`  rapidsnark wtns avg:      ${rsA.wAvg.toFixed(0)}ms`);
  console.log(`  rapidsnark prove avg:     ${rsA.pAvg.toFixed(0)}ms`);
  console.log(`  rapidsnark total avg:     ${rsA.total.toFixed(0)}ms`);
  console.log(`  speedup vs snarkjs:       ${(sjA.avg / rsA.total).toFixed(1)}x`);

  console.log("\n== HumanUniqueness ==");
  const humanInput = await buildHumanInput();
  const sjH = await snarkjsProof("HumanUniqueness", humanInput, N);
  const rsH = await rapidsnarkProof("HumanUniqueness", humanInput, N);
  console.log(`  snarkjs fullProve avg:    ${sjH.avg.toFixed(0)}ms`);
  console.log(`  rapidsnark wtns avg:      ${rsH.wAvg.toFixed(0)}ms`);
  console.log(`  rapidsnark prove avg:     ${rsH.pAvg.toFixed(0)}ms`);
  console.log(`  rapidsnark total avg:     ${rsH.total.toFixed(0)}ms`);
  console.log(`  speedup vs snarkjs:       ${(sjH.avg / rsH.total).toFixed(1)}x`);

  console.log("\n== Handshake (parallel max) ==");
  const handshakeSnarkjs = Math.max(sjA.avg, sjH.avg);
  const handshakeRapidsnark = Math.max(rsA.total, rsH.total);
  console.log(`  snarkjs:    ${handshakeSnarkjs.toFixed(0)}ms`);
  console.log(`  rapidsnark: ${handshakeRapidsnark.toFixed(0)}ms`);
  console.log(`  Sub-200ms target: ${handshakeRapidsnark < 200 ? "✅ PASS" : "❌ FAIL"} (${handshakeRapidsnark.toFixed(0)}ms)`);

  process.exit(0);
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
