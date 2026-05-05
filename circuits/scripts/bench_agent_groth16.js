const snarkjs = require("snarkjs");
const path = require("path");
const { buildPoseidon, buildEddsa } = require("circomlibjs");

const root = "/Users/lordviswa/Projects/identityos/circuits/build";
const WASM = path.join(root, "AgentPolicy_js/AgentPolicy.wasm");
const ZKEY = path.join(root, "AgentPolicy_final.zkey");
const VKEY = require(path.join(root, "AgentPolicy_groth16_vkey.json"));

(async () => {
  const poseidon = await buildPoseidon();
  const eddsa = await buildEddsa();
  const F = poseidon.F;

  const privateKey = Buffer.from("0001020304050607080900010203040506070809000102030405060708090001", "hex");
  const pubKey = eddsa.prv2pub(privateKey);

  const modelHash = 12345n;
  const Ax = F.toObject(pubKey[0]);
  const Ay = F.toObject(pubKey[1]);
  const permissionBitmask = 0b00000111n;
  const expiryTimestamp = BigInt(Math.floor(Date.now() / 1000) + 86400);
  const currentTimestamp = BigInt(Math.floor(Date.now() / 1000));
  const sessionNonce = 42n;
  const requiredScopeMask = 0b00000011n;

  // Correct Poseidon5: modelHash, Ax, Ay, bitmask, expiry
  const credCommit = poseidon([modelHash, Ax, Ay, permissionBitmask, expiryTimestamp]);
  const signature = eddsa.signPoseidon(privateKey, credCommit);

  const siblings = new Array(20).fill("0");

  const input = {
    modelHash: modelHash.toString(),
    operatorPubkeyAx: Ax.toString(),
    operatorPubkeyAy: Ay.toString(),
    permissionBitmask: permissionBitmask.toString(),
    expiryTimestamp: expiryTimestamp.toString(),
    sigR8x: F.toObject(signature.R8[0]).toString(),
    sigR8y: F.toObject(signature.R8[1]).toString(),
    sigS: signature.S.toString(),
    merkleProofLength: "0",
    merkleProofIndex: "0",
    merkleProofSiblings: siblings,
    requiredScopeMask: requiredScopeMask.toString(),
    currentTimestamp: currentTimestamp.toString(),
    sessionNonce: sessionNonce.toString(),
  };

  // Warm-up
  console.log("Warming up...");
  await snarkjs.groth16.fullProve(input, WASM, ZKEY);

  const N = 5;
  const times = [];
  for (let i = 0; i < N; i++) {
    const t0 = performance.now();
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM, ZKEY);
    const t1 = performance.now();
    times.push(t1 - t0);
    console.log(`  Run ${i+1}: ${(t1-t0).toFixed(0)}ms`);
    if (i === 0) {
      const v0 = performance.now();
      const ok = await snarkjs.groth16.verify(VKEY, publicSignals, proof);
      console.log(`  Verify: ${(performance.now()-v0).toFixed(0)}ms (valid: ${ok})`);
    }
  }
  const avg = times.reduce((a,b)=>a+b)/N;
  const min = Math.min(...times);
  const max = Math.max(...times);
  console.log(`\nAgentPolicy Groth16 (snarkjs): avg ${avg.toFixed(0)}ms, min ${min.toFixed(0)}ms, max ${max.toFixed(0)}ms`);
  console.log(`PLONK was ~16320ms → ${(16320/avg).toFixed(1)}x speedup`);
  process.exit(0);
})().catch(e => { console.error(e); process.exit(1); });
