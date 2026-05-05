const snarkjs = require("snarkjs");
const path = require("path");
const { buildPoseidon, buildBabyjub } = require("circomlibjs");

const root = path.join(__dirname, "../build");
const WASM = path.join(root, "HumanUniqueness_js/HumanUniqueness.wasm");
const ZKEY = path.join(root, "HumanUniqueness_final.zkey");
const VKEY = require(path.join(root, "HumanUniqueness_vkey.json"));

(async () => {
  const poseidon = await buildPoseidon();
  const babyJub = await buildBabyjub();
  const F = poseidon.F;

  const secret = 123456789n;
  const pubKey = babyJub.mulPointEscalar(babyJub.Base8, secret);
  const Ax = F.toObject(pubKey[0]);
  const Ay = F.toObject(pubKey[1]);

  const siblings = new Array(20).fill("0");
  const input = {
    secret: secret.toString(),
    merkleProofLength: "0",
    merkleProofIndex: "0",
    merkleProofSiblings: siblings,
    scope: "1",
    sessionNonce: "42",
  };

  console.log("Warming up...");
  await snarkjs.groth16.fullProve(input, WASM, ZKEY);

  const N = 5;
  const times = [];
  for (let i = 0; i < N; i++) {
    const t0 = performance.now();
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM, ZKEY);
    const t1 = performance.now();
    times.push(t1 - t0);
    console.log(`  Run ${i + 1}: ${(t1 - t0).toFixed(0)}ms`);
    if (i === 0) {
      const ok = await snarkjs.groth16.verify(VKEY, publicSignals, proof);
      console.log(`  Verify: valid ${ok}`);
    }
  }
  const avg = times.reduce((a, b) => a + b) / N;
  console.log(`\nHumanUniqueness Groth16 (snarkjs): avg ${avg.toFixed(0)}ms`);
  process.exit(0);
})().catch(e => { console.error(e); process.exit(1); });
