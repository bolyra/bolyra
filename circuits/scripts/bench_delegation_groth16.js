const snarkjs = require("snarkjs");
const path = require("path");
const { buildPoseidon, buildEddsa } = require("circomlibjs");

const root = path.join(__dirname, "../build");
const WASM = path.join(root, "Delegation_js/Delegation.wasm");
const ZKEY = path.join(root, "Delegation_final.zkey");
const VKEY = require(path.join(root, "Delegation_groth16_vkey.json"));

(async () => {
  const poseidon = await buildPoseidon();
  const eddsa = await buildEddsa();
  const F = poseidon.F;
  const h = (xs) => F.toObject(poseidon(xs));

  // Delegator (operator) keys
  const delegatorPrivKey = Buffer.from(
    "0001020304050607080900010203040506070809000102030405060708090001",
    "hex"
  );
  const delegatorPubKey = eddsa.prv2pub(delegatorPrivKey);
  const Ax = F.toObject(delegatorPubKey[0]);
  const Ay = F.toObject(delegatorPubKey[1]);

  const delegatorModelHash = 12345n;
  const delegatorScope = 0b00000111n; // read+write+small-fin
  const delegateeScope = 0b00000011n; // read+write
  const delegatorExpiry = 1000000n;
  const delegateeExpiry = 800000n;
  const currentTimestamp = 100000n;
  const sessionNonce = 42n;
  const delegateeCredCommitment = 54321n;

  // delegatorCredCommitment must equal Poseidon5(modelHash, Ax, Ay, scope, expiry)
  const delegatorCredCommitment = h([
    delegatorModelHash,
    Ax,
    Ay,
    delegatorScope,
    delegatorExpiry,
  ]);

  // previousScopeCommitment = Poseidon3(scope, credCommitment, expiry)
  const previousScopeCommitment = h([
    delegatorScope,
    delegatorCredCommitment,
    delegatorExpiry,
  ]);

  // Token = Poseidon4(prevScopeCommit, delegateeCredCommit, delegateeScope, delegateeExpiry)
  const tokenFe = poseidon([
    previousScopeCommitment,
    delegateeCredCommitment,
    delegateeScope,
    delegateeExpiry,
  ]);
  const sig = eddsa.signPoseidon(delegatorPrivKey, tokenFe);

  // Single-leaf merkle proof for delegatee
  const siblings = new Array(20).fill("0");

  const input = {
    delegatorScope: delegatorScope.toString(),
    delegateeScope: delegateeScope.toString(),
    delegateeExpiry: delegateeExpiry.toString(),
    delegatorExpiry: delegatorExpiry.toString(),
    delegatorModelHash: delegatorModelHash.toString(),
    delegatorPubkeyAx: Ax.toString(),
    delegatorPubkeyAy: Ay.toString(),
    sigR8x: F.toObject(sig.R8[0]).toString(),
    sigR8y: F.toObject(sig.R8[1]).toString(),
    sigS: sig.S.toString(),
    delegatorCredCommitment: delegatorCredCommitment.toString(),
    delegateeCredCommitment: delegateeCredCommitment.toString(),
    delegateeMerkleProofLength: "1",
    delegateeMerkleProofIndex: "0",
    delegateeMerkleProofSiblings: siblings,
    previousScopeCommitment: previousScopeCommitment.toString(),
    sessionNonce: sessionNonce.toString(),
    currentTimestamp: currentTimestamp.toString(),
  };

  console.log("Warming up...");
  await snarkjs.groth16.fullProve(input, WASM, ZKEY);

  const N = 5;
  const times = [];
  for (let i = 0; i < N; i++) {
    const t0 = performance.now();
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
      input,
      WASM,
      ZKEY
    );
    const t1 = performance.now();
    times.push(t1 - t0);
    console.log(`  Run ${i + 1}: ${(t1 - t0).toFixed(0)}ms`);
    if (i === 0) {
      const v0 = performance.now();
      const ok = await snarkjs.groth16.verify(VKEY, publicSignals, proof);
      console.log(`  Verify: ${(performance.now() - v0).toFixed(0)}ms (valid: ${ok})`);
    }
  }
  const avg = times.reduce((a, b) => a + b) / N;
  console.log(
    `\nDelegation Groth16 (snarkjs): avg ${avg.toFixed(0)}ms, min ${Math.min(...times).toFixed(0)}ms, max ${Math.max(...times).toFixed(0)}ms`
  );
  process.exit(0);
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
