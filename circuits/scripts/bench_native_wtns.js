// Bench native witness gen (calc-witness binary) vs cached WASM calculator.
const snarkjs = require("snarkjs");
const path = require("path");
const fs = require("fs");
const os = require("os");
const { execFileSync, spawnSync } = require("child_process");
const { buildPoseidon, buildEddsa } = require("circomlibjs");

const root = path.join(__dirname, "../build");
const PROVER = path.join(root, "rapidsnark_prover");
const CALC_WITNESS = "/tmp/circom-witnesscalc/target/release/calc-witness";

async function buildAgentInput() {
  const poseidon = await buildPoseidon();
  const eddsa = await buildEddsa();
  const F = poseidon.F;
  const sk = Buffer.from("0001020304050607080900010203040506070809000102030405060708090001", "hex");
  const pub = eddsa.prv2pub(sk);
  const Ax = F.toObject(pub[0]);
  const Ay = F.toObject(pub[1]);
  const modelHash = 12345n;
  const perm = 0b111n;
  const exp = BigInt(Math.floor(Date.now() / 1000) + 86400);
  const cur = BigInt(Math.floor(Date.now() / 1000));
  const credCommit = poseidon([modelHash, Ax, Ay, perm, exp]);
  const sig = eddsa.signPoseidon(sk, credCommit);
  return {
    modelHash: modelHash.toString(),
    operatorPubkeyAx: Ax.toString(),
    operatorPubkeyAy: Ay.toString(),
    permissionBitmask: perm.toString(),
    expiryTimestamp: exp.toString(),
    sigR8x: F.toObject(sig.R8[0]).toString(),
    sigR8y: F.toObject(sig.R8[1]).toString(),
    sigS: sig.S.toString(),
    merkleProofLength: "0",
    merkleProofIndex: "0",
    merkleProofSiblings: new Array(20).fill("0"),
    requiredScopeMask: "3",
    currentTimestamp: cur.toString(),
    sessionNonce: "42",
  };
}

(async () => {
  const input = await buildAgentInput();
  const wasmPath = path.join(root, "AgentPolicy_js/AgentPolicy.wasm");
  const wcdPath = path.join(root, "native_wcd/AgentPolicy.wcd");
  const zkey = path.join(root, "AgentPolicy_final.zkey");
  const N = 20;
  const avg = (a) => (a.reduce((x, y) => x + y, 0) / a.length).toFixed(1);

  // Sanity: native witness should be byte-equal (or at least valid) to WASM witness.
  const sanityTmp = fs.mkdtempSync(path.join(os.tmpdir(), "sanity-"));
  const wasmW = path.join(sanityTmp, "wasm.wtns");
  const natW = path.join(sanityTmp, "nat.wtns");
  const inJ = path.join(sanityTmp, "input.json");
  fs.writeFileSync(inJ, JSON.stringify(input));
  await snarkjs.wtns.calculate(input, wasmPath, wasmW);
  spawnSync(CALC_WITNESS, [wcdPath, inJ, natW], { stdio: "pipe" });
  const wasmBuf = fs.readFileSync(wasmW);
  const natBuf = fs.readFileSync(natW);
  console.log(`sanity: wasm ${wasmBuf.length}b, native ${natBuf.length}b, equal=${wasmBuf.equals(natBuf)}`);
  // Try proving with native witness
  const sanityProof = path.join(sanityTmp, "p.json");
  const sanityPub = path.join(sanityTmp, "pub.json");
  try {
    execFileSync(PROVER, [zkey, natW, sanityProof, sanityPub], { stdio: "pipe" });
    console.log("sanity: native witness produces valid proof ✓");
  } catch (e) {
    console.log("sanity: native witness FAILED to prove ✗", e.message);
    fs.rmSync(sanityTmp, { recursive: true, force: true });
    process.exit(1);
  }
  fs.rmSync(sanityTmp, { recursive: true, force: true });

  // Approach B: cached WASM witness calculator (current SDK approach)
  console.log("\n== B: cached WASM witness_calculator + rapidsnark exec ==");
  const wcBuilder = require(path.join(root, "AgentPolicy_js/witness_calculator.js"));
  const wasmBufRead = fs.readFileSync(wasmPath);
  const wc = await wcBuilder(wasmBufRead);
  // Warm
  await wc.calculateWTNSBin(input, 0);
  const bWtns = [];
  const bExec = [];
  for (let i = 0; i < N; i++) {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), `bench-b-${i}-`));
    const wtnsP = path.join(tmp, "w.wtns");
    const proofP = path.join(tmp, "p.json");
    const pubP = path.join(tmp, "pub.json");
    const t0 = performance.now();
    const wtnsBuf = await wc.calculateWTNSBin(input, 0);
    fs.writeFileSync(wtnsP, Buffer.from(wtnsBuf));
    const t1 = performance.now();
    execFileSync(PROVER, [zkey, wtnsP, proofP, pubP], { stdio: "pipe" });
    const t2 = performance.now();
    bWtns.push(t1 - t0);
    bExec.push(t2 - t1);
    fs.rmSync(tmp, { recursive: true, force: true });
  }
  console.log(`  wtns avg: ${avg(bWtns)}ms`);
  console.log(`  exec avg: ${avg(bExec)}ms`);
  console.log(`  total:    ${(parseFloat(avg(bWtns)) + parseFloat(avg(bExec))).toFixed(1)}ms`);

  // Approach C: native calc-witness binary
  console.log("\n== C: native calc-witness binary + rapidsnark exec ==");
  // Warm
  {
    const t = fs.mkdtempSync(path.join(os.tmpdir(), `warm-`));
    const inP = path.join(t, "in.json");
    fs.writeFileSync(inP, JSON.stringify(input));
    spawnSync(CALC_WITNESS, [wcdPath, inP, path.join(t, "w.wtns")], { stdio: "pipe" });
    fs.rmSync(t, { recursive: true, force: true });
  }
  const cWtns = [];
  const cExec = [];
  for (let i = 0; i < N; i++) {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), `bench-c-${i}-`));
    const inP = path.join(tmp, "in.json");
    const wtnsP = path.join(tmp, "w.wtns");
    const proofP = path.join(tmp, "p.json");
    const pubP = path.join(tmp, "pub.json");
    fs.writeFileSync(inP, JSON.stringify(input));
    const t0 = performance.now();
    spawnSync(CALC_WITNESS, [wcdPath, inP, wtnsP], { stdio: "pipe" });
    const t1 = performance.now();
    execFileSync(PROVER, [zkey, wtnsP, proofP, pubP], { stdio: "pipe" });
    const t2 = performance.now();
    cWtns.push(t1 - t0);
    cExec.push(t2 - t1);
    fs.rmSync(tmp, { recursive: true, force: true });
  }
  console.log(`  wtns avg: ${avg(cWtns)}ms`);
  console.log(`  exec avg: ${avg(cExec)}ms`);
  console.log(`  total:    ${(parseFloat(avg(cWtns)) + parseFloat(avg(cExec))).toFixed(1)}ms`);
  const bTotal = parseFloat(avg(bWtns)) + parseFloat(avg(bExec));
  const cTotal = parseFloat(avg(cWtns)) + parseFloat(avg(cExec));
  console.log(`\n  vs B delta: ${(bTotal - cTotal).toFixed(1)}ms (${cTotal < bTotal ? "C wins" : "B wins"})`);

  process.exit(0);
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
