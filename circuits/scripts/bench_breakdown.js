// Microbench: where is the time actually going?
const snarkjs = require("snarkjs");
const path = require("path");
const fs = require("fs");
const os = require("os");
const { execFileSync } = require("child_process");
const { buildPoseidon, buildEddsa } = require("circomlibjs");

const root = path.join(__dirname, "../build");
const PROVER = path.join(root, "rapidsnark_prover");

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
  const zkey = path.join(root, "AgentPolicy_final.zkey");
  const N = 10;

  // Approach A: current SDK approach (snarkjs.wtns.calculate + rapidsnark exec)
  console.log("== A: snarkjs.wtns.calculate (file path each call) + rapidsnark exec ==");
  const aWtns = [];
  const aExec = [];
  for (let i = 0; i < N; i++) {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), `bench-a-${i}-`));
    const wtnsP = path.join(tmp, "w.wtns");
    const proofP = path.join(tmp, "p.json");
    const pubP = path.join(tmp, "pub.json");
    const t0 = performance.now();
    await snarkjs.wtns.calculate(input, wasmPath, wtnsP);
    const t1 = performance.now();
    execFileSync(PROVER, [zkey, wtnsP, proofP, pubP], { stdio: "pipe" });
    const t2 = performance.now();
    aWtns.push(t1 - t0);
    aExec.push(t2 - t1);
    fs.rmSync(tmp, { recursive: true, force: true });
  }
  const avg = (a) => (a.reduce((x, y) => x + y, 0) / a.length).toFixed(1);
  console.log(`  wtns avg: ${avg(aWtns)}ms`);
  console.log(`  exec avg: ${avg(aExec)}ms`);
  console.log(`  total:    ${(parseFloat(avg(aWtns)) + parseFloat(avg(aExec))).toFixed(1)}ms`);

  // Approach B: cached witness calculator (build once, reuse)
  console.log("\n== B: witness_calculator built once, reused (in-memory) ==");
  const wcBuilder = require(path.join(root, "AgentPolicy_js/witness_calculator.js"));
  const wasmBuf = fs.readFileSync(wasmPath);
  const wc = await wcBuilder(wasmBuf);
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
  console.log(`  vs A delta: ${(parseFloat(avg(aWtns)) + parseFloat(avg(aExec)) - parseFloat(avg(bWtns)) - parseFloat(avg(bExec))).toFixed(1)}ms`);

  // Approach C: shared memfs (wtns to /dev/shm equivalent — macOS uses tmpfs at /tmp already)
  // Skip; macOS /tmp is on local SSD, no ramdisk by default. Disk I/O for 1.5MB is ~1ms on NVMe.

  process.exit(0);
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
