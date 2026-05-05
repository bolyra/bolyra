// Measure rapidsnark spawn vs actual prove time
const path = require("path");
const fs = require("fs");
const os = require("os");
const { execFileSync, spawnSync } = require("child_process");

const root = path.join(__dirname, "../build");
const PROVER = path.join(root, "rapidsnark_prover");

(async () => {
  const N = 20;
  // Bare process spawn (just `true` binary)
  const noop = [];
  for (let i = 0; i < N; i++) {
    const t0 = performance.now();
    execFileSync("/usr/bin/true", [], { stdio: "pipe" });
    noop.push(performance.now() - t0);
  }
  const avg = (a) => (a.reduce((x, y) => x + y, 0) / a.length).toFixed(1);
  console.log(`bare spawn (/usr/bin/true): ${avg(noop)}ms`);

  // rapidsnark spawn-only (no args, fails fast)
  const noopRs = [];
  for (let i = 0; i < N; i++) {
    const t0 = performance.now();
    spawnSync(PROVER, [], { stdio: "pipe" });
    noopRs.push(performance.now() - t0);
  }
  console.log(`rapidsnark spawn (no args): ${avg(noopRs)}ms`);

  // Full rapidsnark proving call (need a witness file first)
  const snarkjs = require("snarkjs");
  const { buildPoseidon, buildEddsa } = require("circomlibjs");
  const poseidon = await buildPoseidon();
  const eddsa = await buildEddsa();
  const F = poseidon.F;
  const sk = Buffer.from("0001020304050607080900010203040506070809000102030405060708090001", "hex");
  const pub = eddsa.prv2pub(sk);
  const Ax = F.toObject(pub[0]);
  const Ay = F.toObject(pub[1]);
  const credCommit = poseidon([12345n, Ax, Ay, 7n, BigInt(Date.now() / 1000 + 86400)]);
  const sig = eddsa.signPoseidon(sk, credCommit);
  const input = {
    modelHash: "12345",
    operatorPubkeyAx: Ax.toString(),
    operatorPubkeyAy: Ay.toString(),
    permissionBitmask: "7",
    expiryTimestamp: String(Math.floor(Date.now() / 1000) + 86400),
    sigR8x: F.toObject(sig.R8[0]).toString(),
    sigR8y: F.toObject(sig.R8[1]).toString(),
    sigS: sig.S.toString(),
    merkleProofLength: "0",
    merkleProofIndex: "0",
    merkleProofSiblings: new Array(20).fill("0"),
    requiredScopeMask: "3",
    currentTimestamp: String(Math.floor(Date.now() / 1000)),
    sessionNonce: "42",
  };
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), `bench-spawn-`));
  const wtnsP = path.join(tmp, "w.wtns");
  await snarkjs.wtns.calculate(input, path.join(root, "AgentPolicy_js/AgentPolicy.wasm"), wtnsP);
  const zkey = path.join(root, "AgentPolicy_final.zkey");
  // Warm
  execFileSync(PROVER, [zkey, wtnsP, path.join(tmp, "p.json"), path.join(tmp, "pub.json")], { stdio: "pipe" });

  const proveTimes = [];
  for (let i = 0; i < N; i++) {
    const t0 = performance.now();
    execFileSync(PROVER, [zkey, wtnsP, path.join(tmp, "p.json"), path.join(tmp, "pub.json")], { stdio: "pipe" });
    proveTimes.push(performance.now() - t0);
  }
  console.log(`rapidsnark full prove: ${avg(proveTimes)}ms`);
  console.log(`prove minus spawn:    ${(parseFloat(avg(proveTimes)) - parseFloat(avg(noopRs))).toFixed(1)}ms (this is real compute)`);
  fs.rmSync(tmp, { recursive: true, force: true });

  // Compare snarkjs.groth16.prove (in-process) - reads zkey, generates proof
  console.log("\n== snarkjs.groth16.prove (in-process) ==");
  const sjTimes = [];
  // Warm
  await snarkjs.groth16.prove(zkey, await snarkjs.wtns.calculate(input, path.join(root, "AgentPolicy_js/AgentPolicy.wasm"), undefined));
  for (let i = 0; i < N; i++) {
    const tmp2 = fs.mkdtempSync(path.join(os.tmpdir(), `sj-`));
    const w = path.join(tmp2, "w.wtns");
    await snarkjs.wtns.calculate(input, path.join(root, "AgentPolicy_js/AgentPolicy.wasm"), w);
    const t0 = performance.now();
    await snarkjs.groth16.prove(zkey, w);
    sjTimes.push(performance.now() - t0);
    fs.rmSync(tmp2, { recursive: true, force: true });
  }
  console.log(`snarkjs.groth16.prove: ${avg(sjTimes)}ms`);

  process.exit(0);
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
