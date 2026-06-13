const { expect } = require("chai");
const path = require("path");
const circom_tester = require("circom_tester");
const wasm_tester = circom_tester.wasm;
const { buildPoseidon, buildEddsa } = require("circomlibjs");

// FAST mode: witness generation only (no PLONK proof). Default.
// SLOW mode: opt-in via FULL_PROOF=1; runs full Groth16 proof + verification.
const FULL_PROOF = process.env.FULL_PROOF === "1";

describe("ModelInstanceBinding Circuit (C7)", function () {
  this.timeout(180000);

  let circuit;
  let poseidon;
  let eddsa;
  let F;

  // Two distinct keypairs: one for the operator, one for the provider.
  const OPERATOR_PRIV = Buffer.from(
    "0001020304050607080900010203040506070809000102030405060708090001",
    "hex"
  );
  const PROVIDER_PRIV = Buffer.from(
    "0a0b0c0d0e0f1011121314151617181920212223242526272829303132333435",
    "hex"
  );
  const ATTACKER_PRIV = Buffer.from(
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff01",
    "hex"
  );

  before(async function () {
    circuit = await wasm_tester(
      path.join(__dirname, "../src/ModelInstanceBinding.circom"),
      {
        include: [
          path.join(__dirname, "../node_modules"),
          path.join(__dirname, "../node_modules/circomlib/circuits"),
          path.join(
            __dirname,
            "../node_modules/@zk-kit/binary-merkle-root.circom/src"
          ),
        ],
      }
    );
    poseidon = await buildPoseidon();
    eddsa = await buildEddsa();
    F = poseidon.F;
  });

  // ---------- helpers ----------

  function pubFromPriv(priv) {
    const pk = eddsa.prv2pub(priv);
    return { Ax: F.toObject(pk[0]), Ay: F.toObject(pk[1]) };
  }

  function buildTree(leaves, leafIndex, maxDepth) {
    const depth = Math.max(1, Math.ceil(Math.log2(Math.max(leaves.length, 2))));
    let level = leaves.map((l) => BigInt(l));
    while (level.length < 2 ** depth) level.push(0n);
    const siblings = [];
    let idx = leafIndex;
    for (let d = 0; d < depth; d++) {
      const sibIdx = idx % 2 === 0 ? idx + 1 : idx - 1;
      siblings.push(level[sibIdx]);
      const next = [];
      for (let i = 0; i < level.length; i += 2) {
        next.push(F.toObject(poseidon([level[i], level[i + 1]])));
      }
      level = next;
      idx = Math.floor(idx / 2);
    }
    while (siblings.length < maxDepth) siblings.push(0n);
    return { root: level[0], siblings, depth, index: leafIndex };
  }

  /** Build a fully-formed valid input. Tests then mutate fields to test failures. */
  function buildValidInput({
    operatorPriv = OPERATOR_PRIV,
    providerPriv = PROVIDER_PRIV,
    modelHash = 12345n,
    permissionBitmask = 0b00000111n,
    expiryDeltaSec = 86400, // +1 day
    requiredScopeMask = 0b00000011n,
    sessionNonce = 42n,
    messagePlaintext = 999n,
  } = {}) {
    const op = pubFromPriv(operatorPriv);
    const prov = pubFromPriv(providerPriv);
    const expiryTimestamp = BigInt(
      Math.floor(Date.now() / 1000) + expiryDeltaSec
    );
    const currentTimestamp = BigInt(Math.floor(Date.now() / 1000));

    // credentialCommitment = Poseidon5(modelHash, opAx, opAy, bitmask, expiry)
    const credCommitment = poseidon([
      modelHash,
      op.Ax,
      op.Ay,
      permissionBitmask,
      expiryTimestamp,
    ]);
    const opSig = eddsa.signPoseidon(operatorPriv, credCommitment);

    // Phase 2: provider signs the FULL credentialCommitment (Poseidon5),
    // not Poseidon3(modelHash, opAx, opAy). This binds permissionBitmask
    // and expiryTimestamp to the provider's attestation, so the operator
    // cannot self-grant expanded permissions or extended expiry.
    const provSig = eddsa.signPoseidon(providerPriv, credCommitment);

    // Provider tree leaf = Poseidon2(provAx, provAy)
    const provLeaf = F.toObject(poseidon([prov.Ax, prov.Ay]));
    const provTree = buildTree([provLeaf], 0, 8);

    // Agent tree leaf = credentialCommitment
    const agentTree = buildTree([F.toObject(credCommitment)], 0, 20);

    return {
      modelHash,
      operatorPubkeyAx: op.Ax,
      operatorPubkeyAy: op.Ay,
      permissionBitmask,
      expiryTimestamp,
      operatorSigR8x: F.toObject(opSig.R8[0]),
      operatorSigR8y: F.toObject(opSig.R8[1]),
      operatorSigS: opSig.S,
      providerPubkeyAx: prov.Ax,
      providerPubkeyAy: prov.Ay,
      providerSigR8x: F.toObject(provSig.R8[0]),
      providerSigR8y: F.toObject(provSig.R8[1]),
      providerSigS: provSig.S,
      messagePlaintext,
      merkleProofLength: agentTree.depth,
      merkleProofIndex: agentTree.index,
      merkleProofSiblings: agentTree.siblings,
      providerMerkleProofLength: provTree.depth,
      providerMerkleProofIndex: provTree.index,
      providerMerkleProofSiblings: provTree.siblings,
      requiredScopeMask,
      currentTimestamp,
      sessionNonce,
      providerRegistryRoot: provTree.root,
    };
  }

  // ---------- happy path ----------

  it("verifies a valid (model, operator, message, provider) tuple", async function () {
    const input = buildValidInput();
    const witness = await circuit.calculateWitness(input, true);
    await circuit.checkConstraints(witness);

    // Public outputs at witness[1..6] (Phase 2: 6 outputs):
    //   1: agentMerkleRoot, 2: nullifierHash, 3: scopeCommitment,
    //   4: messageHash, 5: modelOperatorFingerprint,
    //   6: providerKeyCommitment
    const agentMerkleRoot = witness[1];
    expect(agentMerkleRoot.toString()).to.equal(
      input.merkleProofSiblings.length > 0
        ? // Recompute root from witness — buildTree returned it via .root
          // (we can recompute: but easier — just sanity that it's non-zero and
          // matches what the helper computed for our single-leaf tree)
          buildTree([
            F.toObject(
              poseidon([
                input.modelHash,
                input.operatorPubkeyAx,
                input.operatorPubkeyAy,
                input.permissionBitmask,
                input.expiryTimestamp,
              ])
            ),
          ], 0, 20).root.toString()
        : agentMerkleRoot.toString()
    );
  });

  // ---------- failure cases ----------

  it("rejects a forged operator signature", async function () {
    const input = buildValidInput();
    // Re-sign with attacker key (still a valid EdDSA signature, just wrong key)
    const attackerSig = eddsa.signPoseidon(
      ATTACKER_PRIV,
      poseidon([
        input.modelHash,
        input.operatorPubkeyAx,
        input.operatorPubkeyAy,
        input.permissionBitmask,
        input.expiryTimestamp,
      ])
    );
    input.operatorSigR8x = F.toObject(attackerSig.R8[0]);
    input.operatorSigR8y = F.toObject(attackerSig.R8[1]);
    input.operatorSigS = attackerSig.S;

    try {
      await circuit.calculateWitness(input, true);
      expect.fail("Should have rejected forged operator signature");
    } catch (err) {
      expect(err.message).to.match(/Assert Failed|signature|verify/i);
    }
  });

  it("rejects a forged provider signature", async function () {
    const input = buildValidInput();
    // Forge an attacker sig over the same credentialCommitment the valid
    // provider signed. Attacker key ≠ provider key → EdDSA verify fails.
    const credCommitment = poseidon([
      input.modelHash,
      input.operatorPubkeyAx,
      input.operatorPubkeyAy,
      input.permissionBitmask,
      input.expiryTimestamp,
    ]);
    const attackerSig = eddsa.signPoseidon(ATTACKER_PRIV, credCommitment);
    input.providerSigR8x = F.toObject(attackerSig.R8[0]);
    input.providerSigR8y = F.toObject(attackerSig.R8[1]);
    input.providerSigS = attackerSig.S;

    try {
      await circuit.calculateWitness(input, true);
      expect.fail("Should have rejected forged provider signature");
    } catch (err) {
      expect(err.message).to.match(/Assert Failed|signature|verify/i);
    }
  });

  it("rejects an expired credential", async function () {
    const input = buildValidInput({ expiryDeltaSec: -3600 }); // 1 hour ago
    try {
      await circuit.calculateWitness(input, true);
      expect.fail("Should have rejected expired credential");
    } catch (err) {
      expect(err.message).to.include("Assert Failed");
    }
  });

  it("rejects insufficient permissions (scope mismatch)", async function () {
    // Bitmask has only bit 0; required mask demands bit 1 too.
    const input = buildValidInput({
      permissionBitmask: 0b00000001n,
      requiredScopeMask: 0b00000011n,
    });
    try {
      await circuit.calculateWitness(input, true);
      expect.fail("Should have rejected insufficient permissions");
    } catch (err) {
      expect(err.message).to.include("Assert Failed");
    }
  });

  it("rejects a provider key that is not enrolled (wrong root)", async function () {
    const input = buildValidInput();
    // Mutate the registry root so the provider Merkle proof no longer matches.
    input.providerRegistryRoot = (BigInt(input.providerRegistryRoot) + 1n).toString();
    try {
      await circuit.calculateWitness(input, true);
      expect.fail("Should have rejected stale provider registry root");
    } catch (err) {
      expect(err.message).to.include("Assert Failed");
    }
  });

  it("prevents operator from self-granting expanded permissions (Phase 2)", async function () {
    // Pre-Phase-2: provider sig was over Poseidon3(model, opAx, opAy), which
    // omitted permissionBitmask + expiry. An operator with a valid sig for
    // bitmask 0b001 could rebuild a credential claiming bitmask 0b111 and
    // resign it themselves, with the SAME provider sig still verifying.
    //
    // Phase 2: provider sig binds credentialCommitment (Poseidon5 includes
    // bitmask + expiry). Inflating bitmask invalidates the provider sig.
    const input = buildValidInput({ permissionBitmask: 0b00000001n });

    // Operator re-signs an inflated credential. Provider sig is left as the
    // sig over the ORIGINAL low-permission credentialCommitment.
    const opPub = pubFromPriv(OPERATOR_PRIV);
    const inflatedBitmask = 0b11111111n;
    const inflatedCred = poseidon([
      input.modelHash,
      opPub.Ax,
      opPub.Ay,
      inflatedBitmask,
      input.expiryTimestamp,
    ]);
    const inflatedOpSig = eddsa.signPoseidon(OPERATOR_PRIV, inflatedCred);

    const tampered = { ...input };
    tampered.permissionBitmask = inflatedBitmask;
    tampered.operatorSigR8x = F.toObject(inflatedOpSig.R8[0]);
    tampered.operatorSigR8y = F.toObject(inflatedOpSig.R8[1]);
    tampered.operatorSigS = inflatedOpSig.S;
    // Rebuild agent tree leaf to match the tampered credential so the agent
    // Merkle proof itself stays internally consistent — forcing the failure
    // to come from the provider sig check, not the Merkle check.
    const tamperedAgentTree = buildTree([F.toObject(inflatedCred)], 0, 20);
    tampered.merkleProofLength = tamperedAgentTree.depth;
    tampered.merkleProofIndex = tamperedAgentTree.index;
    tampered.merkleProofSiblings = tamperedAgentTree.siblings;

    try {
      await circuit.calculateWitness(tampered, true);
      expect.fail(
        "Should have rejected operator self-grant — provider sig binds bitmask"
      );
    } catch (err) {
      expect(err.message).to.match(/Assert Failed|signature|verify/i);
    }
  });

  it("prevents cross-operator attestation reuse", async function () {
    // An attacker steals a provider attestation issued for operator A but tries
    // to use it under operator B's credential. The credential commitment binds
    // to operator B's keys, while the provider sig binds to operator A's —
    // so the operator EdDSA verification step (Step 7) fails.
    const validForOpA = buildValidInput({ operatorPriv: OPERATOR_PRIV });

    const opB = pubFromPriv(ATTACKER_PRIV);
    const tamperedInput = { ...validForOpA };
    tamperedInput.operatorPubkeyAx = opB.Ax;
    tamperedInput.operatorPubkeyAy = opB.Ay;
    // The operator sig will not verify against opB's key over the recomputed
    // credentialCommitment (which itself now also has different opB keys).

    try {
      await circuit.calculateWitness(tamperedInput, true);
      expect.fail("Should have rejected cross-operator attestation reuse");
    } catch (err) {
      expect(err.message).to.match(/Assert Failed|signature|verify/i);
    }
  });

  // ---------- slow mode (opt-in) ----------

  if (FULL_PROOF) {
    const fs = require("fs");
    const snarkjs = require("snarkjs");

    it("(slow) generates and verifies a full Groth16 proof", async function () {
      this.timeout(300000);
      const input = buildValidInput();

      const buildDir = path.join(__dirname, "../build");
      const wasmPath = path.join(
        buildDir,
        "ModelInstanceBinding_js/ModelInstanceBinding.wasm"
      );
      const zkeyPath = path.join(buildDir, "ModelInstanceBinding_final.zkey");
      const vkeyPath = path.join(
        buildDir,
        "ModelInstanceBinding_groth16_vkey.json"
      );
      if (!fs.existsSync(wasmPath) || !fs.existsSync(zkeyPath)) {
        this.skip();
      }

      const { proof, publicSignals } = await snarkjs.groth16.fullProve(
        input,
        wasmPath,
        zkeyPath
      );
      const vkey = JSON.parse(fs.readFileSync(vkeyPath, "utf8"));
      const ok = await snarkjs.groth16.verify(vkey, publicSignals, proof);
      expect(ok).to.equal(true);
      expect(publicSignals.length).to.equal(10);

      // Phase 2: providerKeyCommitment is now public (signal #5). It must
      // equal Poseidon2(providerPk.x, providerPk.y) for the same key the
      // sig was issued from — exposes WHICH enrolled provider signed.
      const expectedProviderKeyCommitment = F.toObject(
        poseidon([input.providerPubkeyAx, input.providerPubkeyAy])
      );
      expect(publicSignals[5]).to.equal(
        expectedProviderKeyCommitment.toString()
      );
    });
  }
});
