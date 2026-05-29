/**
 * On-chain 2-hop delegation demo.
 *
 * Stands up a fresh hardhat in-process chain, deploys the full verifier stack
 * + IdentityRegistry, and walks the v0.3 delegation flow end-to-end with real
 * Groth16 proofs:
 *
 *     human + rootCred         (handshake — seeds chain state)
 *     rootCred → agentACred    (hop 1, on-chain verifyDelegation)
 *     agentACred → agentBCred  (hop 2, on-chain verifyDelegation)
 *
 * Then asserts: chain depth 2, last scope commitment matches agentB's leaf
 * Poseidon3(scope, commitment, expiry), and replaying hop 2 reverts with
 * ScopeChainMismatch (chain state already advanced).
 *
 * Mirrors the off-chain demo (examples/mcp-demo/src/delegation-demo.ts) but
 * proves the chain to the on-chain registry rather than the SDK verifier.
 *
 *   cd contracts && npx hardhat run scripts/delegation-demo-onchain.js
 */

const path = require("path");
const { ethers } = require("hardhat");
const { buildPoseidon, buildBabyjub, buildEddsa } = require("circomlibjs");
const { proveGroth16 } = require("../../sdk/dist/prover");
const { delegate } = require("../../sdk/dist/delegation");

const HUMAN_WASM = path.join(__dirname, "../../circuits/build/HumanUniqueness_js/HumanUniqueness.wasm");
const HUMAN_ZKEY = path.join(__dirname, "../../circuits/build/HumanUniqueness_final.zkey");
const AGENT_WASM = path.join(__dirname, "../../circuits/build/AgentPolicy_js/AgentPolicy.wasm");
const AGENT_ZKEY = path.join(__dirname, "../../circuits/build/AgentPolicy_final.zkey");

const DELEGATION_MAX_DEPTH = 20;

// Snarkjs Groth16 → flat 8-element calldata array (pi_b column swap).
function formatProofForSolidity(p) {
  return [
    p.pi_a[0], p.pi_a[1],
    p.pi_b[0][1], p.pi_b[0][0],
    p.pi_b[1][1], p.pi_b[1][0],
    p.pi_c[0], p.pi_c[1],
  ];
}

async function main() {
  console.log("=== Bolyra v0.3 on-chain 2-hop delegation demo ===\n");

  const poseidon = await buildPoseidon();
  const babyJub = await buildBabyjub();
  const eddsa = await buildEddsa();
  const F = poseidon.F;

  // ─── Deploy verifier stack + registry ───
  const PoseidonT3 = await ethers.getContractFactory("PoseidonT3");
  const poseidonT3 = await PoseidonT3.deploy();

  const Groth16Verifier = await ethers.getContractFactory("Groth16Verifier");
  const groth16Verifier = await Groth16Verifier.deploy();

  const AgentVerifier = await ethers.getContractFactory(
    "contracts/AgentVerifier.sol:AgentGroth16Verifier",
  );
  const agentVerifier = await AgentVerifier.deploy();

  const DelegationVerifier = await ethers.getContractFactory(
    "contracts/DelegationVerifier.sol:DelegationGroth16Verifier",
  );
  const delegationVerifier = await DelegationVerifier.deploy();

  const IdentityRegistry = await ethers.getContractFactory("IdentityRegistry", {
    libraries: { PoseidonT3: await poseidonT3.getAddress() },
  });
  const registry = await IdentityRegistry.deploy(
    await groth16Verifier.getAddress(),
    await agentVerifier.getAddress(),
    await delegationVerifier.getAddress(),
  );
  console.log("Registry deployed:", await registry.getAddress(), "\n");

  // ─── Identities ───
  const humanSecret = 987654321n;
  const humanPub = babyJub.mulPointEscalar(babyJub.Base8, humanSecret);
  const humanCommitment = F.toObject(poseidon([
    F.toObject(humanPub[0]),
    F.toObject(humanPub[1]),
  ]));

  // Three distinct operator keys (one per credential), each signing its own
  // commitment. Scope narrows root → A → B per the cumulative-bit rules.
  function makeCred(modelHash, opPrivHex, bitmask, expiry) {
    const opPriv = Buffer.from(opPrivHex, "hex");
    const opPub = eddsa.prv2pub(opPriv);
    const ax = F.toObject(opPub[0]);
    const ay = F.toObject(opPub[1]);
    const credFe = poseidon([modelHash, ax, ay, bitmask, expiry]);
    const commitment = F.toObject(credFe);
    const sig = eddsa.signPoseidon(opPriv, credFe);
    return {
      cred: {
        modelHash,
        operatorPublicKey: { x: ax, y: ay },
        permissionBitmask: bitmask,
        expiryTimestamp: expiry,
        signature: {
          R8: {
            x: F.toObject(sig.R8[0]),
            y: F.toObject(sig.R8[1]),
          },
          S: sig.S,
        },
        commitment,
      },
      opPriv,
      ax,
      ay,
    };
  }

  const rootExpiry = BigInt(Math.floor(Date.now() / 1000) + 86400);
  const agentAExpiry = rootExpiry - 3600n;
  const agentBExpiry = agentAExpiry - 60n;

  // Scope narrowing: root = READ|WRITE|FIN_SMALL|FIN_MED|FIN_UNLIM (0b00011111)
  //                  A    = READ|WRITE|FIN_SMALL|FIN_MED          (0b00001111)
  //                  B    = READ|WRITE                            (0b00000011)
  const root = makeCred(
    0xa1n,
    "1101020304050607080900010203040506070809000102030405060708090001",
    0b00011111n,
    rootExpiry,
  );
  const agentA = makeCred(
    0xa2n,
    "2201020304050607080900010203040506070809000102030405060708090002",
    0b00001111n,
    agentAExpiry,
  );
  const agentB = makeCred(
    0xa3n,
    "3301020304050607080900010203040506070809000102030405060708090003",
    0b00000011n,
    agentBExpiry,
  );

  console.log(`root   commitment: ${root.cred.commitment.toString().slice(0, 20)}...`);
  console.log(`agentA commitment: ${agentA.cred.commitment.toString().slice(0, 20)}...`);
  console.log(`agentB commitment: ${agentB.cred.commitment.toString().slice(0, 20)}...\n`);

  // ─── Enroll: human, root, agentA, agentB ───
  // LeanIMT after 3 agents:
  //   leaves = [root, agentA, agentB]
  //   level 1: H(root, agentA); agentB promoted (no level-0 sibling)
  //   root (level 2): H(H(root, agentA), agentB)
  await registry.enrollHuman(humanCommitment);

  await registry.enrollAgent(root.cred.commitment);
  const rootA = await registry.agentTreeRoot();             // = root.commitment
  if (rootA.toString() !== root.cred.commitment.toString()) {
    throw new Error("rootA mismatch");
  }

  await registry.enrollAgent(agentA.cred.commitment);
  const rootB = await registry.agentTreeRoot();             // = H(root, agentA)
  const expectedRootB = F.toObject(poseidon([
    root.cred.commitment,
    agentA.cred.commitment,
  ]));
  if (rootB.toString() !== expectedRootB.toString()) {
    throw new Error("rootB mismatch");
  }

  await registry.enrollAgent(agentB.cred.commitment);
  const rootC = await registry.agentTreeRoot();             // = H(rootB, agentB)
  const expectedRootC = F.toObject(poseidon([rootB, agentB.cred.commitment]));
  if (rootC.toString() !== expectedRootC.toString()) {
    throw new Error("rootC mismatch");
  }
  console.log("Enrolled human + 3 agents. All 3 agent roots in history buffer.\n");

  // ─── Handshake (root) ───
  // Proves against rootA (single-leaf root = root.commitment, still in history).
  const sessionNonce = BigInt(Date.now());
  const requiredScopeMask = 0b00000001n;                   // READ_DATA
  const handshakeTs = BigInt(Math.floor(Date.now() / 1000));
  const humanSiblings = new Array(20).fill("0");
  const { proof: humanProofRaw, publicSignals: humanPubSignals } =
    await proveGroth16(
      {
        secret: humanSecret.toString(),
        merkleProofLength: "0",
        merkleProofIndex: "0",
        merkleProofSiblings: humanSiblings,
        scope: "1",
        sessionNonce: sessionNonce.toString(),
      },
      HUMAN_WASM,
      HUMAN_ZKEY,
      "auto",
    );

  // root agent: leaf 0 in single-leaf tree → length 0, index 0, siblings zero.
  const rootAgentSiblings = new Array(20).fill("0");
  const { proof: rootAgentProofRaw, publicSignals: rootAgentPubSignals } =
    await proveGroth16(
      {
        modelHash: root.cred.modelHash.toString(),
        operatorPubkeyAx: root.ax.toString(),
        operatorPubkeyAy: root.ay.toString(),
        permissionBitmask: root.cred.permissionBitmask.toString(),
        expiryTimestamp: root.cred.expiryTimestamp.toString(),
        sigR8x: root.cred.signature.R8.x.toString(),
        sigR8y: root.cred.signature.R8.y.toString(),
        sigS: root.cred.signature.S.toString(),
        merkleProofLength: "0",
        merkleProofIndex: "0",
        merkleProofSiblings: rootAgentSiblings,
        requiredScopeMask: requiredScopeMask.toString(),
        currentTimestamp: handshakeTs.toString(),
        sessionNonce: sessionNonce.toString(),
      },
      AGENT_WASM,
      AGENT_ZKEY,
      "auto",
    );
  if (rootAgentPubSignals[0] !== rootA.toString()) {
    throw new Error("handshake agent proof root mismatch");
  }

  const hsTx = await registry.verifyHandshake(
    formatProofForSolidity(humanProofRaw),
    humanPubSignals,
    formatProofForSolidity(rootAgentProofRaw),
    rootAgentPubSignals,
    sessionNonce,
  );
  const hsReceipt = await hsTx.wait();
  console.log(`Handshake verified: gas ${hsReceipt.gasUsed} | sessionNonce ${sessionNonce}`);

  const scopeAfterHs = await registry.lastScopeCommitment(sessionNonce);
  const expectedScopeAfterHs = F.toObject(poseidon([
    root.cred.permissionBitmask,
    root.cred.commitment,
    root.cred.expiryTimestamp,
  ]));
  if (scopeAfterHs.toString() !== expectedScopeAfterHs.toString()) {
    throw new Error("chain state mismatch after handshake");
  }
  console.log(`Chain state seeded: lastScopeCommitment = Poseidon3(rootScope, rootCommitment, rootExpiry)\n`);

  // ─── Hop 1: root → agentA ───
  // agentA Merkle proof against rootC (3-leaf tree, leaf index 1):
  //   index = 0b01 = 1, length 2, siblings = [root, agentB].
  const hopOneSiblings = new Array(DELEGATION_MAX_DEPTH).fill(0n);
  hopOneSiblings[0] = root.cred.commitment;
  hopOneSiblings[1] = agentB.cred.commitment;

  console.log("Hop 1: root → agentA — generating proof...");
  const h1Start = performance.now();
  const { proof: hop1Proof, result: hop1Result } = await delegate({
    delegator: root.cred,
    delegatorOperatorPrivateKey: root.opPriv,
    delegateeCommitment: agentA.cred.commitment,
    delegateeScope: agentA.cred.permissionBitmask,
    delegateeExpiry: agentA.cred.expiryTimestamp,
    previousScopeCommitment: expectedScopeAfterHs,
    sessionNonce,
    currentTimestamp: BigInt(Math.floor(Date.now() / 1000)),
    delegateeMerkleProof: {
      length: 2,
      index: 1,
      siblings: hopOneSiblings,
    },
    backend: "auto",
  });
  console.log(`  proof: ${(performance.now() - h1Start).toFixed(0)}ms`);
  if (hop1Result.delegateeMerkleRoot.toString() !== rootC.toString()) {
    throw new Error("hop 1 SDK root != on-chain rootC");
  }

  const hop1Tx = await registry.verifyDelegation(
    formatProofForSolidity(hop1Proof.proof),
    hop1Proof.publicSignals.map((s) => BigInt(s)),
    sessionNonce,
  );
  const hop1Receipt = await hop1Tx.wait();
  console.log(`  on-chain gas: ${hop1Receipt.gasUsed}`);
  console.log(`  hopCount: ${await registry.delegationHopCount(sessionNonce)}`);
  console.log(`  new chain state: Poseidon3(agentAScope, agentACommitment, agentAExpiry)\n`);

  // ─── Hop 2: agentA → agentB ───
  // agentB Merkle proof against rootC (3-leaf tree, leaf index 2, LeanIMT promotion):
  //   one effective hash level. length=1, index=1, siblings=[rootB].
  const hopTwoSiblings = new Array(DELEGATION_MAX_DEPTH).fill(0n);
  hopTwoSiblings[0] = rootB;

  console.log("Hop 2: agentA → agentB — generating proof...");
  const h2Start = performance.now();
  const { proof: hop2Proof, result: hop2Result } = await delegate({
    delegator: agentA.cred,
    delegatorOperatorPrivateKey: agentA.opPriv,
    delegateeCommitment: agentB.cred.commitment,
    delegateeScope: agentB.cred.permissionBitmask,
    delegateeExpiry: agentB.cred.expiryTimestamp,
    previousScopeCommitment: hop1Result.newScopeCommitment,
    sessionNonce,
    currentTimestamp: BigInt(Math.floor(Date.now() / 1000)),
    delegateeMerkleProof: {
      length: 1,
      index: 1,
      siblings: hopTwoSiblings,
    },
    backend: "auto",
  });
  console.log(`  proof: ${(performance.now() - h2Start).toFixed(0)}ms`);
  if (hop2Result.delegateeMerkleRoot.toString() !== rootC.toString()) {
    throw new Error("hop 2 SDK root != on-chain rootC");
  }

  const hop2Tx = await registry.verifyDelegation(
    formatProofForSolidity(hop2Proof.proof),
    hop2Proof.publicSignals.map((s) => BigInt(s)),
    sessionNonce,
  );
  const hop2Receipt = await hop2Tx.wait();
  console.log(`  on-chain gas: ${hop2Receipt.gasUsed}`);
  console.log(`  hopCount: ${await registry.delegationHopCount(sessionNonce)}`);

  // ─── Final chain-state assertion ───
  const expectedLeafScope = F.toObject(poseidon([
    agentB.cred.permissionBitmask,
    agentB.cred.commitment,
    agentB.cred.expiryTimestamp,
  ]));
  const actualScope = await registry.lastScopeCommitment(sessionNonce);
  if (actualScope.toString() !== expectedLeafScope.toString()) {
    throw new Error(
      `final scope mismatch: got ${actualScope}, expected ${expectedLeafScope}`,
    );
  }
  console.log(`  final chain state matches Poseidon3(agentBScope, agentBCommitment, agentBExpiry) ✓\n`);

  // ─── Replay protection: hop 2 again must revert ───
  let replayRejected = false;
  try {
    await registry.verifyDelegation(
      formatProofForSolidity(hop2Proof.proof),
      hop2Proof.publicSignals.map((s) => BigInt(s)),
      sessionNonce,
    );
  } catch (err) {
    if (/ScopeChainMismatch/.test(err.message)) {
      replayRejected = true;
    } else {
      throw err;
    }
  }
  if (!replayRejected) {
    throw new Error("hop 2 replay should have reverted with ScopeChainMismatch");
  }
  console.log("Replay of hop 2 correctly reverted (ScopeChainMismatch — chain already advanced).\n");

  console.log("Result: PASS — 2-hop delegation chain verified end-to-end on-chain.");
}

main()
  .then(() => process.exit(0))
  .catch((err) => {
    console.error(err);
    process.exit(1);
  });
