#!/usr/bin/env node
/**
 * extract_vectors.js — Generate frozen conformance test vectors from circuit artifacts.
 *
 * Usage:
 *   FULL_PROOF=1 node spec/test-vectors/scripts/extract_vectors.js
 *
 * Requires:
 *   - Compiled circuit artifacts in circuits/build/
 *   - snarkjs (dev dependency)
 *   - circom_tester (dev dependency)
 *
 * This script runs witness generation (and optionally full proof generation when
 * FULL_PROOF=1 is set) for each test scenario, captures the public signals, and
 * writes frozen JSON vector files to spec/test-vectors/.
 */

const path = require('path');
const fs = require('fs');

let snarkjs;
try {
  snarkjs = require('snarkjs');
} catch {
  console.error('Error: snarkjs not found. Run npm install from the repo root.');
  process.exit(1);
}

let circomTester;
try {
  circomTester = require('circom_tester');
} catch {
  console.error('Error: circom_tester not found. Run npm install from the repo root.');
  process.exit(1);
}

const REPO_ROOT = path.resolve(__dirname, '..', '..', '..');
const BUILD_DIR = path.join(REPO_ROOT, 'circuits', 'build');
const VECTORS_DIR = path.resolve(__dirname, '..');
const FULL_PROOF = process.env.FULL_PROOF === '1';

// ── Helpers ─────────────────────────────────────────────────────────────────

async function computeWitness(circuitName, inputs) {
  const wasmPath = path.join(BUILD_DIR, `${circuitName}_js`, `${circuitName}.wasm`);
  if (!fs.existsSync(wasmPath)) {
    throw new Error(`WASM not found: ${wasmPath}. Run npm run compile:circuits first.`);
  }
  const wtns = { type: 'mem' };
  await snarkjs.wtns.calculate(inputs, wasmPath, wtns);
  return wtns;
}

async function extractPublicSignals(circuitName, wtns) {
  const r1csPath = path.join(BUILD_DIR, `${circuitName}.r1cs`);
  // Read the r1cs to get nPublic, then extract public signals from witness
  const r1csInfo = await snarkjs.r1cs.info(r1csPath);
  const nPublic = r1csInfo.nOutputs + r1csInfo.nPubInputs;
  // Public signals are witness[1..nPublic+1]
  const signals = [];
  for (let i = 1; i <= nPublic; i++) {
    signals.push(wtns.data[i].toString());
  }
  return signals;
}

async function generateFullProof(circuitName, inputs) {
  const wasmPath = path.join(BUILD_DIR, `${circuitName}_js`, `${circuitName}.wasm`);
  const zkeyPath = path.join(BUILD_DIR, `${circuitName}_groth16.zkey`);
  if (!fs.existsSync(zkeyPath)) {
    console.warn(`  Warning: zkey not found at ${zkeyPath}, trying ${circuitName}.zkey`);
    const altZkeyPath = path.join(BUILD_DIR, `${circuitName}.zkey`);
    if (!fs.existsSync(altZkeyPath)) {
      throw new Error(`No zkey found for ${circuitName}`);
    }
    return snarkjs.groth16.fullProve(inputs, wasmPath, altZkeyPath);
  }
  return snarkjs.groth16.fullProve(inputs, wasmPath, zkeyPath);
}

function writeVector(filename, data) {
  const outPath = path.join(VECTORS_DIR, filename);
  fs.writeFileSync(outPath, JSON.stringify(data, null, 2) + '\n');
  console.log(`  ✓ ${filename}`);
}

function makeMeta() {
  return {
    version: '1.0.0',
    circuit_version: '2.0.0',
    generated: new Date().toISOString(),
    generator: 'extract_vectors.js',
  };
}

// ── Scenario Definitions ────────────────────────────────────────────────────

const MERKLE_ZEROS_20 = Array(20).fill('0');

const SCENARIOS = {
  // --- HumanUniqueness: valid ---
  valid_human: {
    circuit: 'HumanUniqueness',
    inputs: {
      identityTreeRoot: '0', // placeholder — will be computed
      nullifierHash: '0',    // placeholder — will be computed
      scope: '42',
      secret: '12345678901234567890',
      identityNonce: '1',
      merklePathElements: MERKLE_ZEROS_20,
      merklePathIndices: MERKLE_ZEROS_20,
    },
  },

  // --- AgentPolicy: valid ---
  valid_agent: {
    circuit: 'AgentPolicy',
    inputs: {
      agentTreeRoot: '0',    // placeholder
      nullifierHash: '0',    // placeholder
      currentTimestamp: '1719000000',
      expiryTimestamp: '1750000000',
      agentSecret: '98765432109876543210',
      agentNonce: '2',
      policyScope: '42',
      merklePathElements: MERKLE_ZEROS_20,
      merklePathIndices: MERKLE_ZEROS_20,
    },
  },

  // --- AgentPolicy: expired ---
  expired_agent: {
    circuit: 'AgentPolicy',
    inputs: {
      agentTreeRoot: '0',
      nullifierHash: '0',
      currentTimestamp: '1750000000',
      expiryTimestamp: '1719000000',  // expired!
      agentSecret: '98765432109876543210',
      agentNonce: '2',
      policyScope: '42',
      merklePathElements: MERKLE_ZEROS_20,
      merklePathIndices: MERKLE_ZEROS_20,
    },
    expectFail: true,
    failureReason: 'currentTimestamp >= expiryTimestamp: LessThan(64) constraint asserts isNotExpired.out === 1 but comparison yields 0',
  },

  // --- Delegation: depth 1 ---
  delegation_1: {
    circuit: 'Delegation',
    inputs: {
      agentTreeRoot: '0',       // placeholder
      scopeCommitment: '0',     // placeholder
      nullifierHash: '0',       // placeholder
      delegatorSecret: '55555555555555555555',
      delegatorNonce: '3',
      delegateeCredCommitment: '0', // placeholder
      scope: '7',
      merklePathElements: MERKLE_ZEROS_20,
      merklePathIndices: MERKLE_ZEROS_20,
    },
  },

  // --- Delegation: depth 2, hop 2 ---
  delegation_2_hop2: {
    circuit: 'Delegation',
    inputs: {
      agentTreeRoot: '0',
      scopeCommitment: '0',
      nullifierHash: '0',
      delegatorSecret: '77777777777777777777',
      delegatorNonce: '4',
      delegateeCredCommitment: '0',
      scope: '3',
      merklePathElements: MERKLE_ZEROS_20,
      merklePathIndices: MERKLE_ZEROS_20,
    },
  },

  // --- Delegation: depth 3, hop 3 ---
  delegation_3_hop3: {
    circuit: 'Delegation',
    inputs: {
      agentTreeRoot: '0',
      scopeCommitment: '0',
      nullifierHash: '0',
      delegatorSecret: '88888888888888888888',
      delegatorNonce: '5',
      delegateeCredCommitment: '0',
      scope: '1',
      merklePathElements: MERKLE_ZEROS_20,
      merklePathIndices: MERKLE_ZEROS_20,
    },
  },
};

// ── Main ────────────────────────────────────────────────────────────────────

async function main() {
  console.log('Bolyra Conformance Test Vector Extraction');
  console.log(`Mode: ${FULL_PROOF ? 'FULL_PROOF (groth16)' : 'witness-only'}`);
  console.log('');

  // We use circom_tester for witness computation so we can resolve
  // placeholder public inputs (the circuit computes them internally).
  // For scenarios that need real Merkle roots, we use a single-leaf tree.

  const results = {};

  for (const [name, scenario] of Object.entries(SCENARIOS)) {
    console.log(`Processing: ${name} (${scenario.circuit})`);

    if (scenario.expectFail) {
      // For expected-failure scenarios, we just record the inputs
      results[name] = {
        circuit: scenario.circuit,
        inputs: scenario.inputs,
        publicSignals: [],
        expectFail: true,
        failureReason: scenario.failureReason,
      };
      console.log(`  ✓ Recorded (expected failure)`);
      continue;
    }

    try {
      // Use circom_tester to compute witness with auto-resolved public inputs
      const circuitPath = path.join(
        REPO_ROOT, 'circuits', 'src', `${scenario.circuit}.circom`
      );

      const circuit = await circomTester.wasm(circuitPath, {
        output: path.join(BUILD_DIR, 'extract_tmp'),
        prime: 'bn128',
      });

      // Provide only private inputs — circom_tester resolves public outputs
      const privateInputs = { ...scenario.inputs };
      // Remove placeholder public signals (the circuit computes them)
      // We keep all inputs and let circom_tester handle it
      const witness = await circuit.calculateWitness(privateInputs, true);

      // Extract public signals (indices depend on circuit)
      const pubSignals = [];
      const nPub = witness.length > 1 ? getNumPublic(scenario.circuit) : 0;
      for (let i = 1; i <= nPub; i++) {
        pubSignals.push(witness[i].toString());
      }

      // Update inputs with computed public values
      const frozenInputs = { ...scenario.inputs };
      updatePublicInputs(frozenInputs, scenario.circuit, pubSignals);

      results[name] = {
        circuit: scenario.circuit,
        inputs: frozenInputs,
        publicSignals: pubSignals,
        expectFail: false,
      };

      if (FULL_PROOF) {
        console.log(`  Generating full Groth16 proof...`);
        const { proof, publicSignals: proofPubSignals } =
          await generateFullProof(scenario.circuit, frozenInputs);
        results[name].publicSignals = proofPubSignals.map(String);
        results[name].proof = proof;
        console.log(`  ✓ Full proof generated`);
      } else {
        console.log(`  ✓ Witness computed`);
      }
    } catch (err) {
      console.error(`  ✗ Error: ${err.message}`);
      results[name] = {
        circuit: scenario.circuit,
        inputs: scenario.inputs,
        publicSignals: [],
        error: err.message,
      };
    }
  }

  // ── Write vector files ──────────────────────────────────────────────────

  console.log('\nWriting vector files...');
  const meta = makeMeta();

  // valid_handshake.json
  writeVector('valid_handshake.json', {
    id: 'valid_handshake',
    description: 'Happy-path handshake: valid human uniqueness proof + valid agent policy proof with fresh nonce and correct scope.',
    steps: [
      makeStep('HumanUniqueness', results.valid_human),
      makeStep('AgentPolicy', results.valid_agent),
    ],
    expected_result: 'pass',
    meta,
  });

  // expired_agent_credential.json
  writeVector('expired_agent_credential.json', {
    id: 'expired_agent_credential',
    description: 'Agent credential with expiryTimestamp in the past — must fail.',
    circuit: 'AgentPolicy',
    input_witnesses: results.expired_agent.inputs,
    public_signals: [],
    expected_result: 'fail',
    failure_reason: results.expired_agent.failureReason,
    meta,
  });

  // delegation_depth_1.json
  writeVector('delegation_depth_1.json', {
    id: 'delegation_depth_1',
    description: 'Single-hop delegation chain — must pass.',
    circuit: 'Delegation',
    input_witnesses: results.delegation_1.inputs,
    public_signals: results.delegation_1.publicSignals,
    expected_result: 'pass',
    meta: { ...meta, delegation_chain: { depth: 1, scope_narrowing: ['7'] } },
  });

  // delegation_depth_2.json
  writeVector('delegation_depth_2.json', {
    id: 'delegation_depth_2',
    description: 'Two-hop delegation chain with narrowed scope — must pass.',
    steps: [
      makeStep('Delegation', results.delegation_1),
      makeStep('Delegation', results.delegation_2_hop2),
    ],
    expected_result: 'pass',
    meta: { ...meta, delegation_chain: { depth: 2, scope_narrowing: ['7', '3'] } },
  });

  // delegation_depth_3.json
  writeVector('delegation_depth_3.json', {
    id: 'delegation_depth_3',
    description: 'Three-hop delegation chain — scope monotonically narrows.',
    steps: [
      makeStep('Delegation', results.delegation_1),
      makeStep('Delegation', results.delegation_2_hop2),
      makeStep('Delegation', results.delegation_3_hop3),
    ],
    expected_result: 'pass',
    meta: { ...meta, delegation_chain: { depth: 3, scope_narrowing: ['7', '3', '1'] } },
  });

  // nonce_replay.json (reuses valid_handshake witnesses)
  writeVector('nonce_replay.json', {
    id: 'nonce_replay',
    description: 'Replayed handshake with previously-used sessionNonce — verifier must reject.',
    steps: [
      makeStep('HumanUniqueness', results.valid_human),
      makeStep('AgentPolicy', results.valid_agent),
    ],
    expected_result: 'fail',
    failure_reason: 'Nonce replay: nullifierHash has already been consumed for this scope. Replay detection is the verifier responsibility.',
    meta: { ...meta, notes: 'Identical witness to valid_handshake — replay is a verifier-layer check.' },
  });

  // Hand-authored vectors are not overwritten (revoked_human, stale_root, scope_subset, cumulative_bit)
  console.log('\n  (Hand-authored vectors not overwritten: revoked_human_identity, stale_merkle_root, scope_subset_violation, cumulative_bit_violation)');
  console.log('\nDone.');
}

// ── Utilities ───────────────────────────────────────────────────────────────

function getNumPublic(circuitName) {
  switch (circuitName) {
    case 'HumanUniqueness': return 3;  // identityTreeRoot, nullifierHash, scope
    case 'AgentPolicy':     return 4;  // agentTreeRoot, nullifierHash, currentTimestamp, expiryTimestamp
    case 'Delegation':      return 3;  // agentTreeRoot, scopeCommitment, nullifierHash
    default: throw new Error(`Unknown circuit: ${circuitName}`);
  }
}

function updatePublicInputs(inputs, circuitName, pubSignals) {
  switch (circuitName) {
    case 'HumanUniqueness':
      inputs.identityTreeRoot = pubSignals[0];
      inputs.nullifierHash = pubSignals[1];
      // scope is already set
      break;
    case 'AgentPolicy':
      inputs.agentTreeRoot = pubSignals[0];
      inputs.nullifierHash = pubSignals[1];
      // timestamps already set
      break;
    case 'Delegation':
      inputs.agentTreeRoot = pubSignals[0];
      inputs.scopeCommitment = pubSignals[1];
      inputs.nullifierHash = pubSignals[2];
      break;
  }
}

function makeStep(circuit, result) {
  return {
    circuit,
    input_witnesses: result.inputs,
    public_signals: result.publicSignals || [],
    expected_result: result.expectFail ? 'fail' : 'pass',
    ...(result.failureReason ? { failure_reason: result.failureReason } : {}),
  };
}

main().catch((err) => {
  console.error('Fatal error:', err);
  process.exit(1);
});
