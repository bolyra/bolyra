#!/usr/bin/env node
/**
 * validate_vectors.js — Conformance runner for Bolyra test vectors.
 *
 * For each vector file in spec/test-vectors/:
 *   - Reads the JSON vector
 *   - For expected_result='pass': runs witness generation, asserts public_signals match
 *   - For expected_result='fail': asserts witness generation throws OR verifier rejects
 *
 * Usage:
 *   node spec/test-vectors/scripts/validate_vectors.js
 *
 * Exit code 0 = all vectors pass. Non-zero = at least one failure.
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

const REPO_ROOT = path.resolve(__dirname, '..', '..', '..');
const BUILD_DIR = path.join(REPO_ROOT, 'circuits', 'build');
const VECTORS_DIR = path.resolve(__dirname, '..');

// Vectors where failure is enforced at the verifier layer (not circuit constraints)
const VERIFIER_LAYER_VECTORS = new Set([
  'revoked_human_identity',
  'nonce_replay',
]);

// SDK-only vectors (no circuit execution)
const SDK_VECTORS = new Set([
  'cumulative_bit_violation',
]);

let passed = 0;
let failed = 0;
let skipped = 0;

async function computeWitness(circuitName, inputs) {
  const wasmPath = path.join(BUILD_DIR, `${circuitName}_js`, `${circuitName}.wasm`);
  if (!fs.existsSync(wasmPath)) {
    throw new Error(`WASM not found: ${wasmPath}`);
  }
  const wtns = { type: 'mem' };
  await snarkjs.wtns.calculate(inputs, wasmPath, wtns);
  return wtns;
}

function getNumPublic(circuitName) {
  switch (circuitName) {
    case 'HumanUniqueness': return 3;
    case 'AgentPolicy':     return 4;
    case 'Delegation':      return 3;
    default: return 0;
  }
}

function extractPublicFromWitness(witness, circuitName) {
  const nPub = getNumPublic(circuitName);
  const signals = [];
  for (let i = 1; i <= nPub; i++) {
    signals.push(witness[i].toString());
  }
  return signals;
}

/**
 * Validate cumulative bit encoding (SDK-level check).
 */
function validateCumulativeBitEncoding(bitmask) {
  if (bitmask < 0 || bitmask > 255) return false;
  if ((bitmask & 0b00001000) && !(bitmask & 0b00000100)) return false;
  if ((bitmask & 0b00010000) && !(bitmask & 0b00001000)) return false;
  if ((bitmask & 0b00010000) && !(bitmask & 0b00000100)) return false;
  return true;
}

async function validateSingleStep(step, vectorId) {
  const { circuit, input_witnesses, public_signals, expected_result } = step;

  if (circuit === 'SDK') {
    // SDK validation
    const fn = input_witnesses.function;
    if (fn === 'validateCumulativeBitEncoding') {
      const result = validateCumulativeBitEncoding(input_witnesses.bitmask);
      if (expected_result === 'fail' && result === false) return true;
      if (expected_result === 'pass' && result === true) return true;
      return false;
    }
    console.warn(`    Unknown SDK function: ${fn}`);
    return false;
  }

  // Circuit validation
  try {
    const wtns = await computeWitness(circuit, input_witnesses);

    if (expected_result === 'fail') {
      // Witness generation succeeded but we expected failure
      console.error(`    Expected witness generation to fail but it succeeded`);
      return false;
    }

    // Check public signals match (skip FROZEN_BY_EXTRACT placeholders)
    if (public_signals.length > 0 && !public_signals.includes('FROZEN_BY_EXTRACT')) {
      const nPub = getNumPublic(circuit);
      const actual = [];
      for (let i = 1; i <= nPub; i++) {
        const val = typeof wtns.data === 'function' ? wtns.data(i) : wtns.data[i];
        actual.push(val.toString());
      }

      for (let i = 0; i < public_signals.length; i++) {
        if (actual[i] !== public_signals[i]) {
          console.error(`    Public signal mismatch at index ${i}: expected ${public_signals[i]}, got ${actual[i]}`);
          return false;
        }
      }
    }

    return true;
  } catch (err) {
    if (expected_result === 'fail') {
      // Expected failure — witness generation threw
      return true;
    }
    console.error(`    Unexpected error: ${err.message}`);
    return false;
  }
}

async function validateVector(filePath) {
  const vectorData = JSON.parse(fs.readFileSync(filePath, 'utf-8'));
  const vectorId = vectorData.id;
  const basename = path.basename(filePath);

  process.stdout.write(`  ${basename} (${vectorId}): `);

  // Skip verifier-layer vectors (they pass at circuit level but fail at verifier)
  if (VERIFIER_LAYER_VECTORS.has(vectorId)) {
    if (vectorData.expected_result === 'fail') {
      console.log('SKIP (verifier-layer check — not testable via witness generation)');
      skipped++;
      return;
    }
  }

  // SDK-only vectors
  if (SDK_VECTORS.has(vectorId)) {
    const ok = await validateSingleStep(vectorData, vectorId);
    if (ok) {
      console.log('PASS');
      passed++;
    } else {
      console.log('FAIL');
      failed++;
    }
    return;
  }

  // Multi-step vectors
  if (vectorData.steps) {
    let allPassed = true;
    for (let i = 0; i < vectorData.steps.length; i++) {
      const stepOk = await validateSingleStep(vectorData.steps[i], vectorId);
      if (!stepOk) {
        console.log(`FAIL (step ${i + 1})`);
        allPassed = false;
        break;
      }
    }
    if (allPassed) {
      console.log('PASS');
      passed++;
    } else {
      failed++;
    }
    return;
  }

  // Single-step vectors
  const ok = await validateSingleStep(vectorData, vectorId);
  if (ok) {
    console.log('PASS');
    passed++;
  } else {
    console.log('FAIL');
    failed++;
  }
}

async function main() {
  console.log('Bolyra Conformance Test Vector Validation (L2: witness-match)');
  console.log('');

  const vectorFiles = fs.readdirSync(VECTORS_DIR)
    .filter((f) => f.endsWith('.json') && f !== 'schema.json')
    .sort();

  if (vectorFiles.length === 0) {
    console.error('No vector files found in', VECTORS_DIR);
    process.exit(1);
  }

  console.log(`Found ${vectorFiles.length} vector files:\n`);

  for (const file of vectorFiles) {
    await validateVector(path.join(VECTORS_DIR, file));
  }

  console.log('');
  console.log(`Results: ${passed} passed, ${failed} failed, ${skipped} skipped`);

  if (failed > 0) {
    process.exit(1);
  }
}

main().catch((err) => {
  console.error('Fatal error:', err);
  process.exit(1);
});
