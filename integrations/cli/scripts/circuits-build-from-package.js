#!/usr/bin/env node
/**
 * Materialize a `circuits/build`-shaped directory from an installed
 * `@bolyra/circuits`, so the CLI's real-proof tests can run without a Circom
 * toolchain (CI has no compiler and `circuits/build` is gitignored).
 *
 * Three naming conventions are in play and none of them agree:
 *
 *   1. `@bolyra/circuits` ships  artifacts/<Circuit>/<Circuit>_groth16.zkey
 *                               artifacts/<Circuit>/<Circuit>.wasm
 *                               artifacts/<Circuit>/<Circuit>_groth16_vkey.json
 *   2. The SDK's proveHandshake wants  <Circuit>_final.zkey
 *                                      <Circuit>_js/<Circuit>.wasm
 *   3. The CLI's vkey resolver wants   <Circuit>_groth16_vkey.json, except
 *                                      HumanUniqueness_vkey.json
 *
 * This script maps 1 onto 2 and 3. It is a test/CI harness, not a runtime
 * path: nothing in the shipped CLI depends on it.
 *
 * Usage: node scripts/circuits-build-from-package.js <outDir>
 */
'use strict';

const fs = require('node:fs');
const path = require('node:path');

const outDir = process.argv[2];
if (!outDir) {
  console.error('usage: circuits-build-from-package.js <outDir>');
  process.exit(2);
}

let artifactsDir;
try {
  const pkgRoot = path.dirname(require.resolve('@bolyra/circuits/package.json'));
  artifactsDir = path.join(pkgRoot, 'artifacts');
} catch {
  console.error('@bolyra/circuits is not installed; cannot materialize circuit artifacts.');
  process.exit(1);
}

// [source relative to artifacts/, destination relative to outDir]
const MAPPINGS = [
  ['AgentPolicy/AgentPolicy_groth16.zkey', 'AgentPolicy_final.zkey'],
  ['AgentPolicy/AgentPolicy.wasm', 'AgentPolicy_js/AgentPolicy.wasm'],
  ['AgentPolicy/AgentPolicy_groth16_vkey.json', 'AgentPolicy_groth16_vkey.json'],
  ['HumanUniqueness/HumanUniqueness_groth16.zkey', 'HumanUniqueness_final.zkey'],
  ['HumanUniqueness/HumanUniqueness.wasm', 'HumanUniqueness_js/HumanUniqueness.wasm'],
  // The CLI resolver expects the unsuffixed name for this circuit only.
  ['HumanUniqueness/HumanUniqueness_groth16_vkey.json', 'HumanUniqueness_vkey.json'],
  ['Delegation/Delegation_groth16.zkey', 'Delegation_final.zkey'],
  ['Delegation/Delegation.wasm', 'Delegation_js/Delegation.wasm'],
  ['Delegation/Delegation_groth16_vkey.json', 'Delegation_groth16_vkey.json'],
];

fs.mkdirSync(outDir, { recursive: true });

let copied = 0;
const missing = [];
for (const [from, to] of MAPPINGS) {
  const src = path.join(artifactsDir, from);
  if (!fs.existsSync(src)) {
    missing.push(from);
    continue;
  }
  const dest = path.join(outDir, to);
  fs.mkdirSync(path.dirname(dest), { recursive: true });
  fs.copyFileSync(src, dest);
  copied += 1;
}

if (missing.length > 0) {
  console.error(`missing from @bolyra/circuits: ${missing.join(', ')}`);
  process.exit(1);
}

console.log(`materialized ${copied} circuit artifacts into ${outDir}`);
