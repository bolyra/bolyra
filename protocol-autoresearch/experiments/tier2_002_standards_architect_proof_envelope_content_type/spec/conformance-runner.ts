#!/usr/bin/env ts-node
/**
 * Bolyra Proof Envelope — Conformance Runner
 *
 * Validates test vectors from spec/test-vectors/proof-envelope-vectors.json
 * against the SDK's CBOR codec.
 *
 * Usage:
 *   npx ts-node spec/conformance-runner.ts
 */

import { readFileSync } from 'fs';
import { resolve } from 'path';
import { encode } from 'cbor-x';
import {
  encodeProofEnvelope,
  decodeProofEnvelope,
} from '../sdk/src/envelope.js';
import type { ProofEnvelope, ProofSystem } from '../sdk/src/types.js';

interface TestVector {
  id: string;
  description: string;
  expect: 'accept' | 'reject';
  expected_error?: string;
  envelope: {
    version: number;
    proof_system: string;
    circuit_id: string;
    public_signals: number[];
    proof_bytes_hex: string;
    timestamp: number;
    metadata?: Record<string, unknown>;
    [key: string]: unknown; // forward-compat fields
  };
}

interface VectorsFile {
  description: string;
  spec_version: number;
  vectors: TestVector[];
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function vectorToCborBytes(vector: TestVector): Uint8Array {
  const { envelope } = vector;
  const raw: Record<string, unknown> = {
    version: envelope.version,
    proof_system: envelope.proof_system,
    circuit_id: envelope.circuit_id,
    public_signals: envelope.public_signals,
    proof_bytes: hexToBytes(envelope.proof_bytes_hex),
    timestamp: envelope.timestamp,
  };
  if (envelope.metadata) {
    raw.metadata = envelope.metadata;
  }
  // Copy any unknown fields (forward-compat test)
  const knownKeys = new Set([
    'version', 'proof_system', 'circuit_id',
    'public_signals', 'proof_bytes_hex', 'timestamp', 'metadata',
  ]);
  for (const [k, v] of Object.entries(envelope)) {
    if (!knownKeys.has(k)) {
      raw[k] = v;
    }
  }
  return new Uint8Array(encode(raw));
}

async function runVectors(): Promise<void> {
  const vectorsPath = resolve(__dirname, 'test-vectors/proof-envelope-vectors.json');
  const file: VectorsFile = JSON.parse(readFileSync(vectorsPath, 'utf-8'));

  console.log(`\nBolyra Proof Envelope Conformance Runner`);
  console.log(`Spec version: ${file.spec_version}`);
  console.log(`Vectors: ${file.vectors.length}\n`);

  let passed = 0;
  let failed = 0;

  for (const vector of file.vectors) {
    const label = `[${vector.id}] ${vector.description}`;
    const cborBytes = vectorToCborBytes(vector);

    try {
      const decoded = decodeProofEnvelope(cborBytes);

      if (vector.expect === 'reject') {
        console.log(`  FAIL  ${label}`);
        console.log(`        Expected rejection but decoded successfully`);
        failed++;
        continue;
      }

      // Round-trip: encode the decoded envelope and compare
      const reEncoded = encodeProofEnvelope(decoded);
      const reDecoded = decodeProofEnvelope(reEncoded);

      // Verify structural equality
      if (reDecoded.version !== decoded.version ||
          reDecoded.proofSystem !== decoded.proofSystem ||
          reDecoded.circuitId !== decoded.circuitId ||
          reDecoded.timestamp !== decoded.timestamp ||
          reDecoded.publicSignals.length !== decoded.publicSignals.length) {
        console.log(`  FAIL  ${label}`);
        console.log(`        Round-trip mismatch`);
        failed++;
        continue;
      }

      console.log(`  PASS  ${label}`);
      passed++;
    } catch (err) {
      if (vector.expect === 'accept') {
        console.log(`  FAIL  ${label}`);
        console.log(`        Unexpected error: ${(err as Error).message}`);
        failed++;
      } else {
        // Expected rejection
        const msg = (err as Error).message;
        if (vector.expected_error && !msg.includes(vector.expected_error)) {
          console.log(`  FAIL  ${label}`);
          console.log(`        Wrong error: "${msg}" (expected to contain "${vector.expected_error}")`);
          failed++;
        } else {
          console.log(`  PASS  ${label} (correctly rejected: ${msg})`);
          passed++;
        }
      }
    }
  }

  console.log(`\nResults: ${passed} passed, ${failed} failed, ${file.vectors.length} total`);

  if (failed > 0) {
    process.exit(1);
  }
}

runVectors().catch((err) => {
  console.error('Conformance runner failed:', err);
  process.exit(1);
});
