#!/usr/bin/env node

import * as fs from 'fs';
import * as process from 'process';
import { verifyReceipt, hashPayload } from './sign';
import type { SignedReceipt } from './types';

// --- Helpers ---

function usage(): string {
  return `Usage: bolyra-receipt-verify <receipt.json> [options]

Options:
  --stdin               Read receipt JSON from stdin instead of a file
  --signer <address>    Expected signer address (optional)
  --max-age <seconds>   Maximum receipt age in seconds (default: 86400)
  --help                Show this help`;
}

function fail(msg: string): never {
  process.stderr.write(msg + '\n');
  process.exit(2);
}

function truncate(hex: string): string {
  if (hex.length <= 14) return hex;
  return hex.slice(0, 8) + '...' + hex.slice(-4);
}

// --- Arg parsing ---

const args = process.argv.slice(2);

if (args.includes('--help') || args.includes('-h')) {
  console.log(usage());
  process.exit(0);
}

let filePath: string | undefined;
let expectedSigner: string | undefined;
let maxAgeSeconds = 86400;
let useStdin = false;

for (let i = 0; i < args.length; i++) {
  const arg = args[i];
  if (arg === '--stdin') {
    useStdin = true;
  } else if (arg === '--signer') {
    expectedSigner = args[++i];
    if (!expectedSigner) fail('--signer requires an address argument');
  } else if (arg === '--max-age') {
    const val = args[++i];
    if (!val) fail('--max-age requires a number argument');
    maxAgeSeconds = parseInt(val, 10);
    if (Number.isNaN(maxAgeSeconds) || maxAgeSeconds < 0) {
      fail('--max-age must be a non-negative integer');
    }
  } else if (arg.startsWith('-')) {
    fail(`Unknown option: ${arg}\n\n${usage()}`);
  } else {
    filePath = arg;
  }
}

if (!filePath && !useStdin) {
  fail(`No input specified. Provide a file path or use --stdin.\n\n${usage()}`);
}

// --- Read input ---

let rawJson: string;
try {
  if (useStdin) {
    rawJson = fs.readFileSync(0, 'utf-8');
  } else {
    rawJson = fs.readFileSync(filePath!, 'utf-8');
  }
} catch (err: unknown) {
  const msg = err instanceof Error ? err.message : String(err);
  fail(`Cannot read input: ${msg}`);
}

let receipt: SignedReceipt;
try {
  receipt = JSON.parse(rawJson);
} catch {
  fail('Invalid JSON');
}

// --- Checks ---

const checks: string[] = [];
let failed = false;

function pass(msg: string): void {
  checks.push(`\u2713 ${msg}`);
}

function failCheck(msg: string): void {
  checks.push(`\u2717 ${msg}`);
  failed = true;
}

// 1. Schema validation
function validateSchema(): boolean {
  const p = receipt.payload;
  const s = receipt.signature;
  const errors: string[] = [];

  if (!p) { errors.push('missing payload'); }
  if (!s) { errors.push('missing signature'); }
  if (errors.length) { failCheck(`Schema: ${errors.join(', ')}`); return false; }

  if (p.v !== 1) errors.push('payload.v !== 1');
  if (p.kind !== 'bolyra.auth' && p.kind !== 'bolyra.commerce') {
    errors.push('payload.kind must be "bolyra.auth" or "bolyra.commerce"');
  }
  if (typeof p.issuedAt !== 'number') errors.push('payload.issuedAt not a number');
  if (typeof p.issuer !== 'string' || !p.issuer) errors.push('payload.issuer missing');
  if (typeof p.keyId !== 'string' || !p.keyId) errors.push('payload.keyId missing');

  // subject
  if (!p.subject) {
    errors.push('payload.subject missing');
  } else {
    for (const k of ['rootDid', 'actingDid', 'credentialCommitment', 'effectiveCommitment'] as const) {
      if (typeof (p.subject as any)[k] !== 'string' || !(p.subject as any)[k]) {
        errors.push(`payload.subject.${k} missing or not a string`);
      }
    }
  }

  // decision
  if (!p.decision) {
    errors.push('payload.decision missing');
  } else {
    if (typeof p.decision.allowed !== 'boolean') errors.push('decision.allowed not boolean');
    if (typeof p.decision.score !== 'number') errors.push('decision.score not a number');
    if (typeof p.decision.permissionBitmask !== 'string' || !p.decision.permissionBitmask) errors.push('decision.permissionBitmask missing or not a string');
    if (typeof p.decision.chainDepth !== 'number') errors.push('decision.chainDepth not a number');
  }

  // proof
  if (!p.proof) {
    errors.push('payload.proof missing');
  } else {
    for (const k of ['bundleVersion', 'nonce', 'humanProofHash', 'agentProofHash', 'publicSignalsHash'] as const) {
      if (!(k in p.proof)) errors.push(`proof.${k} missing`);
    }
  }

  // commerce fields (required when kind === 'bolyra.commerce')
  if (p.kind === 'bolyra.commerce') {
    const c = (p as any).commerce;
    if (!c) {
      errors.push('commerce fields missing for bolyra.commerce receipt');
    } else {
      if (typeof c.rail !== 'string' || !c.rail) errors.push('commerce.rail missing or not a string');
      if (typeof c.amount !== 'number') errors.push('commerce.amount not a number');
      if (typeof c.currency !== 'string' || !c.currency) errors.push('commerce.currency missing or not a string');
      if (typeof c.merchant !== 'string') errors.push('commerce.merchant not a string');
      if (typeof c.intentHash !== 'string' || !/^[0-9a-fA-F]{64}$/.test(c.intentHash)) {
        errors.push('commerce.intentHash must be a 64-char hex string');
      }
    }
  }

  // signature fields
  if (s.alg !== 'ES256K') errors.push('signature.alg !== "ES256K"');
  if (s.keyId !== p.keyId) errors.push('signature.keyId does not match payload.keyId');
  if (!/^0x[0-9a-fA-F]{40}$/.test(s.signer ?? '')) errors.push('signature.signer invalid format');
  if (!/^0x[0-9a-fA-F]{64}$/.test(s.payloadHash ?? '')) errors.push('signature.payloadHash invalid format');
  if (!/^0x[0-9a-fA-F]{130}$/.test(s.value ?? '')) errors.push('signature.value invalid format');

  if (errors.length) {
    failCheck(`Schema: ${errors.join('; ')}`);
    return false;
  }
  pass('Schema valid');
  return true;
}

// 2. Timestamp check
function validateTimestamp(): void {
  const nowSec = Math.floor(Date.now() / 1000);
  const issuedAt = receipt.payload.issuedAt;
  const allowFutureSeconds = 300;
  const ageSec = nowSec - issuedAt;
  const isoStr = new Date(issuedAt * 1000).toISOString();

  if (issuedAt > nowSec + allowFutureSeconds) {
    failCheck(`Timestamp: ${isoStr} is ${issuedAt - nowSec}s in the future (max skew: ${allowFutureSeconds}s)`);
    return;
  }
  if (ageSec > maxAgeSeconds) {
    failCheck(`Timestamp: ${isoStr} (${ageSec}s ago, max-age: ${maxAgeSeconds}s)`);
    return;
  }
  pass(`Timestamp: ${isoStr} (${ageSec}s ago)`);
}

// 3. Hash check
function validateHash(): boolean {
  const computed = hashPayload(receipt.payload);
  if (computed !== receipt.signature.payloadHash) {
    failCheck(`Payload hash mismatch (expected ${truncate(receipt.signature.payloadHash)}, got ${truncate(computed)})`);
    return false;
  }
  pass('Payload hash matches');
  return true;
}

// 4. ID check
function validateId(): void {
  const expected = '0x' + receipt.signature.payloadHash.slice(2, 18);
  if (receipt.id !== expected) {
    failCheck(`Receipt ID mismatch (expected ${expected}, got ${receipt.id})`);
    return;
  }
  pass('Receipt ID matches');
}

// 5. Signature check
function validateSignature(): void {
  const ok = verifyReceipt(receipt, expectedSigner);
  if (!ok) {
    failCheck(`Signature invalid${expectedSigner ? ` (expected signer: ${truncate(expectedSigner)})` : ''}`);
    return;
  }
  pass(`Signature valid (signer: ${truncate(receipt.signature.signer)})`);
}

// --- Run checks ---

if (validateSchema()) {
  validateTimestamp();
  if (validateHash()) {
    validateId();
    validateSignature();
  }
}

// --- Output ---

for (const line of checks) {
  console.log(line);
}

if (failed) {
  console.log('FAIL \u2014 receipt is invalid');
  process.exit(1);
} else {
  console.log('PASS \u2014 receipt is valid');
  process.exit(0);
}
