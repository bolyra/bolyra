#!/usr/bin/env node
/**
 * Reference host-under-test for the External Verifier Contract v1
 * host-conformance suite (spec/external-verifier-contract-v1.md §16).
 *
 * It implements the Host-Under-Test (HUT) convention the conformance runner
 * drives (§16.2): read the §2.1 request on stdin, spawn the configured verifier,
 * enforce the §7.2 fail-closed obligations (timeout, output bound, exit/signal,
 * single-object parse, verdict schema) and the §7.3 reserve-before-act rule,
 * then emit exactly one decision object on stdout and exit 0.
 *
 * This is a REFERENCE implementation whose purpose is to SELF-TEST the suite: a
 * real host lives in the host's own codebase and language. It is intentionally
 * dependency-free (no ajv) — the §3.4 verdict schema is checked with a small
 * inline validator covering the fields the fixtures exercise.
 *
 * Decision object (single JSON on stdout, exit 0):
 *   { "decision": "allow" }                              verifier allowed (and, in
 *                                                        host nonce mode, every
 *                                                        nonce reserved as novel)
 *   { "decision": "deny", "code": "<registry code>" }    a schema-valid verifier
 *                                                        deny, relayed unchanged
 *   { "decision": "deny", "failure_class": "<class>" }   host fail-closed override
 *                                                        (§7.2) or replay (§7.3)
 */
'use strict';
const fs = require('fs');
const { spawn } = require('child_process');

const KNOWN_CODES = new Set([
  'malformed_input', 'unsupported_version', 'invalid_bundle', 'invalid_proof',
  'untrusted_root', 'delegation_invalid', 'invalid_signature', 'request_mismatch',
  'model_mismatch', 'unknown_capability', 'scope_exceeded', 'expired',
  'nonce_missing', 'nonce_replayed', 'internal_error',
]);
const KINDS = new Set(['classical', 'zk', 'external']);

// --- HUT configuration (§16.2) ---
let verifierCmd;
try { verifierCmd = JSON.parse(process.env.HUT_VERIFIER_CMD || '[]'); } catch (e) { verifierCmd = []; }
const timeoutMs = Number(process.env.HUT_TIMEOUT_MS || 10000);
const maxBytes = Number(process.env.HUT_MAX_STDOUT_BYTES || 1048576);
const nonceMode = process.env.HUT_NONCE_MODE || 'local';
const nonceStore = process.env.HUT_NONCE_STORE || null;
// Reserve-before-act observability (§16.5): the host appends a marker here at the
// moment it authorizes the action — i.e. AFTER every §7.3 reservation succeeds and
// immediately before returning `allow`. It MUST NOT write on any deny.
const actionLog = process.env.HUT_ACTION_LOG || null;

function emit(decision) {
  process.stdout.write(JSON.stringify(decision), () => process.exit(0));
}

if (!Array.isArray(verifierCmd) || verifierCmd.length === 0) {
  emit({ decision: 'deny', failure_class: 'spawn_error' });
} else {
  const reqChunks = [];
  process.stdin.on('data', c => reqChunks.push(c));
  process.stdin.on('end', () => run(Buffer.concat(reqChunks)));
}

function run(request) {
  const child = spawn(verifierCmd[0], verifierCmd.slice(1), { stdio: ['pipe', 'pipe', 'inherit'] });

  let out = Buffer.alloc(0);
  let overflow = false;
  let timedOut = false;
  let settled = false;

  const timer = setTimeout(() => { timedOut = true; child.kill('SIGKILL'); }, timeoutMs);

  function finish(decision) {
    if (settled) return;
    settled = true;
    clearTimeout(timer);
    emit(decision);
  }

  child.stdout.on('data', chunk => {
    out = Buffer.concat([out, chunk]);
    if (out.length > maxBytes) { overflow = true; child.kill('SIGKILL'); }
  });

  child.on('error', () => finish({ decision: 'deny', failure_class: 'spawn_error' }));

  child.on('close', (code, signal) => {
    // §7.2 fail-closed precedence: our own kills (overflow, timeout) first, then
    // an unsolicited signal death, then a non-zero exit, then parse the stdout.
    if (overflow) return finish({ decision: 'deny', failure_class: 'oversize_stdout' });
    if (timedOut) return finish({ decision: 'deny', failure_class: 'timeout' });
    if (signal) return finish({ decision: 'deny', failure_class: 'signal_death' });
    if (code !== 0) return finish({ decision: 'deny', failure_class: 'nonzero_exit' });
    return decide(out.toString('utf8'), finish);
  });

  // Feed the request and close stdin (§2). Swallow EPIPE from a verifier that
  // never reads stdin.
  child.stdin.on('error', () => {});
  child.stdin.end(request);
}

function decide(stdoutStr, finish) {
  const parsed = strictParseSingleObject(stdoutStr);
  if (parsed.error) return finish({ decision: 'deny', failure_class: parsed.error });
  const v = parsed.value;

  // Full §3.4 closed verdict schema (§7.2 requires fail-closed on ANY schema
  // failure, including a disallowed additional property or a malformed
  // consume_nonces entry).
  if (!validVerdict(v)) {
    return finish({ decision: 'deny', failure_class: 'schema_invalid' });
  }
  if (v.verdict === 'deny') {
    return finish({ decision: 'deny', code: v.code }); // relay the verifier deny
  }
  // allow
  if (nonceMode === 'host' && Array.isArray(v.consume_nonces)) {
    if (!reserveAll(v.consume_nonces)) {
      return finish({ decision: 'deny', failure_class: 'replay' });
    }
  }
  recordAction(); // reserve-before-act: authorize only after reservations succeed
  return finish({ decision: 'allow' });
}

/**
 * The §3.4 closed verdict schema, as an inline validator (the reference host is
 * dependency-free by design). Kept in lockstep with
 * spec/external-verifier-contract-v1.md §3.4: allow → { verdict, kind?,
 * consume_nonces? }; deny → { verdict, kind?, code, message, detail? }. Both
 * objects are CLOSED (no additional properties); consume_nonces (when present) is
 * a non-empty array of { issuer_key, nonce, retain_until } with no extra keys.
 */
function validVerdict(v) {
  if (v === null || typeof v !== 'object' || Array.isArray(v)) return false;
  if (v.kind !== undefined && !KINDS.has(v.kind)) return false;

  if (v.verdict === 'allow') {
    for (const k of Object.keys(v)) {
      if (k !== 'verdict' && k !== 'kind' && k !== 'consume_nonces') return false;
    }
    if (v.consume_nonces !== undefined) {
      if (!Array.isArray(v.consume_nonces) || v.consume_nonces.length < 1) return false;
      for (const e of v.consume_nonces) {
        if (e === null || typeof e !== 'object' || Array.isArray(e)) return false;
        const ks = Object.keys(e);
        if (ks.length !== 3) return false;
        if (typeof e.issuer_key !== 'string' || typeof e.nonce !== 'string') return false;
        if (!Number.isInteger(e.retain_until)) return false;
      }
    }
    return true;
  }

  if (v.verdict === 'deny') {
    for (const k of Object.keys(v)) {
      if (k !== 'verdict' && k !== 'kind' && k !== 'code' && k !== 'message' && k !== 'detail') return false;
    }
    if (typeof v.code !== 'string' || !KNOWN_CODES.has(v.code)) return false;
    if (typeof v.message !== 'string') return false;
    if (v.detail !== undefined && (v.detail === null || typeof v.detail !== 'object' || Array.isArray(v.detail))) return false;
    return true;
  }

  return false; // verdict is neither "allow" nor "deny" (or absent)
}

// Append the "action authorized" marker (§16.5). Called ONLY on allow, after all
// reservations succeed.
function recordAction() {
  if (actionLog) {
    try { fs.appendFileSync(actionLog, 'acted\n'); } catch (e) { /* best effort */ }
  }
}

/**
 * Reserve-before-act (§7.3). Consult the durable store, then durably record the
 * novel nonces BEFORE returning success. Returns false (→ replay) if ANY entry
 * was already present.
 */
function reserveAll(entries) {
  if (!nonceStore) return false; // host nonce mode requires a store — fail closed
  const existing = new Set();
  try {
    for (const line of fs.readFileSync(nonceStore, 'utf8').split('\n')) {
      if (line.trim()) existing.add(line.trim());
    }
  } catch (e) { /* missing store == empty */ }

  let conflict = false;
  const toAdd = [];
  for (const e of entries) {
    if (!e || typeof e.nonce !== 'string') return false;
    if (existing.has(e.nonce)) conflict = true;
    else toAdd.push(e.nonce);
  }
  if (toAdd.length) {
    for (const n of toAdd) existing.add(n);
    fs.writeFileSync(nonceStore, Array.from(existing).join('\n') + '\n');
  }
  return !conflict;
}

/**
 * Strict single-object parse (§5.2). Returns { value } for exactly one JSON
 * object with no trailing bytes, else { error } where error is 'multiple_objects'
 * (a concatenated JSON stream) or 'unparseable_stdout' (empty / non-JSON /
 * trailing garbage).
 */
function strictParseSingleObject(str) {
  const s = str.trim();
  if (s === '') return { error: 'unparseable_stdout' };
  const end = firstValueEnd(s);
  if (end < 0) return { error: 'unparseable_stdout' };
  let first;
  try { first = JSON.parse(s.slice(0, end)); } catch (e) { return { error: 'unparseable_stdout' }; }
  const rest = s.slice(end).trim();
  if (rest === '') return { value: first };
  // Trailing content: a second JSON value → multi-object stream; else garbage.
  if (rest[0] === '{' || rest[0] === '[') return { error: 'multiple_objects' };
  return { error: 'unparseable_stdout' };
}

// End index of the first balanced top-level JSON object/array, honoring string
// escapes. Returns -1 for a non-object/array start or an unbalanced value.
function firstValueEnd(s) {
  if (s[0] !== '{' && s[0] !== '[') return -1;
  let depth = 0, inStr = false, esc = false;
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (inStr) {
      if (esc) esc = false;
      else if (ch === '\\') esc = true;
      else if (ch === '"') inStr = false;
      continue;
    }
    if (ch === '"') { inStr = true; continue; }
    if (ch === '{' || ch === '[') depth++;
    else if (ch === '}' || ch === ']') { depth--; if (depth === 0) return i + 1; }
  }
  return -1;
}
