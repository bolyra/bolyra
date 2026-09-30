/**
 * Receipt verification for the playground: a thin, fail-closed wrapper around
 * the published `@bolyra/receipts` verifier.
 *
 * Rules (spec'd in the plan, enforced by test/unit/verify.test.js):
 * - Nothing is verified until the input parses cleanly and every option is
 *   well-formed. One bad line invalidates the whole paste. Empty is invalid.
 * - The envelope is validated before any cryptography runs; an unsupported
 *   envelope never reaches the signature check.
 * - Overall success is decided in ONE place (`decideOverall`) and requires
 *   every component to pass. Signature validity is still reported per row
 *   when instance binding fails.
 * - Checkpoints (expected count / head) and the expected signer come only
 *   from the options object. They are never read from the pasted text.
 * - Every library call is wrapped; an exception is a failure, never a pass.
 */
import { verifyReceipt, verifyReceiptChain, verifyInstanceBinding } from '@bolyra/receipts';

export const LIMITS = Object.freeze({ maxBytes: 2 * 1024 * 1024, maxLines: 2000, maxDepth: 32 });

const HEX = (n) => new RegExp(`^0x[0-9a-fA-F]{${n}}$`);
const RE_ADDRESS = HEX(40);
const RE_HASH = HEX(64);
const RE_SIGNATURE = HEX(130);
const RE_DECIMAL_INT = /^(0|[1-9]\d*)$/;
const KINDS = new Set(['bolyra.auth', 'bolyra.commerce']);
const encoder = new TextEncoder();

function isPlainObject(v) {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/** Maximum bracket nesting in a JSON text, ignoring brackets inside strings. */
function jsonDepth(text) {
  let depth = 0, max = 0, inString = false, escaped = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (inString) {
      if (escaped) escaped = false;
      else if (ch === '\\') escaped = true;
      else if (ch === '"') inString = false;
      continue;
    }
    if (ch === '"') inString = true;
    else if (ch === '{' || ch === '[') { depth++; if (depth > max) max = depth; }
    else if (ch === '}' || ch === ']') depth--;
  }
  return max;
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/**
 * Classify pasted text. `receipt`: exactly one JSON object. `chain`: one JSON
 * object per non-empty line. Anything else, including any single bad line, is
 * `invalid` and nothing is verified.
 */
export function parseInput(text) {
  if (typeof text !== 'string') return { kind: 'invalid', receipts: [], problems: ['input must be text'] };
  if (encoder.encode(text).length > LIMITS.maxBytes) return { kind: 'invalid', receipts: [], problems: [`input exceeds ${LIMITS.maxBytes} bytes`] };
  const trimmed = text.trim();
  if (trimmed.length === 0) return { kind: 'invalid', receipts: [], problems: ['nothing to verify: the input is empty'] };
  // A single (possibly pretty-printed) JSON object is one receipt.
  if (trimmed.startsWith('{')) {
    if (jsonDepth(trimmed) > LIMITS.maxDepth) return { kind: 'invalid', receipts: [], problems: [`JSON nesting exceeds ${LIMITS.maxDepth}`] };
    try {
      const whole = JSON.parse(trimmed);
      if (isPlainObject(whole)) return { kind: 'receipt', receipts: [whole], problems: [] };
    } catch { /* not one object; fall through to line-by-line */ }
  }
  const lines = trimmed.split(/\r?\n/).map((l) => l.trim()).filter((l) => l.length > 0);
  if (lines.length > LIMITS.maxLines) return { kind: 'invalid', receipts: [], problems: [`input exceeds ${LIMITS.maxLines} lines`] };

  const receipts = [];
  const problems = [];
  lines.forEach((line, i) => {
    if (jsonDepth(line) > LIMITS.maxDepth) { problems.push(`line ${i + 1}: JSON nesting exceeds ${LIMITS.maxDepth}`); return; }
    let value;
    try { value = JSON.parse(line); } catch (err) { problems.push(`line ${i + 1}: not valid JSON (${err.message})`); return; }
    if (!isPlainObject(value)) { problems.push(`line ${i + 1}: expected a JSON object, got ${Array.isArray(value) ? 'an array' : typeof value}`); return; }
    receipts.push(value);
  });
  if (problems.length > 0) return { kind: 'invalid', receipts: [], problems };
  return { kind: lines.length === 1 ? 'receipt' : 'chain', receipts, problems: [] };
}

// ---------------------------------------------------------------------------
// Envelope
// ---------------------------------------------------------------------------

function need(problems, cond, msg) { if (!cond) problems.push(msg); }
const isFiniteInt = (v) => typeof v === 'number' && Number.isInteger(v) && Number.isFinite(v);
const isStr = (v) => typeof v === 'string';

/** Structural validation of a signed receipt BEFORE any cryptography. */
export function validateEnvelope(receipt) {
  const problems = [];
  if (!isPlainObject(receipt)) return { ok: false, problems: ['receipt is not a JSON object'] };
  const p = receipt.payload, s = receipt.signature;
  need(problems, isPlainObject(p), 'payload missing or not an object');
  need(problems, isPlainObject(s), 'signature missing or not an object');
  if (problems.length > 0) return { ok: false, problems };

  need(problems, p.v === 1, `payload.v must be 1 (got ${JSON.stringify(p.v)})`);
  need(problems, KINDS.has(p.kind), `payload.kind must be bolyra.auth or bolyra.commerce (got ${JSON.stringify(p.kind)})`);
  need(problems, isFiniteInt(p.issuedAt) && p.issuedAt >= 0, 'payload.issuedAt must be a finite non-negative integer');
  need(problems, isStr(p.issuer) && p.issuer.length > 0, 'payload.issuer must be a non-empty string');
  need(problems, isStr(p.keyId) && p.keyId.length > 0, 'payload.keyId must be a non-empty string');
  if (isPlainObject(p.subject)) {
    for (const f of ['rootDid', 'actingDid', 'credentialCommitment', 'effectiveCommitment']) need(problems, isStr(p.subject[f]), `payload.subject.${f} must be a string`);
  } else problems.push('payload.subject missing or not an object');
  if (isPlainObject(p.decision)) {
    need(problems, typeof p.decision.allowed === 'boolean', 'payload.decision.allowed must be a boolean');
    need(problems, typeof p.decision.score === 'number' && Number.isFinite(p.decision.score), 'payload.decision.score must be a finite number');
    need(problems, isStr(p.decision.permissionBitmask) && RE_DECIMAL_INT.test(p.decision.permissionBitmask), 'payload.decision.permissionBitmask must be a decimal string');
    need(problems, isFiniteInt(p.decision.chainDepth) && p.decision.chainDepth >= 0, 'payload.decision.chainDepth must be a non-negative integer');
    if (p.decision.reasonCode !== undefined) need(problems, isStr(p.decision.reasonCode), 'payload.decision.reasonCode must be a string');
  } else problems.push('payload.decision missing or not an object');
  if (isPlainObject(p.proof)) {
    need(problems, p.proof.bundleVersion === 1 || p.proof.bundleVersion === 2, 'payload.proof.bundleVersion must be 1 or 2');
    for (const f of ['nonce', 'humanProofHash', 'agentProofHash', 'publicSignalsHash']) need(problems, isStr(p.proof[f]), `payload.proof.${f} must be a string`);
  } else problems.push('payload.proof missing or not an object');
  if (p.chain !== undefined) {
    if (isPlainObject(p.chain)) {
      need(problems, isFiniteInt(p.chain.seq) && p.chain.seq >= 0, 'payload.chain.seq must be a non-negative integer');
      need(problems, isStr(p.chain.prevReceiptHash) && RE_HASH.test(p.chain.prevReceiptHash), 'payload.chain.prevReceiptHash must be 0x + 64 hex');
    } else problems.push('payload.chain must be an object when present');
  }
  if (p.kind === 'bolyra.commerce') need(problems, isPlainObject(p.commerce), 'bolyra.commerce payload must carry a commerce object');
  if (p.instance !== undefined) need(problems, isPlainObject(p.instance), 'payload.instance must be an object when present');

  need(problems, s.alg === 'ES256K', `signature.alg must be ES256K (got ${JSON.stringify(s.alg)})`);
  need(problems, isStr(s.keyId) && s.keyId.length > 0, 'signature.keyId must be a non-empty string');
  need(problems, isStr(s.signer) && RE_ADDRESS.test(s.signer), 'signature.signer must be a 0x-prefixed 20-byte address');
  need(problems, isStr(s.payloadHash) && RE_HASH.test(s.payloadHash), 'signature.payloadHash must be 0x + 64 hex');
  need(problems, isStr(s.value) && RE_SIGNATURE.test(s.value), 'signature.value must be 0x + 130 hex (r‖s‖v)');
  if (receipt.receiptHash !== undefined) need(problems, isStr(receipt.receiptHash) && RE_HASH.test(receipt.receiptHash), 'receiptHash must be 0x + 64 hex when present');
  if (receipt.id !== undefined) need(problems, isStr(receipt.id), 'id must be a string when present');
  return { ok: problems.length === 0, problems };
}

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

function blank(v) { return v === undefined || v === null || (typeof v === 'string' && v.trim() === ''); }

/**
 * Normalize blank fields to absent, then reject anything present but
 * malformed. Malformed options BLOCK verification; they are never treated as
 * omitted.
 */
export function validateOptions(raw = {}) {
  const errors = [];
  const options = {};
  if (!isPlainObject(raw)) return { ok: false, errors: ['options must be an object'], options };
  if (!blank(raw.expectedSigner)) {
    const v = String(raw.expectedSigner).trim();
    if (RE_ADDRESS.test(v)) options.expectedSigner = v.toLowerCase(); else errors.push('expected signer must be a 0x-prefixed 20-byte hex address');
  }
  if (!blank(raw.expectedCount)) {
    const v = typeof raw.expectedCount === 'string' ? raw.expectedCount.trim() : raw.expectedCount;
    const n = typeof v === 'string' && RE_DECIMAL_INT.test(v) ? Number(v) : v;
    if (isFiniteInt(n) && n >= 1) options.expectedCount = n; else errors.push('expected count must be a positive integer');
  }
  if (!blank(raw.expectedHeadHash)) {
    const v = String(raw.expectedHeadHash).trim();
    if (RE_HASH.test(v)) options.expectedHeadHash = v.toLowerCase(); else errors.push('expected head hash must be 0x + 64 hex');
  }
  if (raw.allowUnchained !== undefined && raw.allowUnchained !== null) {
    if (typeof raw.allowUnchained === 'boolean') { if (raw.allowUnchained) options.allowUnchained = true; } else errors.push('allowUnchained must be a boolean');
  }
  return { ok: errors.length === 0, errors, options };
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

function invalidResult(problems) {
  return { overall: 'invalid', kind: 'invalid', problems, rows: [], chain: null, checkpoint: { state: 'invalid' } };
}

function safe(fn, fallback) {
  try { return { value: fn(), error: null }; } catch (err) { return { value: fallback, error: err instanceof Error ? err.message : String(err) }; }
}

function verifyRows(receipts, options) {
  return receipts.map((receipt, index) => {
    try { return verifyRow(receipt, index, options); } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return { index, id: null, envelope: { ok: false, problems: [] }, signature: 'invalid', signerMatch: 'not-checked', instance: { code: 'verifier_error', ok: false, present: false, detail: msg }, problems: [`verifier_error: ${msg}`] };
    }
  });
}

function verifyRow(receipt, index, options) {
  {
    const row = { index, id: isPlainObject(receipt) && isStr(receipt.id) ? receipt.id : null, problems: [] };
    row.envelope = validateEnvelope(receipt);
    if (!row.envelope.ok) {
      row.signature = 'not-run'; row.signerMatch = 'not-checked'; row.instance = { code: 'not-run', ok: false, present: false };
      row.problems.push(...row.envelope.problems.map((p) => `envelope: ${p}`));
      return row;
    }
    const sig = safe(() => verifyReceipt(receipt) === true, false);
    if (sig.error) { row.signature = 'invalid'; row.problems.push(`verifier_error: ${sig.error}`); }
    else row.signature = sig.value ? 'valid' : 'invalid';
    if (options.expectedSigner === undefined || row.signature !== 'valid') row.signerMatch = 'not-checked';
    else row.signerMatch = String(receipt.signature.signer).toLowerCase() === options.expectedSigner ? 'matched' : 'mismatch';
    const inst = safe(() => verifyInstanceBinding(receipt), null);
    if (inst.error || !isPlainObject(inst.value)) { row.instance = { code: 'verifier_error', ok: false, present: false, detail: inst.error ?? 'no result' }; row.problems.push(`verifier_error: instance ${inst.error ?? 'no result'}`); }
    else row.instance = { code: inst.value.code, ok: inst.value.ok === true, present: inst.value.present === true, detail: inst.value.detail };
    return row;
  }
}

function verifyChainPart(receipts, options) {
  const chained = receipts.filter((r) => isPlainObject(r) && isPlainObject(r.payload) && r.payload.chain !== undefined).length;
  const res = safe(() => verifyReceiptChain(receipts, {
    ...(options.expectedSigner !== undefined ? { expectedSigner: options.expectedSigner } : {}),
    ...(options.expectedCount !== undefined ? { expectedCount: options.expectedCount } : {}),
    ...(options.expectedHeadHash !== undefined ? { expectedHeadHash: options.expectedHeadHash } : {}),
    ...(options.allowUnchained ? { allowUnchained: true } : {}),
  }), null);
  if (res.error || !isPlainObject(res.value)) {
    return { ok: false, issues: [{ index: -1, code: 'verifier_error', message: res.error ?? 'no result' }], headHash: null, count: receipts.length, chained, unchainedPrefix: false, error: true };
  }
  const v = res.value;
  return {
    ok: v.ok === true,
    issues: Array.isArray(v.issues) ? v.issues.map((i) => ({ index: i.index, receiptId: i.receiptId, code: i.code, message: i.message })) : [],
    headHash: typeof v.headHash === 'string' ? v.headHash : null,
    count: typeof v.total === 'number' ? v.total : receipts.length,
    chained: typeof v.chained === 'number' ? v.chained : chained,
    unchainedPrefix: Boolean(options.allowUnchained) && typeof v.unchained === 'number' && v.unchained > 0,
    error: false,
  };
}

function decideCheckpoint(chain, options, componentsFailed) {
  const hasCount = options.expectedCount !== undefined, hasHead = options.expectedHeadHash !== undefined;
  const countMismatch = chain.issues.some((i) => i.code === 'count-mismatch');
  const headMismatch = chain.issues.some((i) => i.code === 'head-hash-mismatch');
  const cp = { count: hasCount ? (countMismatch ? 'mismatch' : 'matched') : 'absent', head: hasHead ? (headMismatch ? 'mismatch' : 'matched') : 'absent' };
  if (!hasCount && !hasHead) return { state: 'missing', ...cp };
  if ((hasCount && countMismatch) || (hasHead && headMismatch)) return { state: 'mismatch', ...cp };
  if (hasCount && hasHead) return { state: componentsFailed ? 'matched-but-failed' : 'matched', ...cp };
  return { state: 'partial', ...cp };
}

/** The ONE place overall success is decided. */
function decideOverall(rows, chain, options) {
  if (rows.length === 0) return false;
  for (const row of rows) {
    if (!row.envelope.ok) return false;
    if (row.signature !== 'valid') return false;
    if (row.problems.length > 0) return false;
    if (!(row.instance.code === 'ok' || row.instance.code === 'absent')) return false;
    if (options.expectedSigner !== undefined && row.signerMatch !== 'matched') return false;
  }
  if (chain !== null) {
    if (chain.error) return false;
    if (chain.issues.length > 0) return false;
  }
  return true;
}

function run(kind, receipts, options) {
  const rows = verifyRows(receipts, options);
  const anyChainFields = receipts.some((r) => isPlainObject(r) && isPlainObject(r.payload) && r.payload.chain !== undefined);
  const suppliedCheckpoint = options.expectedCount !== undefined || options.expectedHeadHash !== undefined;

  let chain = null;
  let checkpoint;
  if (kind === 'receipt' && !anyChainFields && !options.allowUnchained) {
    if (suppliedCheckpoint) return invalidResult(['a checkpoint (expected count / head hash) was supplied for a single unchained receipt; there is no chain to compare it against']);
    checkpoint = { state: 'not-applicable', count: 'absent', head: 'absent' };
  } else {
    chain = verifyChainPart(receipts, options);
  }

  const rowsFailed = !rows.every((row) => row.envelope.ok && row.signature === 'valid' && row.problems.length === 0 && (row.instance.code === 'ok' || row.instance.code === 'absent') && (options.expectedSigner === undefined || row.signerMatch === 'matched'));
  if (chain !== null) {
    const nonCheckpointIssues = chain.issues.filter((i) => i.code !== 'count-mismatch' && i.code !== 'head-hash-mismatch');
    checkpoint = decideCheckpoint(chain, options, rowsFailed || chain.error || nonCheckpointIssues.length > 0);
  }
  const overall = decideOverall(rows, chain, options) ? 'ok' : 'failed';
  return { overall, kind, problems: [], rows, chain, checkpoint };
}

/**
 * Verify pasted text with the supplied options. Returns a result whose
 * `overall` is `'ok'`, `'failed'`, or `'invalid'` (nothing was verified).
 */
export function verifyAll(text, rawOptions = {}) {
  const opts = validateOptions(rawOptions);
  if (!opts.ok) return invalidResult(opts.errors.map((e) => `options: ${e}`));
  const parsed = parseInput(text);
  if (parsed.kind === 'invalid') return invalidResult(parsed.problems);
  return run(parsed.kind, parsed.receipts, opts.options);
}

/** Test-only entry: skip parsing, verify already-parsed receipt objects. */
verifyAll.__withReceipts = function withReceipts(receipts, rawOptions = {}) {
  const opts = validateOptions(rawOptions);
  if (!opts.ok) return invalidResult(opts.errors.map((e) => `options: ${e}`));
  if (!Array.isArray(receipts) || receipts.length === 0) return invalidResult(['nothing to verify']);
  return run(receipts.length === 1 ? 'receipt' : 'chain', receipts, opts.options);
};
