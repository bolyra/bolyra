/**
 * Executable form of the spec §3.4 verdict JSON Schema (closed, oneOf
 * allow/deny) — the test oracle every worker response is validated against,
 * and the validator behind the `static_verdict` conformance vectors.
 */

const KINDS = new Set(['classical', 'zk', 'external']);

const DENY_CODES = new Set([
  'malformed_input',
  'unsupported_version',
  'invalid_bundle',
  'invalid_proof',
  'untrusted_root',
  'delegation_invalid',
  'invalid_signature',
  'request_mismatch',
  'model_mismatch',
  'unknown_capability',
  'scope_exceeded',
  'expired',
  'nonce_missing',
  'nonce_replayed',
  'internal_error',
]);

export type SchemaResult = { ok: true } | { ok: false; reason: string };

function fail(reason: string): SchemaResult {
  return { ok: false, reason };
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function checkConsumeNonces(value: unknown): SchemaResult {
  if (!Array.isArray(value)) return fail('consume_nonces must be an array');
  if (value.length < 1) return fail('consume_nonces violates minItems 1');
  for (const entry of value) {
    if (!isPlainObject(entry)) return fail('consume_nonces entry must be an object');
    const keys = Object.keys(entry);
    for (const k of keys) {
      if (!['issuer_key', 'nonce', 'retain_until'].includes(k)) {
        return fail(`consume_nonces entry has disallowed property "${k}"`);
      }
    }
    if (typeof entry.issuer_key !== 'string') return fail('issuer_key must be a string');
    if (typeof entry.nonce !== 'string') return fail('nonce must be a string');
    if (typeof entry.retain_until !== 'number' || !Number.isInteger(entry.retain_until)) {
      return fail('retain_until must be an integer');
    }
  }
  return { ok: true };
}

/** Validate one verdict object against the closed §3.4 schema. */
export function validateVerdictSchema(v: unknown): SchemaResult {
  if (!isPlainObject(v)) return fail('verdict must be an object');

  if (v.kind !== undefined && (typeof v.kind !== 'string' || !KINDS.has(v.kind))) {
    return fail(`kind value outside the classical|zk|external enum`);
  }

  if (v.verdict === 'allow') {
    for (const k of Object.keys(v)) {
      if (!['verdict', 'kind', 'consume_nonces'].includes(k)) {
        return fail(`allow verdict has disallowed property "${k}"`);
      }
    }
    if (v.consume_nonces !== undefined) return checkConsumeNonces(v.consume_nonces);
    return { ok: true };
  }

  if (v.verdict === 'deny') {
    for (const k of Object.keys(v)) {
      if (!['verdict', 'kind', 'code', 'message', 'detail'].includes(k)) {
        return fail(`deny verdict has disallowed property "${k}"`);
      }
    }
    if (typeof v.code !== 'string' || !DENY_CODES.has(v.code)) {
      return fail('deny code missing or outside the §9 registry');
    }
    if (typeof v.message !== 'string') return fail('deny message missing');
    if (v.detail !== undefined && !isPlainObject(v.detail)) {
      return fail('deny detail must be an object');
    }
    return { ok: true };
  }

  return fail('verdict must be "allow" or "deny"');
}

/** Spec §3.3: a verdict without `kind` is interpreted as `zk`. */
export function effectiveKind(v: Record<string, unknown>): string {
  return typeof v.kind === 'string' ? v.kind : 'zk';
}
