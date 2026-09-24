/**
 * `TENANTS` — the one Worker secret that defines who may call this verifier,
 * and what each caller may do.
 *
 *   {
 *     "<org_id>": {
 *       "admin_token":       "<opaque; 32–256 chars, ≥ 32 bytes of entropy>",
 *       "verifier_token":    "<opaque>",
 *       "trusted_operators": ["<x>:<y>", …],      // BabyJubjub public keys, decimal
 *       "disabled":          false                  // optional quarantine switch
 *     }
 *   }
 *
 * Tenant AND role derive exclusively from which token matched:
 *
 *   Authorization: Bearer <t>
 *          │
 *          ▼
 *   loadTenants(env.TENANTS) ──defect──► throws internal_error (caller fails closed)
 *          │
 *          ▼
 *   resolveAuth(request, tenants)   every token of every tenant is compared in
 *          │                         constant time; the scan never exits early
 *          ├─ no match ──► null
 *          └─ match ─────► { org_id, role: 'admin' | 'verifier', disabled, trusted_operators }
 *
 * Load-time validation is strict and total: malformed JSON, a bad org id, an
 * unknown field (a typo in `disabled` must not silently leave a tenant live),
 * a missing or weak token, a duplicate token value ANYWHERE (a token that
 * appears twice grants nothing anywhere), an empty or malformed operator list,
 * a missing (unset or '') secret, or an oversize one — each throws, and the
 * caller must treat that as "no tenant is trusted", never "all tenants are
 * trusted". An empty MAP (`{}`) is not a defect (E13): it loads as zero tenants,
 * so every bearer is unauthenticated.
 */

import { sha256 } from '@noble/hashes/sha256';
import { loadTrustedOperators } from './verify/operators';
import { isVerifyDenial, VerifyDenial } from './verify/verdict';

export type Role = 'admin' | 'verifier';

export interface TenantConfig {
  admin_token: string;
  verifier_token: string;
  /** Canonical `x:y` operator key ids (see `operatorKeyId`). Never empty. */
  trusted_operators: Set<string>;
  /** Quarantine switch: tokens still resolve, but no route serves the tenant. */
  disabled: boolean;
}

/**
 * What a successful resolution hands the caller. Deliberately carries NO token
 * value — an auth result may be logged or serialized; a tenant's tokens never.
 */
export interface AuthResult {
  org_id: string;
  role: Role;
  /** Quarantine switch — callers MUST refuse to serve a disabled tenant. */
  disabled: boolean;
  /** The tenant's canonical operator key ids, for the verify core. */
  trusted_operators: ReadonlySet<string>;
}

/** Lowercase, 2–63 chars, no leading hyphen — it is also a durable identity. */
export const ORG_ID_PATTERN = /^[a-z0-9][a-z0-9-]{1,62}$/;

/**
 * Opaque bearer tokens: 32–256 characters of the RFC 6750 token68 alphabet
 * (minus `=`), never whitespace — so a token can neither be trivially weak nor
 * ambiguous under header parsing.
 */
export const TOKEN_PATTERN = /^[A-Za-z0-9._~+/-]{32,256}$/;

/** The only keys a tenant entry may carry; anything else is a defect. */
const TENANT_FIELDS: ReadonlySet<string> = new Set([
  'admin_token',
  'verifier_token',
  'trusted_operators',
  'disabled',
]);

/** Cloudflare's per-secret limit is 5 KB; the margin is deliberate (~10 tenants). */
export const MAX_TENANTS_BYTES = 4096;

const encoder = new TextEncoder();

/** SHA-256 output size: every compared value is reduced to exactly this many bytes. */
export const DIGEST_BYTES = 32;

/** The longest valid token (TOKEN_PATTERN), in bytes: every stored token pads to this. */
const MAX_TOKEN_BYTES = 256;

/**
 * The hashed preimage of a token: `u32be(byteLength) || bytes || zero padding` up to
 * `4 + MAX_TOKEN_BYTES`. The length prefix folds the length into the digest (different
 * lengths → different preimages, so a zero-padded prefix never collides), and the padding
 * makes hashing a STORED token (32–256 bytes) the same number of SHA-256 blocks whatever
 * its length. Only a presented value longer than any valid token grows the preimage, and
 * that costs the caller's own length only.
 */
export function tokenPreimage(value: string): Uint8Array {
  const bytes = encoder.encode(value);
  const out = new Uint8Array(4 + Math.max(bytes.length, MAX_TOKEN_BYTES));
  new DataView(out.buffer).setUint32(0, bytes.length);
  out.set(bytes, 4);
  return out;
}

/** The fixed-size digest a token is compared through. */
export function tokenDigest(value: string): Uint8Array {
  return sha256(tokenPreimage(value));
}

/**
 * Compare two `DIGEST_BYTES` digests with a fixed-count XOR loop (no early exit). Anything
 * else is a programming error, refused — so the loop count never depends on an input.
 */
export function compareDigests(x: Uint8Array, y: Uint8Array): boolean {
  if (x.length !== DIGEST_BYTES || y.length !== DIGEST_BYTES) {
    throw new TypeError(`compareDigests takes two ${DIGEST_BYTES}-byte digests`);
  }
  let diff = 0;
  for (let i = 0; i < DIGEST_BYTES; i++) diff |= x[i]! ^ y[i]!;
  return diff === 0;
}

/**
 * Timing-safe token comparison: both inputs are hashed to fixed-size digests, which are
 * compared in constant time. Neither the content nor the length of a stored token shapes
 * the work (see `tokenPreimage`); a length mismatch is folded into the digests, never a
 * short-circuit.
 */
export function timingSafeEqual(a: string, b: string): boolean {
  return compareDigests(tokenDigest(a), tokenDigest(b));
}

/**
 * Build a load-time defect. `detail` names the tenant and the field only —
 * NEVER a token value or any part of one: the Worker logs these details.
 */
function invalid(message: string, detail?: Record<string, unknown>): VerifyDenial {
  return new VerifyDenial('internal_error', `TENANTS: ${message}`, detail);
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * `JSON.parse` silently keeps the LAST of duplicate members, so
 * `"disabled": true, …, "disabled": false` would leave a tenant live and a
 * shadowed duplicate token would escape the duplicate-value check. Reject a
 * repeated key in any object, at any depth, BEFORE parsing. The scan is a
 * plain string walk (strings honour escapes; a string is a key when the next
 * non-space character is `:`); anything it cannot follow is left for
 * `JSON.parse` to reject. Key text is never logged.
 */
function assertNoDuplicateKeys(raw: string): void {
  const stack: Array<Set<string> | null> = []; // Set for an object, null for an array
  const n = raw.length;
  let i = 0;
  while (i < n) {
    const c = raw[i]!;
    if (c === '"') {
      const start = i;
      i++;
      while (i < n && raw[i] !== '"') i += raw[i] === '\\' ? 2 : 1;
      if (i >= n) return; // unterminated string: JSON.parse rejects it
      const text = raw.slice(start, i + 1);
      i++;
      const top = stack[stack.length - 1];
      if (top instanceof Set) {
        let j = i;
        while (j < n && (raw[j] === ' ' || raw[j] === '\n' || raw[j] === '\r' || raw[j] === '\t')) j++;
        if (raw[j] === ':') {
          let key: string;
          try {
            key = JSON.parse(text) as string;
          } catch {
            return; // malformed escape: JSON.parse rejects it
          }
          if (top.has(key)) throw invalid('duplicate key in a JSON object', { depth: stack.length });
          top.add(key);
        }
      }
      continue;
    }
    if (c === '{') stack.push(new Set());
    else if (c === '[') stack.push(null);
    else if (c === '}' || c === ']') stack.pop();
    i++;
  }
}

function requireToken(
  raw: unknown,
  field: 'admin_token' | 'verifier_token',
  orgId: string,
  seen: Set<string>,
): string {
  if (typeof raw !== 'string' || raw === '') {
    throw invalid(`${field} must be a non-empty string`, { org_id: orgId });
  }
  if (!TOKEN_PATTERN.test(raw)) {
    throw invalid(`${field} must be 32-256 characters of [A-Za-z0-9._~+/-]`, { org_id: orgId });
  }
  if (seen.has(raw)) {
    throw invalid('duplicate token value — a token that appears twice grants nothing anywhere', {
      org_id: orgId,
      field,
    });
  }
  seen.add(raw);
  return raw;
}

/**
 * Parse + validate the `TENANTS` secret. Throws `VerifyDenial('internal_error')`
 * on ANY defect; a partial map is never returned.
 */
export function loadTenants(raw: string | undefined): Map<string, TenantConfig> {
  if (raw === undefined || raw === '') throw invalid('not configured');
  if (encoder.encode(raw).byteLength >= MAX_TENANTS_BYTES) {
    throw invalid(`serialized size must be under ${MAX_TENANTS_BYTES} bytes`);
  }

  assertNoDuplicateKeys(raw);
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw invalid('not valid JSON');
  }
  if (!isPlainObject(parsed)) throw invalid('must be a JSON object keyed by org_id');
  // `{}` is VALID (E13): the deliberately empty map the last tenant's removal leaves. It loads
  // as an empty Map, so resolveAuth finds no tenant for any bearer and every authenticated
  // route answers 401. Only a missing or malformed configuration is a defect.
  const entries = Object.entries(parsed);

  const tenants = new Map<string, TenantConfig>();
  const seenTokens = new Set<string>();
  for (const [index, [orgId, value]] of entries.entries()) {
    if (!ORG_ID_PATTERN.test(orgId)) {
      // A rejected org id failed the charset check, so it may be ANY text (even a
      // token pasted into the wrong place): log its position, never its value.
      throw invalid('org_id must match ^[a-z0-9][a-z0-9-]{1,62}$', { entry_index: index });
    }
    if (!isPlainObject(value)) throw invalid('tenant entry must be an object', { org_id: orgId });
    for (const key of Object.keys(value)) {
      // Same rule: an unknown key may be a misplaced secret — name the tenant only.
      if (!TENANT_FIELDS.has(key)) throw invalid('unknown tenant field', { org_id: orgId });
    }

    const adminToken = requireToken(value.admin_token, 'admin_token', orgId, seenTokens);
    const verifierToken = requireToken(value.verifier_token, 'verifier_token', orgId, seenTokens);

    const operators = value.trusted_operators;
    if (!Array.isArray(operators) || !operators.every((e): e is string => typeof e === 'string')) {
      throw invalid('trusted_operators must be an array of "x:y" strings', { org_id: orgId });
    }
    let trustedOperators: Set<string>;
    try {
      trustedOperators = loadTrustedOperators(operators);
    } catch (e) {
      if (isVerifyDenial(e)) throw invalid(e.message, { org_id: orgId });
      throw e;
    }

    if (value.disabled !== undefined && typeof value.disabled !== 'boolean') {
      throw invalid('disabled must be a boolean when present', { org_id: orgId });
    }

    tenants.set(orgId, {
      admin_token: adminToken,
      verifier_token: verifierToken,
      trusted_operators: trustedOperators,
      disabled: value.disabled === true,
    });
  }
  return tenants;
}

/**
 * Resolve the presented bearer token to a tenant and role, or null. The
 * scheme grammar is deliberately narrower than RFC 7235 (SP/HTAB separators,
 * visible-ASCII token) so a fronting proxy or log parser cannot see a
 * different token than the Worker does. Every candidate token of every tenant
 * is compared digest to digest (`tokenDigest` + `compareDigests`, the
 * `timingSafeEqual` construction) and ALL candidates are always scanned (no
 * early exit on match). Duplicate values are impossible here —
 * `loadTenants` rejects them.
 */
export function resolveAuth(request: Request, tenants: Map<string, TenantConfig>): AuthResult | null {
  const header = request.headers.get('authorization') ?? '';
  const match = /^Bearer[ \t]+([\x21-\x7e]+)$/i.exec(header);
  if (match === null || match[1] === undefined) return null;
  const presented = tokenDigest(match[1]); // hashed once; each candidate is compared digest to digest

  let result: AuthResult | null = null;
  for (const [org_id, tenant] of tenants) {
    const candidates: ReadonlyArray<readonly [Role, string]> = [
      ['admin', tenant.admin_token],
      ['verifier', tenant.verifier_token],
    ];
    for (const [role, token] of candidates) {
      if (compareDigests(presented, tokenDigest(token)) && result === null) {
        result = { org_id, role, disabled: tenant.disabled, trusted_operators: tenant.trusted_operators };
      }
    }
  }
  return result;
}
