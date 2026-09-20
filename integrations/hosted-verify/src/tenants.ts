/**
 * `TENANTS` — the one Worker secret that defines who may call this verifier,
 * and what each caller may do.
 *
 *   {
 *     "<org_id>": {
 *       "admin_token":       "<opaque; ≥ 32 bytes of entropy from provisioning>",
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
 *          └─ match ─────► { org_id, role: 'admin' | 'verifier' }
 *
 * Load-time validation is strict and total: malformed JSON, a bad org id, a
 * missing role, a duplicate token value ANYWHERE (a token that appears twice
 * grants nothing anywhere), an empty or malformed operator list, an oversize
 * secret, or an empty map — each throws, and the caller must treat that as
 * "no tenant is trusted", never "all tenants are trusted".
 */

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

export interface AuthResult {
  org_id: string;
  role: Role;
}

/** Lowercase, 2–63 chars, no leading hyphen — it is also a durable identity. */
export const ORG_ID_PATTERN = /^[a-z0-9][a-z0-9-]{1,62}$/;

/** Cloudflare's per-secret limit is 5 KB; the margin is deliberate (~10 tenants). */
export const MAX_TENANTS_BYTES = 4096;

const encoder = new TextEncoder();

/** Constant-time byte comparison (no early exit on mismatch). */
export function timingSafeEqual(a: string, b: string): boolean {
  const ab = encoder.encode(a);
  const bb = encoder.encode(b);
  let diff = ab.length ^ bb.length;
  const len = Math.max(ab.length, bb.length);
  for (let i = 0; i < len; i++) {
    diff |= (ab[i % ab.length] ?? 0) ^ (bb[i % bb.length] ?? 0);
  }
  return diff === 0;
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

function requireToken(
  raw: unknown,
  field: 'admin_token' | 'verifier_token',
  orgId: string,
  seen: Set<string>,
): string {
  if (typeof raw !== 'string' || raw === '') {
    throw invalid(`${field} must be a non-empty string`, { org_id: orgId });
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

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw invalid('not valid JSON');
  }
  if (!isPlainObject(parsed)) throw invalid('must be a JSON object keyed by org_id');
  const entries = Object.entries(parsed);
  if (entries.length === 0) throw invalid('no tenants configured');

  const tenants = new Map<string, TenantConfig>();
  const seenTokens = new Set<string>();
  for (const [orgId, value] of entries) {
    if (!ORG_ID_PATTERN.test(orgId)) {
      throw invalid('org_id must match ^[a-z0-9][a-z0-9-]{1,62}$', { org_id: orgId });
    }
    if (!isPlainObject(value)) throw invalid('tenant entry must be an object', { org_id: orgId });

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
 * Resolve the presented bearer token to a tenant and role, or null. Every
 * candidate token of every tenant is compared with the constant-time
 * comparator and ALL candidates are always scanned (no early exit on match).
 * Duplicate values are impossible here — `loadTenants` rejects them.
 */
export function resolveAuth(request: Request, tenants: Map<string, TenantConfig>): AuthResult | null {
  const header = request.headers.get('authorization') ?? '';
  const match = /^Bearer\s+(.+)$/i.exec(header);
  if (match === null || match[1] === undefined) return null;
  const presented = match[1];

  let result: AuthResult | null = null;
  for (const [org_id, tenant] of tenants) {
    const candidates: ReadonlyArray<readonly [Role, string]> = [
      ['admin', tenant.admin_token],
      ['verifier', tenant.verifier_token],
    ];
    for (const [role, token] of candidates) {
      if (timingSafeEqual(presented, token) && result === null) result = { org_id, role };
    }
  }
  return result;
}
