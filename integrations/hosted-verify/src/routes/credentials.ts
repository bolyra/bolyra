/**
 * Registration-request parsing for `POST /v1/credentials`.
 *
 *   { "version": 1,
 *     "binding":         { agent_name, project_key, program, model, capabilities, expiry },
 *     "signature":       { "R8": { "x", "y" }, "S" },
 *     "operator_pubkey": { "x", "y" } }
 *
 * The binding and signature shapes are validated by the SAME functions the
 * presentation-bundle parser uses (`parseBinding`, `parseSig`), so a
 * registration and a later presentation canonicalize identically. This module
 * returns a result, never throws, and never echoes request text into messages
 * (a misplaced secret must not come back in a response).
 */

import { isPointDec, parseBinding, parseSig, type Binding, type BundleSignature, type PointDec } from '../verify/bundle';
import { isVerifyDenial } from '../verify/verdict';

export interface RegistrationRequest {
  binding: Binding;
  signature: BundleSignature;
  operator_pubkey: PointDec;
}

export type ParseResult = { ok: true; value: RegistrationRequest } | { ok: false; message: string };

/** Non-2xx bodies on the registry routes are `{ error, message }` with these codes. */
export type RegistryErrorCode =
  | 'unauthorized'
  | 'forbidden'
  | 'untrusted_operator'
  | 'malformed_input'
  | 'binding_signature_invalid'
  | 'binding_expired'
  | 'credential_revoked'
  | 'not_found'
  | 'method_not_allowed'
  | 'tenant_disabled'
  | 'internal_error';

const FIELDS: ReadonlySet<string> = new Set(['version', 'binding', 'signature', 'operator_pubkey']);

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** The wire grammar is decimal digits only — narrower than what `BigInt()` would accept. */
const isDecimal = (v: string): boolean => /^[0-9]+$/.test(v);

/** An object with exactly these keys — unknown nested fields are rejected like unknown top-level ones. */
function hasExactKeys(value: unknown, keys: readonly string[]): value is Record<string, unknown> {
  if (!isPlainObject(value)) return false;
  const present = Object.keys(value);
  return present.length === keys.length && keys.every((k) => Object.prototype.hasOwnProperty.call(value, k));
}

export function parseRegistration(body: unknown): ParseResult {
  if (!isPlainObject(body)) return { ok: false, message: 'request must be a JSON object' };
  for (const key of Object.keys(body)) {
    if (!FIELDS.has(key)) return { ok: false, message: 'request carries an unexpected field' };
  }
  if (body.version !== 1) return { ok: false, message: 'version must be 1' };

  let binding: Binding;
  try {
    binding = parseBinding(body.binding);
  } catch (e) {
    // The parser's message may quote a request-supplied key name; the code is enough.
    if (isVerifyDenial(e)) {
      const why =
        e.code === 'unsupported_version'
          ? 'a five-field v1 binding is not accepted; re-issue with expiry'
          : 'missing, ill-typed or unexpected fields';
      return { ok: false, message: `binding: ${why}` };
    }
    throw e;
  }
  if (!hasExactKeys(body.signature, ['R8', 'S']) || !hasExactKeys(body.signature.R8, ['x', 'y'])) {
    return { ok: false, message: 'signature: missing or ill-typed fields' };
  }
  let signature: BundleSignature;
  try {
    signature = parseSig(body.signature);
  } catch (e) {
    if (isVerifyDenial(e)) return { ok: false, message: 'signature: missing or ill-typed fields' };
    throw e;
  }
  if (
    !hasExactKeys(body.operator_pubkey, ['x', 'y']) ||
    !isPointDec(body.operator_pubkey) ||
    !isDecimal(body.operator_pubkey.x) ||
    !isDecimal(body.operator_pubkey.y)
  ) {
    return { ok: false, message: 'operator_pubkey must be { x, y } decimal strings' };
  }
  if (!isDecimal(signature.R8.x) || !isDecimal(signature.R8.y) || !isDecimal(signature.S)) {
    return { ok: false, message: 'signature: missing or ill-typed fields' };
  }
  return {
    ok: true,
    value: {
      binding,
      signature,
      operator_pubkey: { x: body.operator_pubkey.x, y: body.operator_pubkey.y },
    },
  };
}
