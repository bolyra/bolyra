/**
 * Browser port of the x402 PAYMENT-REQUIRED header/leg parser and the JWS
 * protected-header peek from `@bolyra/payment-protocols` (version pinned in
 * package.json `config.paymentProtocolsVersion`):
 *   integrations/payment-protocols/src/x402-local-challenge.ts  (x402LocalChallenge)
 *   integrations/payment-protocols/src/x402-issuer-quote/jws.ts (peekHeader)
 *
 * The published package needs Node (node:crypto, Buffer, @bolyra/mpp), so this
 * file re-implements ONLY the pure header/leg validation. It is differentially
 * tested against the published package in test/unit/x402.diff.test.js; the
 * claim is "matches the pinned package on that corpus", nothing wider.
 *
 * Known deliberate divergence: a JSON nesting cap (`header_depth`) is applied
 * before parsing as a playground guard; the package has no such cap.
 *
 * Nothing here verifies a signature, a mandate, or a payee. `classifyLeg` is a
 * playground description of observed fields, not a package function.
 */
import { sha256 } from '@noble/hashes/sha2';
import { utf8ToBytes, bytesToHex } from '@noble/hashes/utils';

export const LIMITS = Object.freeze({
  MAX_PAYMENT_REQUIRED_CHARS: 64 * 1024,
  MAX_LOCAL_CHALLENGE_SECONDS: 900,
  MAX_COMPACT_JWS_CHARS: 8 * 1024,
  MAX_JSON_DEPTH: 32,
});
/** The placeholder the x402 EVC profile §4.2 discusses (asserted at build to equal the fixture's leg-1 payTo). */
export const PLACEHOLDER_URN = 'urn:x402:agent-pay:see-quote';

const STANDARD_BASE64 = /^[A-Za-z0-9+/]+={0,2}$/;
const BASE64URL_PART = /^[A-Za-z0-9_-]+$/;
const FORBIDDEN_MEMBERS = ['__proto__', 'constructor', 'prototype'];
const ADDRESS_VALUED = /^0x[0-9a-fA-F]{40}$/;
const utf8 = new TextDecoder('utf-8', { fatal: true });

export class PlaygroundDenial extends Error {
  constructor(code, message, detail) { super(message); this.name = 'PlaygroundDenial'; this.code = code; this.detail = detail; }
}
export class JwsRejected extends Error {
  constructor(reason, detail) { super(detail ? `${reason}: ${detail}` : reason); this.name = 'JwsRejected'; this.reason = reason; }
}
const malformed = (reason) => new PlaygroundDenial('malformed_input', 'x402 PAYMENT-REQUIRED challenge is not usable', { reason });
const hostFault = (reason) => new PlaygroundDenial('internal_error', 'local challenge host input is invalid', { reason });

// ---------------------------------------------------------------------------
// Canonical base64 / base64url (no Buffer, no atob: identical in every runtime)
// ---------------------------------------------------------------------------
const STD = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const URL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const REV = (alphabet) => { const m = new Map(); for (let i = 0; i < 64; i++) m.set(alphabet[i], i); return m; };
const STD_REV = REV(STD), URL_REV = REV(URL);

function decodeLenient(s, rev) {
  // Decodes any run of alphabet chars (padding stripped), ignoring trailing partial bits.
  const out = []; let buf = 0, bits = 0;
  for (const ch of s) { const v = rev.get(ch); if (v === undefined) return null; buf = (buf << 6) | v; bits += 6; if (bits >= 8) { bits -= 8; out.push((buf >> bits) & 0xff); } }
  return new Uint8Array(out);
}
function encodeWith(bytes, alphabet, pad) {
  let out = ''; let i = 0;
  for (; i + 2 < bytes.length; i += 3) { const n = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2]; out += alphabet[n >> 18] + alphabet[(n >> 12) & 63] + alphabet[(n >> 6) & 63] + alphabet[n & 63]; }
  const rest = bytes.length - i;
  if (rest === 1) { const n = bytes[i] << 16; out += alphabet[n >> 18] + alphabet[(n >> 12) & 63] + (pad ? '==' : ''); }
  else if (rest === 2) { const n = (bytes[i] << 16) | (bytes[i + 1] << 8); out += alphabet[n >> 18] + alphabet[(n >> 12) & 63] + alphabet[(n >> 6) & 63] + (pad ? '=' : ''); }
  return out;
}
/** Standard base64 with canonical padding and zero trailing bits; null otherwise. Mirrors Buffer round-trip in the package. */
export function decodeBase64Strict(s) {
  if (typeof s !== 'string' || !STANDARD_BASE64.test(s)) return null;
  const body = s.replace(/=+$/, '');
  if (body.length % 4 === 1) return null;
  const bytes = decodeLenient(body, STD_REV);
  if (bytes === null || encodeWith(bytes, STD, true) !== s) return null;
  return bytes;
}
/** base64url, no padding, canonical trailing bits; null otherwise. */
export function decodeBase64UrlStrict(s) {
  if (typeof s !== 'string' || !BASE64URL_PART.test(s) || s.length % 4 === 1) return null;
  const bytes = decodeLenient(s, URL_REV);
  if (bytes === null || encodeWith(bytes, URL, false) !== s) return null;
  return bytes;
}

// ---------------------------------------------------------------------------
// Shared helpers (mirroring the package)
// ---------------------------------------------------------------------------
export function isUnixSeconds(value) { return typeof value === 'number' && Number.isFinite(value) && value >= 0 && value <= 2 ** 40; }
export function isPlainObject(value) { return typeof value === 'object' && value !== null && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype; }
function hasForbiddenMember(o) { return FORBIDDEN_MEMBERS.some((n) => Object.prototype.hasOwnProperty.call(o, n)); }
export function sha256Hex(text) { return bytesToHex(sha256(utf8ToBytes(text))); }
function deepFreeze(value) { if (typeof value === 'object' && value !== null) { for (const k of Object.keys(value)) deepFreeze(value[k]); Object.freeze(value); } return value; }
function cloneJson(value, reason) {
  if (Array.isArray(value)) return value.map((v) => cloneJson(v, reason));
  if (isPlainObject(value)) { const out = {}; for (const key of Object.keys(value)) { if (FORBIDDEN_MEMBERS.includes(key)) throw malformed(reason); out[key] = cloneJson(value[key], reason); } return out; }
  if (value === null || ['string', 'number', 'boolean'].includes(typeof value)) return value;
  throw malformed(reason);
}
function jsonDepth(text) {
  let depth = 0, max = 0, inString = false, escaped = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (inString) { if (escaped) escaped = false; else if (ch === '\\') escaped = true; else if (ch === '"') inString = false; continue; }
    if (ch === '"') inString = true; else if (ch === '{' || ch === '[') { depth++; if (depth > max) max = depth; } else if (ch === '}' || ch === ']') depth--;
  }
  return max;
}
function requireString(leg, field) { const v = leg[field]; if (typeof v !== 'string' || v.length === 0) throw malformed(`leg_${field}`); return v; }

/** Header-level decoding in the package's order. Throws PlaygroundDenial. */
function decodeHeader(headerValue) {
  if (typeof headerValue !== 'string') throw malformed('header_type');
  if (headerValue.length > LIMITS.MAX_PAYMENT_REQUIRED_CHARS) throw malformed('header_size');
  const bytes = decodeBase64Strict(headerValue);
  if (bytes === null) throw malformed('header_base64');
  let text;
  try { text = utf8.decode(bytes); } catch { throw malformed('header_json'); }
  if (jsonDepth(text) > LIMITS.MAX_JSON_DEPTH) throw malformed('header_depth'); // playground guard (see header)
  let parsed;
  try { parsed = JSON.parse(text); } catch { throw malformed('header_json'); }
  if (!isPlainObject(parsed) || hasForbiddenMember(parsed)) throw malformed('header_object');
  if (parsed.x402Version !== 2) throw malformed('x402_version');
  const accepts = parsed.accepts;
  if (!Array.isArray(accepts) || accepts.length === 0) throw malformed('accepts');
  return { parsed, accepts };
}
/** One leg in the package's order. Throws PlaygroundDenial. */
function buildLeg(rawLeg) {
  if (!isPlainObject(rawLeg)) throw malformed('leg_object');
  const timeout = rawLeg.maxTimeoutSeconds;
  if (typeof timeout !== 'number' || !Number.isInteger(timeout) || timeout <= 0) throw malformed('leg_max_timeout');
  const leg = { scheme: requireString(rawLeg, 'scheme'), network: requireString(rawLeg, 'network'), asset: requireString(rawLeg, 'asset'), amount: requireString(rawLeg, 'amount'), payTo: requireString(rawLeg, 'payTo'), maxTimeoutSeconds: timeout };
  if ('extra' in rawLeg) { if (!isPlainObject(rawLeg.extra)) throw malformed('leg_extra'); leg.extra = cloneJson(rawLeg.extra, 'leg_extra'); }
  return leg;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------
/** Header-level parse for display: never throws. Per-leg problems are reported per leg. */
export function parseChallenge(headerValue) {
  let decoded;
  try { decoded = decodeHeader(headerValue); } catch (err) {
    if (err instanceof PlaygroundDenial) return { ok: false, code: err.code, reason: err.detail.reason };
    return { ok: false, code: 'malformed_input', reason: 'header_json' };
  }
  const legs = decoded.accepts.map((raw, index) => {
    try { return { index, leg: deepFreeze(buildLeg(raw)) }; } catch (err) { return { index, leg: null, reason: err instanceof PlaygroundDenial ? err.detail.reason : 'leg_object' }; }
  });
  return { ok: true, decoded: decoded.parsed, headerSha256: sha256Hex(headerValue), legs };
}

/** Exact mirror of x402LocalChallenge (host faults first, then header, then the selected leg). */
export function selectLeg(input) {
  const { headerValue, resource, legIndex, now, maxSeconds } = input;
  if (typeof resource !== 'string' || resource.length === 0) throw hostFault('resource');
  if (!isUnixSeconds(now)) throw hostFault('now');
  if (!Number.isInteger(maxSeconds) || maxSeconds < 1 || maxSeconds > LIMITS.MAX_LOCAL_CHALLENGE_SECONDS) throw hostFault('max_seconds');
  const { accepts } = decodeHeader(headerValue);
  if (!Number.isInteger(legIndex) || legIndex < 0 || legIndex >= accepts.length) throw malformed('leg_index');
  const leg = deepFreeze(buildLeg(accepts[legIndex]));
  const headerSha256 = sha256Hex(headerValue);
  const requirements = { scheme: leg.scheme, network: leg.network, asset: leg.asset, amount: leg.amount, payTo: leg.payTo, ...(leg.extra !== undefined ? { extra: cloneJson(leg.extra, 'leg_extra') } : {}) };
  return deepFreeze({
    mode: 'local', receivedAt: now, headerSha256, selectedLeg: leg, requirements,
    context: { resource, requirements, nonce: headerSha256, expiresAt: now + Math.min(leg.maxTimeoutSeconds, maxSeconds) },
  });
}

/** Playground description of a leg's observed fields. Not a package function; establishes nothing. */
export function classifyLeg(leg) {
  const kind = leg.payTo === PLACEHOLDER_URN ? 'placeholder-urn' : ADDRESS_VALUED.test(leg.payTo) ? 'address-valued' : 'other';
  const hasQuoteToken = isPlainObject(leg.extra) && typeof leg.extra.quoteToken === 'string';
  return { kind, hasQuoteToken };
}
/** The package's default payee matcher: byte equality. */
export function defaultPayeeMatch(audience, payTo) { return typeof audience === 'string' && audience === payTo; }

// ---------------------------------------------------------------------------
// JWS: header peek (mirror of peekHeader) and SEPARATE payload inspection
// ---------------------------------------------------------------------------
function parseJsonObjectPart(bytes, reason) {
  let text; try { text = utf8.decode(bytes); } catch { throw new JwsRejected('utf8'); }
  let value; try { value = JSON.parse(text); } catch { throw new JwsRejected(reason, 'not json'); }
  if (!isPlainObject(value)) throw new JwsRejected(reason);
  for (const name of FORBIDDEN_MEMBERS) if (Object.prototype.hasOwnProperty.call(value, name)) throw new JwsRejected(reason, name);
  return value;
}
function splitCompact(compact) {
  if (typeof compact !== 'string') throw new JwsRejected('compact_shape');
  if (compact.length > LIMITS.MAX_COMPACT_JWS_CHARS) throw new JwsRejected('size');
  const parts = compact.split('.');
  if (parts.length !== 3 || parts.some((p) => p.length === 0)) throw new JwsRejected('compact_shape');
  return parts;
}
function decodePart(part) { const b = decodeBase64UrlStrict(part); if (b === null) throw new JwsRejected('base64url'); return b; }
/** Mirror of peekHeader: the protected header WITHOUT verifying anything. */
export function peekJwsHeader(compact) { const [h] = splitCompact(compact); return parseJsonObjectPart(decodePart(h), 'header_object'); }
/** Display-only payload decode. Runs the header peek first; never a substitute for verification. */
export function inspectJwsPayload(compact) { const [h, p] = splitCompact(compact); parseJsonObjectPart(decodePart(h), 'header_object'); return parseJsonObjectPart(decodePart(p), 'payload_object'); }
/** SHA-256 of the compact token: an audit handle, not a quote identifier. */
export function tokenSha256(compact) { return sha256Hex(compact); }
