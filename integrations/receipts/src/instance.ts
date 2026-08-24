import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';
import { canonicalize } from './canonical';
import type { SignedReceipt } from './types';

/**
 * Instance binding for commerce receipts (spec/receipt-instance-binding-v1.md).
 *
 * commerce.intentHash is parameter-shaped: two otherwise identical spend
 * intents produce the same hash, and instance uniqueness comes only from the
 * issuer-generated proof.nonce, which a third party cannot recompute. The
 * instance block closes that gap: an instance-shaped reference any holder of
 * the preimage fields derives independently, with no callback to the issuer.
 *
 * verifyInstanceBinding() is the SEMANTIC check and deliberately separate from
 * verifyReceipt(): signature validity and instance-binding validity are
 * different claims. verifyReceipt() proves the issuer signed the payload; it
 * happily accepts a payload whose instance.ref does not match its own
 * preimage. Every consumer of the instance claim must call both.
 */

/** Domain-separation tag hashed into the ref, terminated by an explicit 0x00. */
export const INSTANCE_BINDING_DST = 'bolyra.receipt.instance/1';

/** Version marker in the reference string syntax — a verifier never guesses the derivation. */
export const INSTANCE_REF_PREFIX = 'birv1:';

const REF_PATTERN = /^birv1:[0-9a-f]{64}$/;
const DECISION_AT_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
// eslint-disable-next-line no-control-regex
const ASCII_ONLY = /^[\x00-\x7f]*$/;

/**
 * The full preimage of instance.ref, carried in the receipt so it is
 * self-contained. Closed schema: exactly these members, every value an ASCII
 * string (or array of ASCII strings) — within that domain the sorted-key
 * canonical JSON is byte-equivalent to RFC 8785.
 */
export interface InstancePreimage {
  /** Payee / project_key the decision bound to. */
  audience: string;
  /** Binding program discriminator (e.g. "x402", "mpp"). */
  program: string;
  /** Granted capability tokens, order as granted (order is significant). */
  capabilities: string[];
  /** Decimal string, exactly as decided. */
  amountUsd: string;
  /** RFC 3339 UTC with exactly 3-digit milliseconds: "2026-08-24T10:00:00.123Z". */
  decisionAt: string;
  /** In-protocol pre-decision challenge nonce, when the transport has one. */
  requestNonce?: string;
  /** External instance reference (e.g. an argentum action_ref), verbatim. */
  actionRef?: string;
}

export interface ReceiptInstanceFields {
  /** INSTANCE_REF_PREFIX + lowercase sha256 hex over the domain-tagged canonical preimage. */
  ref: string;
  preimage: InstancePreimage;
}

export type InstanceBindingCode =
  | 'absent'
  | 'ok'
  | 'wrong_kind'
  | 'malformed_ref'
  | 'out_of_domain'
  | 'ref_mismatch';

export type InstanceBindingResult =
  | { ok: true; present: false; code: 'absent' }
  | { ok: true; present: true; code: 'ok' }
  | { ok: false; present: true; code: Exclude<InstanceBindingCode, 'absent' | 'ok'>; detail: string };

export type PreimageValidation = { ok: true } | { ok: false; detail: string };

const REQUIRED_MEMBERS = ['audience', 'program', 'capabilities', 'amountUsd', 'decisionAt'] as const;
const OPTIONAL_MEMBERS = ['requestNonce', 'actionRef'] as const;
const ALLOWED_MEMBERS: ReadonlySet<string> = new Set([...REQUIRED_MEMBERS, ...OPTIONAL_MEMBERS]);
const STRING_MEMBERS = ['audience', 'program', 'amountUsd', 'decisionAt', ...OPTIONAL_MEMBERS] as const;

/**
 * Enforces the closed canonicalization domain of spec §3.1. Anything outside
 * it is rejected outright — no best-effort canonicalization, one pinned
 * behavior.
 */
export function validateInstancePreimage(value: unknown): PreimageValidation {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return { ok: false, detail: 'preimage must be a JSON object' };
  }
  const obj = value as Record<string, unknown>;

  for (const member of Object.keys(obj)) {
    if (!ALLOWED_MEMBERS.has(member)) {
      return { ok: false, detail: `unknown member "${member}" (closed schema)` };
    }
  }
  for (const member of REQUIRED_MEMBERS) {
    if (!(member in obj)) {
      return { ok: false, detail: `missing required member "${member}"` };
    }
  }
  for (const member of STRING_MEMBERS) {
    if (!(member in obj)) continue;
    const v = obj[member];
    if (typeof v !== 'string') {
      return { ok: false, detail: `member "${member}" must be a string` };
    }
    if (!ASCII_ONLY.test(v)) {
      return { ok: false, detail: `member "${member}" must contain only ASCII (0x00..0x7F)` };
    }
  }
  const capabilities = obj.capabilities;
  if (!Array.isArray(capabilities)) {
    return { ok: false, detail: 'member "capabilities" must be an array of strings' };
  }
  for (const cap of capabilities) {
    if (typeof cap !== 'string') {
      return { ok: false, detail: 'every capability must be a string' };
    }
    if (!ASCII_ONLY.test(cap)) {
      return { ok: false, detail: 'every capability must contain only ASCII (0x00..0x7F)' };
    }
  }
  if (!DECISION_AT_PATTERN.test(obj.decisionAt as string)) {
    return {
      ok: false,
      detail: 'decisionAt must match YYYY-MM-DDTHH:MM:SS.mmmZ exactly (3-digit ms, UTC Z)',
    };
  }
  return { ok: true };
}

function utf8(str: string): Uint8Array {
  return new TextEncoder().encode(str);
}

/**
 * ref = "birv1:" + sha256hex( utf8(DST) || 0x00 || utf8(canonicalize(preimage)) )
 *
 * Throws on an out-of-domain preimage: an emitter must never produce a ref
 * whose preimage a verifier is required to reject.
 */
export function computeInstanceRef(preimage: InstancePreimage): string {
  const validation = validateInstancePreimage(preimage);
  if (!validation.ok) {
    throw new Error(`instance preimage out of domain: ${validation.detail}`);
  }
  const dst = utf8(INSTANCE_BINDING_DST);
  const canonical = utf8(canonicalize(preimage));
  const input = new Uint8Array(dst.length + 1 + canonical.length);
  input.set(dst, 0);
  input[dst.length] = 0x00;
  input.set(canonical, dst.length + 1);
  return INSTANCE_REF_PREFIX + bytesToHex(sha256(input));
}

/**
 * The semantic instance-binding check. Assumes nothing about the signature —
 * pair it with verifyReceipt(). Returns ok with present:false when the
 * receipt carries no instance block (the block is optional).
 */
export function verifyInstanceBinding(receipt: SignedReceipt): InstanceBindingResult {
  const instance = receipt.payload.instance;
  if (instance === undefined) {
    return { ok: true, present: false, code: 'absent' };
  }
  if (receipt.payload.kind !== 'bolyra.commerce') {
    return {
      ok: false,
      present: true,
      code: 'wrong_kind',
      detail: `instance binding v1 is scoped to bolyra.commerce receipts, got "${receipt.payload.kind}"`,
    };
  }
  // Parsed JSON can carry any shape here regardless of the TS type; a signed
  // receipt with e.g. "instance": null must fail deterministically, not throw.
  if (typeof instance !== 'object' || instance === null || Array.isArray(instance)) {
    return {
      ok: false,
      present: true,
      code: 'malformed_ref',
      detail: 'instance block must be a JSON object with ref and preimage members',
    };
  }
  if (typeof instance.ref !== 'string' || !REF_PATTERN.test(instance.ref)) {
    return {
      ok: false,
      present: true,
      code: 'malformed_ref',
      detail: 'ref must be "birv1:" followed by 64 lowercase hex characters',
    };
  }
  const validation = validateInstancePreimage(instance.preimage);
  if (!validation.ok) {
    return { ok: false, present: true, code: 'out_of_domain', detail: validation.detail };
  }
  const recomputed = computeInstanceRef(instance.preimage);
  if (recomputed !== instance.ref) {
    return {
      ok: false,
      present: true,
      code: 'ref_mismatch',
      detail: 'recomputed instance ref does not match the carried ref',
    };
  }
  return { ok: true, present: true, code: 'ok' };
}
