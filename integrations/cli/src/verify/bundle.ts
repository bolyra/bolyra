/**
 * Decode + structurally validate a "Bolyra Verifiable Presentation" (`bvp/1`)
 * bundle — the wire input to `bolyra verify` (spec §4.2).
 *
 * This module is purely structural: it decodes the transport encoding, checks
 * the `bvp` version, runs each embedded proof envelope through the SDK's
 * `validateEnvelope`, pins each envelope to its expected circuit slot, and
 * verifies the presence/shape of the credential, binding, delegation leaves,
 * and signature blocks. It does NOT verify any proof math, signature, or
 * business rule — later verifier modules BigInt the string field elements and
 * do the cryptographic + policy checks.
 *
 * Every failed check throws `VerifyDenial(<code>, ...)`; the core orchestrator
 * converts that to the machine-readable deny verdict. Field-element values are
 * kept as strings so downstream modules can parse them with the precision they
 * need.
 */

import { validateEnvelope, type ProofEnvelope } from '@bolyra/sdk';
import { VerifyDenial } from './verdict';

/** Ed25519/BabyJubjub-style point with decimal-string coordinates. */
export interface PointDec {
  x: string;
  y: string;
}

/** The agent's revealed credential (spec §4.2). Values kept as strings. */
export interface AgentCredential {
  model_hash: string;
  operator_pubkey: PointDec;
  permission_bitmask: string;
  expiry: number;
}

/** The agent slot: an AgentPolicy proof plus its revealed credential. */
export interface AgentSlot {
  envelope: ProofEnvelope;
  credential: AgentCredential;
}

/** The optional human slot: a HumanUniqueness proof. */
export interface HumanSlot {
  envelope: ProofEnvelope;
}

/** A revealed delegation leaf (spec §4.2). Values kept as strings. */
export interface DelegationLeaf {
  delegatee_scope: string;
  delegatee_commitment: string;
  delegatee_expiry: number;
}

/** One delegation hop: a Delegation proof, optionally revealing its leaf. */
export interface DelegationHop {
  envelope: ProofEnvelope;
  leaf?: DelegationLeaf;
}

/** The request-binding block the presentation commits to. */
export interface Binding {
  agent_name: string;
  project_key: string;
  program: string;
  model: string;
  capabilities: string[];
}

/** The EdDSA signature over the binding. Values kept as strings. */
export interface BundleSignature {
  R8: PointDec;
  S: string;
}

/** A decoded + structurally-validated `bvp/1` presentation bundle. */
export interface ParsedBundle {
  bvp: 1;
  agent: AgentSlot;
  human?: HumanSlot;
  delegation?: DelegationHop[];
  binding: Binding;
  sig: BundleSignature;
}

/** Circuit name each slot's envelope MUST carry. */
const CIRCUIT_FOR_SLOT = {
  agent: 'AgentPolicy',
  human: 'HumanUniqueness',
  delegation: 'Delegation',
} as const;

/** Narrow an unknown value to a non-null, non-array plain object. */
function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Is `value` a non-empty decimal string (structural check only)? */
function isDecString(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0;
}

/** A finite, integral point coordinate pair with decimal-string members. */
function isPointDec(value: unknown): value is PointDec {
  return isPlainObject(value) && isDecString(value.x) && isDecString(value.y);
}

/**
 * Decode the transport encoding into a plain object.
 *
 * If the (left-trimmed) input starts with `{` it is treated as raw JSON;
 * otherwise it is base64url-decoded and then JSON-parsed. Anything that fails
 * to decode, fails to parse, or does not yield a plain object is an
 * `invalid_bundle` denial.
 */
function decode(bundleString: string): Record<string, unknown> {
  let jsonText: string;
  if (bundleString.trimStart().startsWith('{')) {
    jsonText = bundleString;
  } else {
    // base64url -> utf8. Buffer is lenient, so re-encode and compare to reject
    // input that is not valid base64url (e.g. contains stray characters).
    const buf = Buffer.from(bundleString, 'base64url');
    jsonText = buf.toString('utf8');
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(jsonText);
  } catch {
    throw new VerifyDenial('invalid_bundle', 'bundle is not decodable JSON', {
      hint: 'expected raw JSON object or base64url-encoded JSON',
    });
  }

  if (!isPlainObject(parsed)) {
    throw new VerifyDenial('invalid_bundle', 'bundle must be a JSON object', {
      got: Array.isArray(parsed) ? 'array' : typeof parsed,
    });
  }
  return parsed;
}

/**
 * Validate one embedded proof envelope and pin it to its circuit slot.
 * Any structural violation OR circuit mismatch is an `invalid_proof` denial.
 */
function validateSlotEnvelope(
  raw: unknown,
  slot: keyof typeof CIRCUIT_FOR_SLOT,
  where: string
): ProofEnvelope {
  if (!isPlainObject(raw)) {
    throw new VerifyDenial('invalid_proof', `${where}: missing proof envelope`, { slot });
  }
  let envelope: ProofEnvelope;
  try {
    envelope = validateEnvelope(raw);
  } catch (err) {
    throw new VerifyDenial('invalid_proof', `${where}: invalid proof envelope`, {
      slot,
      reason: err instanceof Error ? err.message : String(err),
    });
  }
  const expected = CIRCUIT_FOR_SLOT[slot];
  if (envelope.circuit.name !== expected) {
    throw new VerifyDenial('invalid_proof', `${where}: wrong circuit for slot`, {
      slot,
      expected,
      got: envelope.circuit.name,
    });
  }
  return envelope;
}

/** Parse + structurally validate the agent slot (envelope + credential). */
function parseAgent(raw: unknown): AgentSlot {
  if (!isPlainObject(raw)) {
    throw new VerifyDenial('invalid_bundle', 'agent slot is missing or malformed');
  }
  const envelope = validateSlotEnvelope(raw.envelope, 'agent', 'agent');

  const credential = raw.credential;
  if (!isPlainObject(credential)) {
    throw new VerifyDenial('invalid_bundle', 'agent.credential is missing or malformed');
  }
  if (
    !isDecString(credential.model_hash) ||
    !isPointDec(credential.operator_pubkey) ||
    !isDecString(credential.permission_bitmask) ||
    typeof credential.expiry !== 'number' ||
    !Number.isFinite(credential.expiry)
  ) {
    throw new VerifyDenial('invalid_bundle', 'agent.credential has missing or ill-typed fields');
  }

  return {
    envelope,
    credential: {
      model_hash: credential.model_hash,
      operator_pubkey: { x: credential.operator_pubkey.x, y: credential.operator_pubkey.y },
      permission_bitmask: credential.permission_bitmask,
      expiry: credential.expiry,
    },
  };
}

/** Parse the optional human slot, if present. */
function parseHuman(raw: unknown): HumanSlot | undefined {
  if (raw === undefined) return undefined;
  if (!isPlainObject(raw)) {
    throw new VerifyDenial('invalid_bundle', 'human slot is malformed');
  }
  const envelope = validateSlotEnvelope(raw.envelope, 'human', 'human');
  return { envelope };
}

/** Parse an optionally-present delegation leaf. */
function parseLeaf(raw: unknown): DelegationLeaf | undefined {
  if (raw === undefined) return undefined;
  if (
    !isPlainObject(raw) ||
    !isDecString(raw.delegatee_scope) ||
    !isDecString(raw.delegatee_commitment) ||
    typeof raw.delegatee_expiry !== 'number' ||
    !Number.isFinite(raw.delegatee_expiry)
  ) {
    throw new VerifyDenial('delegation_invalid', 'delegation leaf has missing or ill-typed fields');
  }
  return {
    delegatee_scope: raw.delegatee_scope,
    delegatee_commitment: raw.delegatee_commitment,
    delegatee_expiry: raw.delegatee_expiry,
  };
}

/**
 * Parse the optional delegation chain. When present and non-empty, the FINAL
 * hop MUST reveal its leaf (the delegatee the whole chain resolves to);
 * intermediate leaves are optional.
 */
function parseDelegation(raw: unknown): DelegationHop[] | undefined {
  if (raw === undefined) return undefined;
  if (!Array.isArray(raw)) {
    throw new VerifyDenial('invalid_bundle', 'delegation must be an array');
  }
  if (raw.length === 0) return undefined;

  const hops: DelegationHop[] = raw.map((entry, i) => {
    if (!isPlainObject(entry)) {
      throw new VerifyDenial('invalid_bundle', `delegation[${i}] is malformed`);
    }
    const envelope = validateSlotEnvelope(entry.envelope, 'delegation', `delegation[${i}]`);
    const leaf = parseLeaf(entry.leaf);
    return leaf === undefined ? { envelope } : { envelope, leaf };
  });

  if (hops[hops.length - 1].leaf === undefined) {
    throw new VerifyDenial(
      'delegation_invalid',
      'final delegation hop must reveal its leaf',
      { index: hops.length - 1 }
    );
  }
  return hops;
}

/** Parse + structurally validate the request-binding block. */
function parseBinding(raw: unknown): Binding {
  if (
    !isPlainObject(raw) ||
    typeof raw.agent_name !== 'string' ||
    typeof raw.project_key !== 'string' ||
    typeof raw.program !== 'string' ||
    typeof raw.model !== 'string' ||
    !Array.isArray(raw.capabilities) ||
    !raw.capabilities.every((c): c is string => typeof c === 'string')
  ) {
    throw new VerifyDenial('invalid_bundle', 'binding is missing or has ill-typed fields');
  }
  return {
    agent_name: raw.agent_name,
    project_key: raw.project_key,
    program: raw.program,
    model: raw.model,
    capabilities: [...raw.capabilities],
  };
}

/** Parse + structurally validate the signature block. */
function parseSig(raw: unknown): BundleSignature {
  if (!isPlainObject(raw) || !isPointDec(raw.R8) || !isDecString(raw.S)) {
    throw new VerifyDenial('invalid_bundle', 'sig is missing or has ill-typed fields');
  }
  return { R8: { x: raw.R8.x, y: raw.R8.y }, S: raw.S };
}

/**
 * Decode + structurally validate a `bvp/1` presentation bundle.
 *
 * @param bundleString raw JSON object text, or base64url-encoded JSON.
 * @throws VerifyDenial on any structural violation (see module doc for codes).
 */
export function parseBundle(bundleString: string): ParsedBundle {
  const obj = decode(bundleString);

  if (obj.bvp !== 1) {
    throw new VerifyDenial('unsupported_version', 'unsupported bvp version', {
      expected: 1,
      got: obj.bvp,
    });
  }

  const agent = parseAgent(obj.agent);
  const human = parseHuman(obj.human);
  const delegation = parseDelegation(obj.delegation);
  const binding = parseBinding(obj.binding);
  const sig = parseSig(obj.sig);

  const parsed: ParsedBundle = { bvp: 1, agent, binding, sig };
  if (human !== undefined) parsed.human = human;
  if (delegation !== undefined) parsed.delegation = delegation;
  return parsed;
}
