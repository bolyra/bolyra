/**
 * Decode + structurally validate a `bvp/1` presentation bundle.
 *
 * Ported from `integrations/cli/src/verify/bundle.ts` for the Workers runtime:
 * base64url decoding uses `atob` (no Node `Buffer`), and envelope validation
 * reuses the SDK's pure `validateEnvelope` via a deep import so no circuit
 * crypto is pulled in. Purely structural — no proof math here.
 */

import {
  validateEnvelope,
  type ProofEnvelope,
} from '@bolyra/sdk/dist/envelope.js';
import { VerifyDenial } from './verdict';

export interface PointDec {
  x: string;
  y: string;
}

export interface AgentCredential {
  model_hash: string;
  operator_pubkey: PointDec;
  permission_bitmask: string;
  expiry: number;
}

export interface AgentSlot {
  envelope: ProofEnvelope;
  credential: AgentCredential;
}

export interface HumanSlot {
  envelope: ProofEnvelope;
}

export interface DelegationLeaf {
  delegatee_scope: string;
  delegatee_commitment: string;
  delegatee_expiry: number;
}

export interface DelegationHop {
  envelope: ProofEnvelope;
  leaf?: DelegationLeaf;
}

export interface Binding {
  agent_name: string;
  project_key: string;
  program: string;
  model: string;
  capabilities: string[];
}

export interface BundleSignature {
  R8: PointDec;
  S: string;
}

export interface ParsedBundle {
  bvp: 1;
  agent: AgentSlot;
  human?: HumanSlot;
  delegation?: DelegationHop[];
  binding: Binding;
  sig: BundleSignature;
}

const CIRCUIT_FOR_SLOT = {
  agent: 'AgentPolicy',
  human: 'HumanUniqueness',
  delegation: 'Delegation',
} as const;

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isDecString(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0;
}

function isPointDec(value: unknown): value is PointDec {
  return isPlainObject(value) && isDecString(value.x) && isDecString(value.y);
}

/** base64url → utf8 string, or null when the input is not valid base64url. */
function base64urlToUtf8(input: string): string | null {
  if (!/^[A-Za-z0-9_-]+={0,2}$/.test(input)) return null;
  const b64 = input.replace(/-/g, '+').replace(/_/g, '/');
  let binary: string;
  try {
    binary = atob(b64);
  } catch {
    return null;
  }
  const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
  return new TextDecoder('utf-8').decode(bytes);
}

/** Decode raw-JSON or base64url-JSON transport encoding into a plain object. */
function decode(bundleString: string): Record<string, unknown> {
  const jsonText = bundleString.trimStart().startsWith('{')
    ? bundleString
    : base64urlToUtf8(bundleString);

  let parsed: unknown;
  try {
    if (jsonText === null) throw new Error('bad base64url');
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

function validateSlotEnvelope(
  raw: unknown,
  slot: keyof typeof CIRCUIT_FOR_SLOT,
  where: string,
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

function parseHuman(raw: unknown): HumanSlot | undefined {
  if (raw === undefined) return undefined;
  if (!isPlainObject(raw)) {
    throw new VerifyDenial('invalid_bundle', 'human slot is malformed');
  }
  const envelope = validateSlotEnvelope(raw.envelope, 'human', 'human');
  return { envelope };
}

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

  if (hops[hops.length - 1]!.leaf === undefined) {
    throw new VerifyDenial('delegation_invalid', 'final delegation hop must reveal its leaf', {
      index: hops.length - 1,
    });
  }
  return hops;
}

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

function parseSig(raw: unknown): BundleSignature {
  if (!isPlainObject(raw) || !isPointDec(raw.R8) || !isDecString(raw.S)) {
    throw new VerifyDenial('invalid_bundle', 'sig is missing or has ill-typed fields');
  }
  return { R8: { x: raw.R8.x, y: raw.R8.y }, S: raw.S };
}

/** Decode + structurally validate a `bvp/1` presentation bundle. */
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
