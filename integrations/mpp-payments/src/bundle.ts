/**
 * Decode + structurally validate a `bvp/1` presentation bundle — the value
 * carried in the `X-Bolyra-Authorization` request header.
 *
 * This mirrors the wire format accepted by the `bolyra verify` reference
 * verifier (spec/external-verifier-contract-v1.md §4.2): raw JSON object
 * text, or base64url-encoded JSON. Structural checks only — cryptographic and
 * policy checks live in `classical.ts`.
 *
 * The classical gate is AGENT-ONLY: bundles carrying `human` or `delegation`
 * slots are backed exclusively by ZK proofs this package's default verifier
 * cannot check, so their presence is recorded and denied by the classical
 * pipeline rather than silently half-verified (same posture as the Bolyra
 * hosted-verify preview).
 */

import { validateEnvelope, type ProofEnvelope } from '@bolyra/sdk';
import { VerifyDenial } from './types';

/** Decimal-string BabyJubjub point. */
export interface PointDec {
  x: string;
  y: string;
}

/** The agent's revealed credential (spec §4.2). Values kept as strings. */
export interface RevealedCredential {
  model_hash: string;
  operator_pubkey: PointDec;
  permission_bitmask: string;
  expiry: number;
}

/** The request-binding block the presentation commits to (spec §4.3). */
export interface BindingClaim {
  agent_name: string;
  project_key: string;
  program: string;
  model: string;
  capabilities: string[];
}

/** The operator's EdDSA signature over the binding digest. */
export interface BundleSignature {
  R8: PointDec;
  S: string;
}

/** A decoded, structurally-validated agent-only view of a `bvp/1` bundle. */
export interface ParsedBundle {
  bvp: 1;
  agent: {
    envelope: ProofEnvelope;
    credential: RevealedCredential;
  };
  binding: BindingClaim;
  sig: BundleSignature;
  /** ZK-only slots present in the raw bundle (denied by the classical gate). */
  zkOnlySlots: string[];
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isDecString(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0;
}

function isPointDec(value: unknown): value is PointDec {
  return isPlainObject(value) && isDecString(value.x) && isDecString(value.y);
}

/**
 * Decode the transport encoding into a plain object. Left-trimmed input
 * starting with `{` is raw JSON; anything else is base64url-decoded first.
 */
function decode(bundleString: string): Record<string, unknown> {
  const jsonText = bundleString.trimStart().startsWith('{')
    ? bundleString
    : Buffer.from(bundleString, 'base64url').toString('utf8');

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

/** Parse + structurally validate the agent slot (envelope + credential). */
function parseAgent(raw: unknown): ParsedBundle['agent'] {
  if (!isPlainObject(raw)) {
    throw new VerifyDenial('invalid_bundle', 'agent slot is missing or malformed');
  }
  if (!isPlainObject(raw.envelope)) {
    throw new VerifyDenial('invalid_proof', 'agent: missing proof envelope');
  }
  let envelope: ProofEnvelope;
  try {
    envelope = validateEnvelope(raw.envelope);
  } catch (err) {
    throw new VerifyDenial('invalid_proof', 'agent: invalid proof envelope', {
      reason: err instanceof Error ? err.message : String(err),
    });
  }
  if (envelope.circuit.name !== 'AgentPolicy') {
    throw new VerifyDenial('invalid_proof', 'agent: wrong circuit for slot', {
      expected: 'AgentPolicy',
      got: envelope.circuit.name,
    });
  }

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

/** Parse + structurally validate the request-binding block. */
function parseBinding(raw: unknown): BindingClaim {
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
 * Decode + structurally validate a `bvp/1` bundle (agent-only view).
 * @throws {VerifyDenial} on any structural violation.
 */
export function parseBundle(bundleString: string): ParsedBundle {
  const obj = decode(bundleString);

  if (obj.bvp !== 1) {
    throw new VerifyDenial('unsupported_version', 'unsupported bvp version', {
      expected: 1,
      got: obj.bvp,
    });
  }

  const zkOnlySlots: string[] = [];
  if (obj.human !== undefined) zkOnlySlots.push('human');
  if (obj.delegation !== undefined && !(Array.isArray(obj.delegation) && obj.delegation.length === 0)) {
    zkOnlySlots.push('delegation');
  }

  return {
    bvp: 1,
    agent: parseAgent(obj.agent),
    binding: parseBinding(obj.binding),
    sig: parseSig(obj.sig),
    zkOnlySlots,
  };
}

/** A cheap, non-cryptographic peek used to echo identity fields. */
export interface BundlePeek {
  agent_name: string;
  model: string;
}

/**
 * Decode the bundle just far enough to read `binding.agent_name` and
 * `binding.model` for the verifier-request echo. NOT a validation step —
 * every mode's verifier re-checks the binding against its signature. Fails
 * closed (`invalid_bundle`) when the header value cannot be decoded at all.
 */
export function peekBundle(bundleString: string): BundlePeek {
  const obj = decode(bundleString);
  const binding = obj.binding;
  if (
    !isPlainObject(binding) ||
    typeof binding.agent_name !== 'string' ||
    typeof binding.model !== 'string'
  ) {
    throw new VerifyDenial('invalid_bundle', 'binding is missing agent_name/model');
  }
  return { agent_name: binding.agent_name, model: binding.model };
}
