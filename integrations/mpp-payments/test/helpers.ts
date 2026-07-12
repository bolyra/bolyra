/**
 * Test fixtures: build classical `bvp/1` presentation bundles with a REAL
 * operator EdDSA-Poseidon binding signature (the load-bearing fact in
 * classical verification) and a structurally-valid mock proof envelope (the
 * proof math is never checked on the classical path).
 */

import {
  derivePublicKey,
  eddsaSign,
  permissionsToBitmask,
  poseidon3,
  poseidon5,
  Permission,
} from '@bolyra/sdk';
import { bindingDigest, hashModel } from '../src/classical';
import type { BindingClaim } from '../src/bundle';
import type { OperatorKey } from '../src/types';

export const OPERATOR_PRIV = 42n;
export const OTHER_OPERATOR_PRIV = 43n;

export const AGENT_NAME = 'shopper-bot';
export const AUDIENCE = 'api.merchant.example';
export const PROGRAM = 'mpp';
export const MODEL = 'opus-4.1';

/** Far-future expiry so fixtures never age out. */
export const EXPIRY = 4102444800; // 2100-01-01T00:00:00Z
/** Fixed test clock, comfortably before EXPIRY. */
export const NOW_UNIX = 1751990400;

export async function operatorKey(priv: bigint = OPERATOR_PRIV): Promise<OperatorKey> {
  const pub = await derivePublicKey(priv);
  return { x: pub.x.toString(), y: pub.y.toString() };
}

export interface MakeBundleOptions {
  operatorPriv?: bigint;
  /** Signed by the binding; defaults to the standard fixture context. */
  binding?: Partial<BindingClaim>;
  /** Permissions revealed in the credential bitmask. */
  permissions?: Permission[];
  /** Credential expiry (unix seconds). */
  expiry?: number;
  /** Override the revealed bitmask AFTER signing (tamper helper). */
  tamperBitmask?: bigint;
  /** Corrupt the binding signature. */
  breakSignature?: boolean;
  /** Add zk-only slots to the raw bundle. */
  withHumanSlot?: boolean;
  /** Encode as base64url instead of raw JSON. */
  base64?: boolean;
}

/**
 * Build a serialized `bvp/1` bundle string. The credential's scopeCommitment
 * public signal is recomputed from the revealed preimage so the classical
 * scope-anchoring check passes unless a tamper option breaks it.
 */
export async function makeBundle(options: MakeBundleOptions = {}): Promise<string> {
  const {
    operatorPriv = OPERATOR_PRIV,
    permissions = [Permission.READ_DATA, Permission.FINANCIAL_SMALL],
    expiry = EXPIRY,
    breakSignature = false,
    withHumanSlot = false,
    base64 = false,
  } = options;

  const binding: BindingClaim = {
    agent_name: AGENT_NAME,
    project_key: AUDIENCE,
    program: PROGRAM,
    model: MODEL,
    capabilities: ['mpp:financial:small'],
    ...options.binding,
  };

  const operatorPub = await derivePublicKey(operatorPriv);
  const modelHash = hashModel(binding.model);
  const bitmask = permissionsToBitmask(permissions);
  const revealedBitmask = options.tamperBitmask ?? bitmask;

  const credentialCommitment = await poseidon5(
    modelHash,
    operatorPub.x,
    operatorPub.y,
    revealedBitmask,
    BigInt(expiry),
  );
  const scopeCommitment = await poseidon3(
    revealedBitmask,
    credentialCommitment,
    BigInt(expiry),
  );

  const sig = await eddsaSign(operatorPriv, bindingDigest(binding));
  const sigBlock = {
    R8: { x: sig.R8.x.toString(), y: sig.R8.y.toString() },
    S: (breakSignature ? sig.S + 1n : sig.S).toString(),
  };

  const envelope = {
    version: '1.0.0',
    circuit: { name: 'AgentPolicy', version: '1.0.0' },
    proofType: 'groth16',
    publicSignals: [
      '1', // agentMerkleRoot (carries no weight classically)
      '2', // nullifierHash
      scopeCommitment.toString(),
      revealedBitmask.toString(),
      String(NOW_UNIX),
      '3', // sessionNonce
    ],
    proof: {
      pi_a: ['1', '2'],
      pi_b: [
        ['1', '2'],
        ['3', '4'],
      ],
      pi_c: ['5', '6'],
    },
  };

  const bundle: Record<string, unknown> = {
    bvp: 1,
    agent: {
      envelope,
      credential: {
        model_hash: modelHash.toString(),
        operator_pubkey: { x: operatorPub.x.toString(), y: operatorPub.y.toString() },
        permission_bitmask: revealedBitmask.toString(),
        expiry,
      },
    },
    binding,
    sig: sigBlock,
  };
  if (withHumanSlot) {
    bundle.human = { envelope: { ...envelope, circuit: { name: 'HumanUniqueness', version: '1.0.0' } } };
  }

  const json = JSON.stringify(bundle);
  return base64 ? Buffer.from(json, 'utf8').toString('base64url') : json;
}

/** The spec §2.1 request context matching the standard fixture binding. */
export function fixtureRequestContext(overrides: Partial<Record<string, unknown>> = {}) {
  return {
    agent_name: AGENT_NAME,
    project_key: AUDIENCE,
    program: PROGRAM,
    model: MODEL,
    granted_capabilities: ['mpp:financial:small'],
    ...overrides,
  };
}
