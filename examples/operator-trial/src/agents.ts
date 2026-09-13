/**
 * Simulated agent credentials + dev-mode proof bundles.
 *
 * Dev mode is the real Bolyra protocol with mock proofs: bundle shape, signal
 * layout, nonce layout, policy checks, replay protection, and receipts are
 * identical to production; only the Groth16 proof strings are mocked. This
 * is a controlled trial, not production agent authentication.
 */

import { randomBytes } from 'node:crypto';
import type { BolyraProofBundle } from '@bolyra/mcp';

/** Permission names in bit order (bit 0 first), matching @bolyra/sdk's Permission enum. */
export const PERMISSION_NAMES = [
  'READ_DATA',
  'WRITE_DATA',
  'FINANCIAL_SMALL',
  'FINANCIAL_MEDIUM',
  'FINANCIAL_UNLIMITED',
  'SIGN_ON_BEHALF',
  'SUB_DELEGATE',
  'ACCESS_PII',
] as const;
export type PermissionName = (typeof PERMISSION_NAMES)[number];

/**
 * Cumulative-closed masks: FINANCIAL_MEDIUM implies FINANCIAL_SMALL, and
 * FINANCIAL_UNLIMITED implies both. Every value here satisfies
 * validateCumulativeBitEncoding.
 */
export const CLOSED_MASK: Record<PermissionName, bigint> = {
  READ_DATA: 1n,
  WRITE_DATA: 2n,
  FINANCIAL_SMALL: 4n,
  FINANCIAL_MEDIUM: 12n,
  FINANCIAL_UNLIMITED: 28n,
  SIGN_ON_BEHALF: 32n,
  SUB_DELEGATE: 64n,
  ACCESS_PII: 128n,
};

/** The policy's requireBitmask for a required permission name. */
export function requiredMask(name: PermissionName): bigint {
  return CLOSED_MASK[name];
}

/**
 * The withheld credential's mask: the closed mask of the previous row, or 0
 * for READ_DATA. A lower row's mask never contains the required row's own
 * bit, so checkToolPolicy's `(mask & required) === required` always fails.
 */
export function withheldMask(name: PermissionName): bigint {
  const i = PERMISSION_NAMES.indexOf(name);
  return i === 0 ? 0n : CLOSED_MASK[PERMISSION_NAMES[i - 1]];
}

/** Narration label for the withheld credential. */
export function withheldLabel(name: PermissionName): string {
  const i = PERMISSION_NAMES.indexOf(name);
  return i === 0 ? 'no permissions' : `${PERMISSION_NAMES[i - 1]} only`;
}

export interface DemoAgent {
  /** Narration label. */
  name: string;
  /** Credential commitment, identifies the credential in the static map. */
  commitment: bigint;
  /** Cumulative permission bitmask granted to this credential. */
  permissionBitmask: bigint;
}

export function createDemoAgent(name: string, permissionBitmask: bigint): DemoAgent {
  return {
    name,
    commitment: BigInt('0x' + randomBytes(16).toString('hex')),
    permissionBitmask,
  };
}

export interface AgentAuth {
  /** Value for the Authorization header ("Bolyra <base64 bundle>"). */
  header: string;
  bundle: BolyraProofBundle;
}

/** Production nonce layout: (unix_seconds << 64) | 64 bits of entropy. */
function freshNonce(nowSeconds: bigint): bigint {
  const entropy = BigInt('0x' + randomBytes(8).toString('hex'));
  return (nowSeconds << 64n) | entropy;
}

/**
 * Build a dev-mode proof bundle. Each call generates a fresh nonce; reusing a
 * header is a replay and the gateway middleware rejects it.
 */
export function buildDevBundle(agent: DemoAgent): AgentAuth {
  const now = BigInt(Math.floor(Date.now() / 1000));
  const nonce = freshNonce(now);
  const mockProofStrings = Array.from({ length: 8 }, () =>
    BigInt('0x' + randomBytes(4).toString('hex')).toString(),
  );

  const bundle: BolyraProofBundle = {
    v: 1,
    humanProof: {
      proof: mockProofStrings as never,
      publicSignals: ['0', '0', '0', '0', nonce.toString()],
    },
    // AgentPolicy public signal layout:
    // [0] agentMerkleRoot, [1] nullifierHash, [2] scopeCommitment,
    // [3] requiredScopeMask, [4] currentTimestamp, [5] sessionNonce
    agentProof: {
      proof: mockProofStrings as never,
      publicSignals: [
        '0',
        '0',
        agent.commitment.toString(),
        agent.permissionBitmask.toString(),
        now.toString(),
        nonce.toString(),
      ],
    },
    nonce: nonce.toString(),
    credentialCommitment: agent.commitment.toString(),
    _dev: true,
  };

  const encoded = Buffer.from(JSON.stringify(bundle), 'utf8').toString('base64');
  return { header: `Bolyra ${encoded}`, bundle };
}

/** Render a bitmask as binary with a "b" suffix, e.g. 3n -> "11b". */
export function fmtMask(mask: bigint): string {
  return mask.toString(2) + 'b';
}
