/**
 * Demo agent credentials + dev-mode proof bundles.
 *
 * Dev mode is the real Bolyra protocol with mock proofs: the bundle shape,
 * signal layout, nonce layout, policy checks, replay protection, and receipts
 * are all identical to production — only the Groth16 proof strings are mocked.
 * In production, clients call attachBolyraProof(human, credential) from
 * @bolyra/mcp, which generates real proofs via @bolyra/sdk.
 *
 * The bundle built here mirrors @bolyra/mcp's attachBolyraProof dev-mode
 * output (integrations/mcp/src/client.ts), with one improvement: it uses the
 * production nonce layout `(unix_seconds << 64) | random_64_bits` so every
 * call gets a unique, fresh nonce (the helper's plain-seconds dev nonce would
 * collide when two calls land in the same second and trip replay protection).
 */

import { randomBytes } from 'node:crypto';
import type { BolyraProofBundle } from '@bolyra/mcp';

/** Cumulative permission bits (see gateway README for the full table). */
export const READ_DATA = 1n;
export const WRITE_DATA = 2n;

export interface DemoAgent {
  /** Human-readable label for narration only. */
  name: string;
  /** Credential commitment — identifies the agent credential. */
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
 * Build a dev-mode proof bundle for one tool call. Each call generates a
 * fresh nonce — reusing a bundle is a replay and the gateway rejects it.
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
    // AgentPolicy public signal layout (per spec):
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
