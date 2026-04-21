/**
 * Lazy SDK loader — avoids pulling heavy snarkjs/crypto deps at module load.
 *
 * The @bolyra/sdk dist may not include all modules (e.g., offchain was added
 * in v0.3). This loader uses require() with a fallback for missing exports.
 */

import type {
  HumanIdentity,
  AgentCredential,
  HandshakeResult,
  Proof,
  BolyraConfig,
} from '@bolyra/sdk';

/** Subset of SDK functions used by the payment protocol adapters */
export interface BolyraSDK {
  proveHandshake(
    human: HumanIdentity,
    agent: AgentCredential,
    options?: { scope?: bigint; nonce?: bigint; config?: BolyraConfig },
  ): Promise<{ humanProof: Proof; agentProof: Proof; nonce: bigint }>;

  verifyHandshake(
    humanProof: Proof,
    agentProof: Proof,
    nonce: bigint,
    config?: BolyraConfig,
  ): Promise<HandshakeResult>;

  verifyHandshakeOffchain(
    humanProof: Proof,
    agentProof: Proof,
    nonce: bigint,
    config?: BolyraConfig,
  ): Promise<HandshakeResult>;
}

let cached: BolyraSDK | null = null;

/**
 * Lazily load the Bolyra SDK, resolving both core and offchain modules.
 * Caches the result for subsequent calls.
 */
export function loadSDK(): BolyraSDK {
  if (cached) return cached;

  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const sdk = require('@bolyra/sdk') as Record<string, unknown>;

  const proveHandshake = sdk['proveHandshake'] as BolyraSDK['proveHandshake'];
  const verifyHandshake = sdk['verifyHandshake'] as BolyraSDK['verifyHandshake'];

  // verifyHandshakeOffchain may not be in dist yet (added in v0.3)
  // Fall back to verifyHandshake if not available
  const verifyHandshakeOffchain = (
    sdk['verifyHandshakeOffchain'] ?? verifyHandshake
  ) as BolyraSDK['verifyHandshakeOffchain'];

  if (!proveHandshake || !verifyHandshake) {
    throw new Error(
      '@bolyra/sdk is missing core exports (proveHandshake, verifyHandshake). ' +
      'Ensure @bolyra/sdk >= 0.2.0 is installed and built.'
    );
  }

  cached = { proveHandshake, verifyHandshake, verifyHandshakeOffchain };
  return cached;
}
