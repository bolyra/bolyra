/**
 * Bolyra OpenClaw Adapter
 *
 * Maps Bolyra's ZKP mutual handshake to OpenClaw's TrustVerificationResult.
 * Thin glue code — all cryptographic work delegated to @bolyra/sdk.
 *
 * Usage:
 *   import { createBolyraPlugin } from '@bolyra/openclaw';
 *   const plugin = createBolyraPlugin({ network: 'base-sepolia' });
 *   // Register with OpenClaw runtime
 *   openclaw.use(plugin);
 */

import type {
  HumanIdentity,
  AgentCredential,
  HandshakeResult,
  Permission,
} from '@bolyra/sdk';

import type {
  TrustVerificationResult,
  TrustGrade,
  OpenClawPlugin,
  BolyraOpenClawConfig,
  VerificationPoint,
} from './types';

const DEFAULT_CONFIG: Required<Omit<BolyraOpenClawConfig, 'sdkConfig'>> = {
  network: 'base-sepolia',
  minScore: 70,
  maxProofAge: 300,
  verificationPoints: [
    'skill_installation',
    'payment_execution',
    'inter_agent_communication',
    'gateway_startup',
  ],
};

/** Cache entry for verified agents (avoids re-proving within maxProofAge) */
interface CacheEntry {
  result: TrustVerificationResult;
  timestamp: number;
}

/**
 * Compute a trust score (0–100) from a Bolyra handshake result.
 *
 * Scoring:
 *   - 40 pts: Both proofs valid (humanProof + agentProof)
 *   - 20 pts: Credential not expired
 *   - 20 pts: Permission scope covers required operations
 *   - 10 pts: Session nonce is fresh (within maxProofAge)
 *   - 10 pts: Scope commitment is non-zero (chain-state ready)
 */
export function computeTrustScore(
  handshake: HandshakeResult,
  credential: AgentCredential,
  maxProofAge: number,
): { score: number; warnings: string[] } {
  let score = 0;
  const warnings: string[] = [];

  // Proof validity (40 pts)
  if (handshake.verified) {
    score += 40;
  } else {
    warnings.push('ZKP verification failed — proofs are invalid');
  }

  // Credential expiry (20 pts)
  const now = BigInt(Math.floor(Date.now() / 1000));
  if (credential.expiryTimestamp > now) {
    score += 20;
  } else {
    warnings.push(
      `Agent credential expired at ${credential.expiryTimestamp} (current: ${now})`,
    );
  }

  // Permission coverage (20 pts)
  // At minimum, agents should have READ_DATA permission
  const hasBasicPermissions = (credential.permissionBitmask & 0b11n) !== 0n;
  if (hasBasicPermissions) {
    score += 20;
  } else {
    warnings.push('Agent has no read/write permissions');
  }

  // Nonce freshness (10 pts)
  const nonceAge = Number(now - handshake.sessionNonce / 1000n);
  if (nonceAge < maxProofAge) {
    score += 10;
  } else {
    warnings.push(`Session nonce is stale (${nonceAge}s old, max ${maxProofAge}s)`);
  }

  // Scope commitment (10 pts)
  if (handshake.scopeCommitment !== 0n) {
    score += 10;
  } else {
    warnings.push('Scope commitment is zero — delegation chain not initialized');
  }

  return { score, warnings };
}

/** Map a numeric score to a letter grade */
export function scoreToGrade(score: number): TrustGrade {
  if (score >= 90) return 'A';
  if (score >= 70) return 'B';
  if (score >= 50) return 'C';
  if (score >= 30) return 'D';
  return 'F';
}

/** Construct a did:bolyra DID from a credential commitment */
export function buildDid(network: string, commitment: bigint): string {
  const hex = commitment.toString(16).padStart(64, '0');
  return `did:bolyra:${network}:${hex}`;
}

/**
 * Core verification function.
 * Takes pre-existing identity + credential and runs the handshake,
 * then maps the result to OpenClaw's TrustVerificationResult.
 */
export async function verifyAgent(
  human: HumanIdentity,
  credential: AgentCredential,
  config: BolyraOpenClawConfig = {},
): Promise<TrustVerificationResult> {
  const network = config.network ?? DEFAULT_CONFIG.network;
  const maxProofAge = config.maxProofAge ?? DEFAULT_CONFIG.maxProofAge;

  // Lazy-import SDK to avoid pulling heavy crypto deps at module load
  const sdk = await import('@bolyra/sdk');

  try {
    // Generate mutual handshake proofs
    const { humanProof, agentProof, nonce } = await sdk.proveHandshake(
      human,
      credential,
      { config: config.sdkConfig },
    );

    // Verify proofs locally
    const handshake = await sdk.verifyHandshake(
      humanProof,
      agentProof,
      nonce,
      config.sdkConfig,
    );

    // Score the result
    const { score, warnings } = computeTrustScore(
      handshake,
      credential,
      maxProofAge,
    );
    const grade = scoreToGrade(score);
    const did = buildDid(network, credential.commitment);

    return {
      verified: handshake.verified && score >= (config.minScore ?? DEFAULT_CONFIG.minScore),
      score,
      grade,
      did,
      warnings: warnings.length > 0 ? warnings : undefined,
    };
  } catch (err: any) {
    // Map SDK errors to a failed verification result
    return {
      verified: false,
      score: 0,
      grade: 'F',
      warnings: [`Verification error: ${err.message ?? String(err)}`],
    };
  }
}

/**
 * Create an OpenClaw plugin that uses Bolyra for trust verification.
 *
 * The plugin requires a human identity and a function to resolve agent credentials
 * from OpenClaw agent IDs. This allows the adapter to work with any credential
 * storage backend.
 *
 * @param human - The human operator's Bolyra identity
 * @param resolveCredential - Function to look up an AgentCredential by OpenClaw agent ID
 * @param config - Adapter configuration
 * @returns An OpenClaw-compatible plugin object
 *
 * @example
 * ```ts
 * import { createBolyraPlugin } from '@bolyra/openclaw';
 * import { createHumanIdentity, createAgentCredential } from '@bolyra/sdk';
 *
 * const human = await createHumanIdentity(mySecret);
 * const plugin = createBolyraPlugin(
 *   human,
 *   async (agentId) => agentRegistry.get(agentId),
 *   { network: 'base-sepolia' }
 * );
 *
 * // Register with OpenClaw
 * openclaw.use(plugin);
 * ```
 */
export function createBolyraPlugin(
  human: HumanIdentity,
  resolveCredential: (agentId: string) => Promise<AgentCredential | null>,
  config: BolyraOpenClawConfig = {},
): OpenClawPlugin {
  const cache = new Map<string, CacheEntry>();
  const maxProofAge = config.maxProofAge ?? DEFAULT_CONFIG.maxProofAge;

  return {
    async onAgentVerify(agentId: string): Promise<TrustVerificationResult> {
      // Check cache
      const cached = cache.get(agentId);
      if (cached) {
        const age = (Date.now() - cached.timestamp) / 1000;
        if (age < maxProofAge) {
          return cached.result;
        }
        cache.delete(agentId);
      }

      // Resolve the agent's Bolyra credential
      const credential = await resolveCredential(agentId);
      if (!credential) {
        return {
          verified: false,
          score: 0,
          grade: 'F',
          warnings: [`No Bolyra credential found for agent: ${agentId}`],
        };
      }

      // Run verification
      const result = await verifyAgent(human, credential, config);

      // Cache successful verifications
      if (result.verified) {
        cache.set(agentId, { result, timestamp: Date.now() });
      }

      return result;
    },
  };
}
