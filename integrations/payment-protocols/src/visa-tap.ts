/**
 * Visa Trusted Agent Protocol (TAP) Adapter
 *
 * Maps Bolyra's ZKP mutual handshake to Visa TAP's trust verification flow.
 * Instead of relying on Visa's centralized registry to vouch for an agent,
 * the agent proves — via zero-knowledge — that a human has authorized it
 * with a specific spend policy, without revealing the policy graph.
 *
 * TAP Flow (standard):
 *   1. Agent signs HTTP request with cryptographic key (RFC 9421)
 *   2. Merchant verifies signature against Visa's agent registry
 *   3. Visa's Payment Signals API matches agent request to consumer instructions
 *
 * Bolyra-enhanced Flow:
 *   1. Agent presents a ZKP proof of human authorization + spend policy
 *   2. Merchant verifies the proof locally (no Visa registry lookup needed)
 *   3. The payment signal includes the ZKP scope commitment for audit trail
 *
 * Privacy gain: the merchant learns "this agent is authorized to spend up to
 * tier X in category Y" without learning the exact limit, the human's identity,
 * or the full policy graph.
 *
 * @see https://developer.visa.com/capabilities/trusted-agent-protocol
 * @see https://github.com/visa/trusted-agent-protocol
 */

import type {
  HumanIdentity,
  AgentCredential,
  HandshakeResult,
} from '@bolyra/sdk';

import type {
  SpendPolicy,
  TAPVerificationRequest,
  TAPVerificationResult,
  PaymentTrustGrade,
  PaymentVerificationConfig,
} from './types';

import { encodeSpendPolicy, verifySpendPolicyProof } from './spend-policy';
import { loadSDK } from './sdk-loader';

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

const DEFAULT_CONFIG: Required<Omit<PaymentVerificationConfig, 'sdkConfig' | 'registryAddress'>> & { registryAddress: string } = {
  network: 'base-sepolia',
  registryAddress: '0x0000000000000000000000000000000000000000',
  minScore: 70,
  maxProofAge: 120,
  offchainByDefault: true,
};

// ---------------------------------------------------------------------------
// Trust Scoring (TAP-specific)
// ---------------------------------------------------------------------------

/**
 * Compute a TAP trust score (0-100) from a Bolyra handshake result and
 * the requested transaction.
 *
 * Scoring:
 *   - 35 pts: Both ZKP proofs valid (human + agent)
 *   - 25 pts: Spend policy covers the requested transaction
 *   - 15 pts: Credential not expired
 *   - 15 pts: Session nonce is fresh (within maxProofAge)
 *   - 10 pts: Scope commitment is non-zero (delegation chain active)
 */
export function computeTAPScore(
  handshake: HandshakeResult,
  credential: AgentCredential,
  spendPolicy: SpendPolicy,
  request: TAPVerificationRequest,
  maxProofAge: number,
): { score: number; warnings: string[] } {
  let score = 0;
  const warnings: string[] = [];

  // Proof validity (35 pts)
  if (handshake.verified) {
    score += 35;
  } else {
    warnings.push('ZKP verification failed — proofs are invalid');
  }

  // Spend policy coverage (25 pts)
  const policyBitmask = encodeSpendPolicy(spendPolicy);
  const policyCheck = verifySpendPolicyProof(policyBitmask, {
    minTransactionAmount: request.amount,
    requiredMCCs: request.mcc ? [request.mcc] : undefined,
  });
  if (policyCheck.satisfied) {
    score += 25;
  } else {
    warnings.push(`Spend policy insufficient: ${policyCheck.reasons.join('; ')}`);
  }

  // Credential expiry (15 pts)
  const now = BigInt(Math.floor(Date.now() / 1000));
  if (credential.expiryTimestamp > now) {
    score += 15;
  } else {
    warnings.push(
      `Agent credential expired at ${credential.expiryTimestamp} (current: ${now})`
    );
  }

  // Nonce freshness (15 pts)
  const nonceAge = Number(now - handshake.sessionNonce / 1000n);
  if (nonceAge < maxProofAge) {
    score += 15;
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

/** Map numeric score to a grade */
function scoreToGrade(score: number): PaymentTrustGrade {
  if (score >= 90) return 'A';
  if (score >= 70) return 'B';
  if (score >= 50) return 'C';
  if (score >= 30) return 'D';
  return 'F';
}

/** Construct a did:bolyra DID from network + commitment */
function buildDid(network: string, commitment: bigint): string {
  const hex = commitment.toString(16).padStart(64, '0');
  return `did:bolyra:${network}:${hex}`;
}

// ---------------------------------------------------------------------------
// Cache
// ---------------------------------------------------------------------------

interface CacheEntry {
  result: TAPVerificationResult;
  timestamp: number;
}

// ---------------------------------------------------------------------------
// Core Verification
// ---------------------------------------------------------------------------

/**
 * Generate a TAP-compatible ZKP verification for an agent transaction.
 *
 * This is the primary entry point for the Visa TAP adapter. It:
 *   1. Runs a Bolyra mutual handshake (human proves they authorized the agent)
 *   2. Encodes the spend policy into the ZKP bitmask
 *   3. Verifies the proof (off-chain by default for high-throughput commerce)
 *   4. Maps the result to TAP's trust verification format
 *
 * @param human - The human operator's Bolyra identity
 * @param agent - The agent's Bolyra credential
 * @param spendPolicy - The human's spend policy for this agent
 * @param request - The TAP verification request (merchant + transaction details)
 * @param config - Adapter configuration
 * @returns TAP verification result with trust score and payment signal
 */
export async function createVisaTAPVerification(
  human: HumanIdentity,
  agent: AgentCredential,
  spendPolicy: SpendPolicy,
  request: TAPVerificationRequest,
  config: PaymentVerificationConfig = {},
): Promise<TAPVerificationResult> {
  const network = config.network ?? DEFAULT_CONFIG.network;
  const maxProofAge = config.maxProofAge ?? DEFAULT_CONFIG.maxProofAge;
  const minScore = config.minScore ?? DEFAULT_CONFIG.minScore;
  const useBatch = config.offchainByDefault ?? DEFAULT_CONFIG.offchainByDefault;

  // Lazy-load SDK to avoid pulling heavy crypto deps at module load
  const sdk = loadSDK();

  try {
    // Step 1: Generate mutual handshake proofs
    const policyBitmask = encodeSpendPolicy(spendPolicy);
    const { humanProof, agentProof, nonce } = await sdk.proveHandshake(
      human,
      { ...agent, permissionBitmask: policyBitmask },
      { scope: BigInt(request.transactionId.length), config: config.sdkConfig },
    );

    // Step 2: Verify (off-chain by default for high-throughput)
    let handshake: HandshakeResult;
    if (useBatch) {
      handshake = await sdk.verifyHandshakeOffchain(
        humanProof, agentProof, nonce, config.sdkConfig,
      );
    } else {
      handshake = await sdk.verifyHandshake(
        humanProof, agentProof, nonce, config.sdkConfig,
      );
    }

    // Step 3: Score
    const { score, warnings } = computeTAPScore(
      handshake, agent, spendPolicy, request, maxProofAge,
    );
    const grade = scoreToGrade(score);
    const did = buildDid(network, agent.commitment);

    // Step 4: Build TAP payment signal (opaque token for Visa's Payment Signals API)
    const paymentSignal = [
      'bolyra-tap-v1',
      handshake.scopeCommitment.toString(16),
      handshake.agentNullifier.toString(16),
      request.transactionId,
    ].join(':');

    return {
      verified: handshake.verified && score >= minScore,
      score,
      grade,
      did,
      protocolToken: paymentSignal,
      warnings: warnings.length > 0 ? warnings : undefined,
      paymentSignal,
      batchMode: useBatch,
      scopeCommitment: handshake.scopeCommitment,
    };
  } catch (err: any) {
    return {
      verified: false,
      score: 0,
      grade: 'F',
      did: buildDid(network, agent.commitment),
      warnings: [`TAP verification error: ${err.message ?? String(err)}`],
      batchMode: useBatch,
      scopeCommitment: 0n,
    };
  }
}

/**
 * Create a cached TAP verifier — reuses verification results within maxProofAge.
 *
 * For high-throughput merchant integrations where the same agent makes
 * multiple purchases within a short window.
 *
 * @param human - The human operator's identity
 * @param resolveCredential - Resolves agent DID to Bolyra credential + spend policy
 * @param config - Adapter configuration
 * @returns A function that verifies TAP requests with caching
 */
export function createCachedTAPVerifier(
  human: HumanIdentity,
  resolveCredential: (agentDid: string) => Promise<{
    credential: AgentCredential;
    spendPolicy: SpendPolicy;
  } | null>,
  config: PaymentVerificationConfig = {},
): (request: TAPVerificationRequest) => Promise<TAPVerificationResult> {
  const cache = new Map<string, CacheEntry>();
  const maxProofAge = config.maxProofAge ?? DEFAULT_CONFIG.maxProofAge;
  const network = config.network ?? DEFAULT_CONFIG.network;

  return async (request: TAPVerificationRequest): Promise<TAPVerificationResult> => {
    // Check cache
    const cacheKey = `${request.agentDid}:${request.merchantId}`;
    const cached = cache.get(cacheKey);
    if (cached) {
      const age = (Date.now() - cached.timestamp) / 1000;
      if (age < maxProofAge) {
        return cached.result;
      }
      cache.delete(cacheKey);
    }

    // Resolve credential
    const resolved = await resolveCredential(request.agentDid);
    if (!resolved) {
      return {
        verified: false,
        score: 0,
        grade: 'F',
        did: request.agentDid,
        warnings: [`No Bolyra credential found for agent: ${request.agentDid}`],
        batchMode: config.offchainByDefault ?? true,
        scopeCommitment: 0n,
      };
    }

    // Run verification
    const result = await createVisaTAPVerification(
      human, resolved.credential, resolved.spendPolicy, request, config,
    );

    // Cache successful results
    if (result.verified) {
      cache.set(cacheKey, { result, timestamp: Date.now() });
    }

    return result;
  };
}
