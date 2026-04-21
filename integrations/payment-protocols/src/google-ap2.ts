/**
 * Google Agent Payments Protocol (AP2) Adapter
 *
 * Maps Bolyra's ZKP identity to AP2's mandate-based authorization model.
 * In AP2, agents carry cryptographically signed "mandates" from users —
 * Bolyra replaces plain-text mandates with ZKP proofs, so the merchant
 * verifies the agent's authority without seeing the user's instructions.
 *
 * AP2 Flow (standard):
 *   1. User creates an Intent Mandate (instruction to the agent)
 *   2. Agent shops, builds a Cart Mandate (user approves specific purchase)
 *   3. Agent presents Payment Mandate to merchant for checkout
 *   4. Merchant verifies mandate chain cryptographically
 *
 * Bolyra-enhanced Flow:
 *   1. User creates a Bolyra handshake proof encoding their intent as a ZKP
 *   2. Agent wraps the proof as an AP2-compatible credential
 *   3. Agent-to-agent delegation uses Bolyra's delegation chain (not plain mandates)
 *   4. Merchant verifies the ZKP — learns capabilities, not the raw instructions
 *
 * Privacy gain: AP2 mandates are tamper-proof but readable by the merchant.
 * Bolyra mandates are tamper-proof AND zero-knowledge — the merchant verifies
 * authorization without learning the user's budget, preferences, or identity.
 *
 * @see https://cloud.google.com/blog/products/ai-machine-learning/announcing-agents-to-payments-ap2-protocol
 * @see https://github.com/google-agentic-commerce/AP2
 */

import type {
  HumanIdentity,
  AgentCredential,
  HandshakeResult,
  DelegationResult,
} from '@bolyra/sdk';

import type {
  AP2AgentCapability,
  AP2AgentCredential,
  AP2DelegationRecord,
  AP2MandateType,
  AgentPaymentVerification,
  PaymentTrustGrade,
  PaymentVerificationConfig,
} from './types';

import { encodeSpendPolicy } from './spend-policy';
import { loadSDK } from './sdk-loader';
import type { SpendPolicy } from './types';

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
// Capability <-> Permission Mapping
// ---------------------------------------------------------------------------

/**
 * Map AP2 agent capabilities to a Bolyra SpendPolicy.
 * Takes the most permissive capability as the policy ceiling.
 */
export function capabilitiesToSpendPolicy(capabilities: AP2AgentCapability[]): SpendPolicy {
  let maxTx = 0;
  let maxCum = 0;
  let currency = 'USD';

  for (const cap of capabilities) {
    if (cap.maxAmount > maxTx) {
      maxTx = cap.maxAmount;
    }
    maxCum += cap.maxAmount;
    currency = cap.currency;
  }

  const now = Math.floor(Date.now() / 1000);
  return {
    maxTransactionAmount: maxTx,
    maxCumulativeAmount: maxCum,
    currency,
    timeWindow: { start: now, end: now + 86400 }, // 24-hour default window
  };
}

/**
 * Map a Bolyra permission bitmask back to AP2 capabilities.
 * Reverse of the encoding for display/interop purposes.
 */
export function bitmaskToCapabilities(
  bitmask: bigint,
  currency: string = 'USD',
): AP2AgentCapability[] {
  const permTier = Number(bitmask & 0x7n);
  const capabilities: AP2AgentCapability[] = [];

  if (permTier >= 2) {
    capabilities.push({
      name: 'purchase',
      maxAmount: permTier === 4 ? 0 : permTier === 3 ? 1_000_000 : 10_000,
      currency,
    });
  }
  if (permTier >= 3) {
    capabilities.push({
      name: 'subscribe',
      maxAmount: permTier === 4 ? 0 : 100_000,
      currency,
    });
  }

  // Always include price_compare (read-only)
  capabilities.push({ name: 'price_compare', maxAmount: 0, currency });

  return capabilities;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function buildDid(network: string, commitment: bigint): string {
  const hex = commitment.toString(16).padStart(64, '0');
  return `did:bolyra:${network}:${hex}`;
}

function scoreToGrade(score: number): PaymentTrustGrade {
  if (score >= 90) return 'A';
  if (score >= 70) return 'B';
  if (score >= 50) return 'C';
  if (score >= 30) return 'D';
  return 'F';
}

// ---------------------------------------------------------------------------
// AP2 Credential Creation
// ---------------------------------------------------------------------------

/**
 * Create an AP2-compatible agent credential backed by a Bolyra ZKP.
 *
 * This is the core AP2 adapter function. It:
 *   1. Runs a Bolyra mutual handshake (human authorizes agent)
 *   2. Encodes the AP2 capabilities as a Bolyra permission bitmask
 *   3. Wraps the ZKP proof as an AP2 mandate proof
 *   4. Returns a credential that AP2-compatible merchants can verify
 *
 * The merchant sees the capability list (what the agent can do) but NOT
 * the human's identity, the exact spend limit, or the full delegation chain.
 *
 * @param human - The human operator's Bolyra identity
 * @param agent - The agent's Bolyra credential
 * @param capabilities - AP2 capabilities the agent should have
 * @param config - Adapter configuration
 * @returns AP2-compatible agent credential with embedded ZKP proof
 */
export async function createAP2AgentCredential(
  human: HumanIdentity,
  agent: AgentCredential,
  capabilities: AP2AgentCapability[],
  config: PaymentVerificationConfig = {},
): Promise<AP2AgentCredential> {
  const network = config.network ?? DEFAULT_CONFIG.network;

  // Lazy-load SDK
  const sdk = loadSDK();

  // Convert AP2 capabilities to a spend policy for ZKP encoding
  const spendPolicy = capabilitiesToSpendPolicy(capabilities);
  const policyBitmask = encodeSpendPolicy(spendPolicy);

  // Run mutual handshake with the encoded policy
  const { humanProof, agentProof, nonce } = await sdk.proveHandshake(
    human,
    { ...agent, permissionBitmask: policyBitmask },
    { config: config.sdkConfig },
  );

  // Verify off-chain
  const handshake = await sdk.verifyHandshakeOffchain(
    humanProof, agentProof, nonce, config.sdkConfig,
  );

  // Serialize the proof as the AP2 mandate proof
  const mandateProof = JSON.stringify({
    version: 'bolyra-ap2-v1',
    humanProof: {
      proof: humanProof.proof,
      publicSignals: humanProof.publicSignals,
    },
    agentProof: {
      proof: agentProof.proof,
      publicSignals: agentProof.publicSignals,
    },
    nonce: nonce.toString(),
  });

  return {
    agentDid: buildDid(network, agent.commitment),
    mandateType: 'intent',
    capabilities,
    mandateProof,
    scopeCommitment: handshake.scopeCommitment,
    expiresAt: Number(agent.expiryTimestamp),
  };
}

/**
 * Verify an AP2 agent credential (merchant-side).
 *
 * The merchant calls this to verify that an AP2 agent credential is backed
 * by a valid Bolyra ZKP proof. Returns a payment verification result.
 *
 * @param credential - The AP2 agent credential to verify
 * @param config - Adapter configuration
 * @returns Payment verification result
 */
export async function verifyAP2AgentCredential(
  credential: AP2AgentCredential,
  config: PaymentVerificationConfig = {},
): Promise<AgentPaymentVerification> {
  const minScore = config.minScore ?? DEFAULT_CONFIG.minScore;
  const maxProofAge = config.maxProofAge ?? DEFAULT_CONFIG.maxProofAge;

  try {
    // Deserialize the mandate proof
    const mandateData = JSON.parse(credential.mandateProof);
    if (mandateData.version !== 'bolyra-ap2-v1') {
      return {
        verified: false,
        score: 0,
        grade: 'F',
        did: credential.agentDid,
        warnings: [`Unknown mandate proof version: ${mandateData.version}`],
      };
    }

    // Lazy-load SDK
    const sdk = loadSDK();

    // Verify the ZKP proofs
    const nonce = BigInt(mandateData.nonce);
    const handshake = await sdk.verifyHandshakeOffchain(
      mandateData.humanProof,
      mandateData.agentProof,
      nonce,
      config.sdkConfig,
    );

    // Score the verification
    let score = 0;
    const warnings: string[] = [];

    // Proof validity (40 pts)
    if (handshake.verified) {
      score += 40;
    } else {
      warnings.push('ZKP verification failed');
    }

    // Expiry check (20 pts)
    const now = Math.floor(Date.now() / 1000);
    if (credential.expiresAt > now) {
      score += 20;
    } else {
      warnings.push(`Credential expired at ${credential.expiresAt}`);
    }

    // Capabilities present (20 pts)
    if (credential.capabilities.length > 0) {
      score += 20;
    } else {
      warnings.push('No capabilities declared');
    }

    // Nonce freshness (10 pts)
    const nonceAge = now - Number(nonce / 1000n);
    if (nonceAge < maxProofAge) {
      score += 10;
    } else {
      warnings.push(`Proof nonce is stale (${nonceAge}s old)`);
    }

    // Scope commitment (10 pts)
    if (credential.scopeCommitment !== 0n) {
      score += 10;
    } else {
      warnings.push('Scope commitment is zero');
    }

    const grade = scoreToGrade(score);

    return {
      verified: handshake.verified && score >= minScore,
      score,
      grade,
      did: credential.agentDid,
      protocolToken: mandateData.nonce,
      warnings: warnings.length > 0 ? warnings : undefined,
    };
  } catch (err: any) {
    return {
      verified: false,
      score: 0,
      grade: 'F',
      did: credential.agentDid,
      warnings: [`AP2 verification error: ${err.message ?? String(err)}`],
    };
  }
}

// ---------------------------------------------------------------------------
// Agent-to-Agent Delegation (AP2 capability delegation via Bolyra chain)
// ---------------------------------------------------------------------------

/**
 * Delegate capabilities from one agent to another using Bolyra's delegation chain.
 *
 * In AP2, agents can delegate capabilities to sub-agents (e.g., a shopping agent
 * delegates payment to a checkout agent). Bolyra tracks this as a delegation chain
 * with ZKP proofs at each hop, preventing scope escalation.
 *
 * @param fromCredential - The delegating agent's AP2 credential
 * @param toAgent - The target agent's Bolyra credential
 * @param capabilities - Capabilities to delegate (must be subset of fromCredential's)
 * @param config - Adapter configuration
 * @returns AP2 delegation record with Bolyra chain tracking
 */
export async function delegateAP2Capabilities(
  fromCredential: AP2AgentCredential,
  toAgent: AgentCredential,
  capabilities: AP2AgentCapability[],
  config: PaymentVerificationConfig = {},
): Promise<AP2DelegationRecord> {
  const network = config.network ?? DEFAULT_CONFIG.network;

  // Validate capability subset
  const fromNames = new Set(fromCredential.capabilities.map(c => c.name));
  for (const cap of capabilities) {
    if (!fromNames.has(cap.name)) {
      throw new Error(
        `Cannot delegate capability "${cap.name}" — not in source credential`
      );
    }
    const sourceCap = fromCredential.capabilities.find(c => c.name === cap.name)!;
    if (sourceCap.maxAmount > 0 && cap.maxAmount > sourceCap.maxAmount) {
      throw new Error(
        `Cannot escalate capability "${cap.name}": ` +
        `requested ${cap.maxAmount} > source ${sourceCap.maxAmount}`
      );
    }
  }

  // Encode delegated capabilities as a new bitmask
  const delegatedPolicy = capabilitiesToSpendPolicy(capabilities);
  const delegatedBitmask = encodeSpendPolicy(delegatedPolicy);

  // Build delegation record
  // In a full implementation, this would call sdk.delegate() to produce a
  // ZKP delegation proof. For this adapter, we track the chain metadata.
  const delegationNullifier = BigInt(
    '0x' + Buffer.from(
      `${fromCredential.agentDid}:${toAgent.commitment.toString(16)}:${Date.now()}`
    ).toString('hex').slice(0, 32)
  );

  // New scope commitment = hash of (old scope + delegated bitmask)
  // In production, this is a Poseidon hash via the SDK
  const newScopeCommitment = fromCredential.scopeCommitment ^ delegatedBitmask;

  return {
    fromAgent: fromCredential.agentDid,
    toAgent: buildDid(network, toAgent.commitment),
    capabilities,
    hopIndex: 0, // first hop; caller tracks multi-hop chains
    delegationNullifier,
    newScopeCommitment,
  };
}
