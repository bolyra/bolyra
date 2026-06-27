/**
 * Delegation setup for Base Agent Wallet.
 *
 * Creates a human identity and a scope-narrowed agent credential
 * using the Bolyra SDK. Returns the wallet policy that the
 * BaseAgentWallet enforces at runtime.
 */

import {
  createHumanIdentity,
  createAgentCredential,
  permissionsToBitmask,
  Permission,
} from '@bolyra/sdk';
import type { HumanIdentity, AgentCredential } from '@bolyra/sdk';

export interface WalletPolicy {
  maxPerRequest: number;    // cents
  dailyCap: number;         // cents
  allowedAssets: string[];
  allowedNetworks: string[];
  agentDid: string;
  expiresAt?: string;       // ISO timestamp
}

export interface DelegationConfig {
  /** Permissions to grant the agent (scope-narrowed from human's full set). */
  permissions: Permission[];
  /** Per-request spending cap in cents. */
  maxPerRequest: number;
  /** Daily spending cap in cents. */
  dailyCap: number;
  /** Allowed payment assets (e.g., ['USDC']). */
  allowedAssets: string[];
  /** Allowed networks (e.g., ['base', 'base-sepolia']). */
  allowedNetworks: string[];
  /** Optional expiry as ISO timestamp string. */
  expiresAt?: string;
}

export interface DelegationSetup {
  humanIdentity: HumanIdentity;
  agentCredential: AgentCredential;
  walletPolicy: WalletPolicy;
}

// Fixed dev seeds for demo purposes — NEVER use in production
const DEV_SECRET = BigInt('0xBA5EA6E4700000000000000000000001');
const DEV_MODEL_HASH = BigInt('0xBA5EA6E4700000000000000000000002');
const DEV_OPERATOR_KEY: Buffer = Buffer.from([
  0xba, 0x5e, 0xa6, 0xe4, 0x70, 0x00, 0x00, 0x01,
  0xba, 0x5e, 0xa6, 0xe4, 0x70, 0x00, 0x00, 0x02,
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
]);

// Far-future expiry for dev fixtures
const DEV_EXPIRY = BigInt(Math.floor(Date.now() / 1000) + 365 * 24 * 3600);

/**
 * Set up a delegation from a human to an AI agent with the given permissions
 * and spending policy. Uses dev-mode seeds for demo purposes.
 */
export async function setupDelegation(config: DelegationConfig): Promise<DelegationSetup> {
  const humanIdentity = await createHumanIdentity(DEV_SECRET);

  const agentCredential = await createAgentCredential(
    DEV_MODEL_HASH,
    DEV_OPERATOR_KEY,
    config.permissions,
    DEV_EXPIRY,
  );

  // Derive a deterministic DID from the agent commitment
  const agentDid = `did:bolyra:${agentCredential.commitment.toString(16).slice(0, 16)}`;

  const walletPolicy: WalletPolicy = {
    maxPerRequest: config.maxPerRequest,
    dailyCap: config.dailyCap,
    allowedAssets: config.allowedAssets,
    allowedNetworks: config.allowedNetworks,
    agentDid,
    expiresAt: config.expiresAt,
  };

  return { humanIdentity, agentCredential, walletPolicy };
}
