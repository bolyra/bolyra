/**
 * Autonomous Agent Identity
 *
 * An agent that owns its own keypair and carries a Bolyra credential.
 * The credential defines what the agent is authorized to do:
 * - Permission bitmask (READ_DATA, WRITE_DATA, FINANCIAL_SMALL, etc.)
 * - Spend limits (per-request, daily cap)
 * - Allowed assets and networks
 * - Expiry
 *
 * The agent can prove its authorization without exposing the underlying
 * private key or credential details — only the proof and receipt are shared.
 */

import * as crypto from 'crypto';

// Permission bits (cumulative — higher tiers imply lower)
export const PERMISSIONS = {
  READ_DATA: 0,
  WRITE_DATA: 1,
  FINANCIAL_SMALL: 2,    // < $100
  FINANCIAL_MEDIUM: 3,   // < $10K (implies bit 2)
  FINANCIAL_UNLIMITED: 4, // implies 2+3
  SIGN_ON_BEHALF: 5,
  SUB_DELEGATE: 6,
  ACCESS_PII: 7,
} as const;

export interface AgentCredential {
  agentDid: string;
  publicKey: string;
  permissionBitmask: number;
  maxPerRequest: number;    // cents
  dailyCap: number;         // cents
  allowedAssets: string[];
  allowedNetworks: string[];
  issuedAt: string;
  expiresAt: string;
  issuer: string;           // human/org DID that delegated authority
  signature: string;        // issuer's signature over the credential
}

export interface AgentKeypair {
  publicKey: string;
  privateKey: string;
}

/**
 * Generate a new agent keypair.
 * In production this would be Ed25519 or secp256k1.
 * For the demo we use a deterministic hash-based keypair.
 */
export function generateAgentKeypair(seed?: string): AgentKeypair {
  const s = seed ?? crypto.randomBytes(32).toString('hex');
  const privateKey = crypto.createHash('sha256').update(s).digest('hex');
  const publicKey = crypto.createHash('sha256').update(privateKey).digest('hex').slice(0, 40);
  return { publicKey, privateKey };
}

/**
 * Derive a DID from an agent's public key.
 */
export function deriveAgentDid(publicKey: string, network: string = 'base-sepolia'): string {
  return `did:bolyra:${network}:0x${publicKey}`;
}

/**
 * Compute permission bitmask from a list of permission names.
 * Enforces cumulative implication rules.
 */
export function computeBitmask(permissions: (keyof typeof PERMISSIONS)[]): number {
  let mask = 0;
  for (const p of permissions) {
    mask |= (1 << PERMISSIONS[p]);
  }
  // Enforce cumulative implications
  if (mask & (1 << PERMISSIONS.FINANCIAL_UNLIMITED)) {
    mask |= (1 << PERMISSIONS.FINANCIAL_MEDIUM) | (1 << PERMISSIONS.FINANCIAL_SMALL);
  }
  if (mask & (1 << PERMISSIONS.FINANCIAL_MEDIUM)) {
    mask |= (1 << PERMISSIONS.FINANCIAL_SMALL);
  }
  return mask;
}

/**
 * Check if a bitmask includes a specific permission.
 */
export function hasPermission(bitmask: number, permission: keyof typeof PERMISSIONS): boolean {
  return (bitmask & (1 << PERMISSIONS[permission])) !== 0;
}

/**
 * Issue a credential from a human/org to an agent.
 * In production this would involve ZKP proof generation.
 */
export function issueCredential(opts: {
  agentKeypair: AgentKeypair;
  permissions: (keyof typeof PERMISSIONS)[];
  maxPerRequest: number;
  dailyCap: number;
  allowedAssets: string[];
  allowedNetworks: string[];
  expiresInHours: number;
  issuerDid: string;
}): AgentCredential {
  const agentDid = deriveAgentDid(opts.agentKeypair.publicKey, opts.allowedNetworks[0] ?? 'base-sepolia');
  const bitmask = computeBitmask(opts.permissions);
  const issuedAt = new Date().toISOString();
  const expiresAt = new Date(Date.now() + opts.expiresInHours * 3600_000).toISOString();

  // Sign the credential (mock — in production this is EdDSA over the credential hash)
  const credentialData = `${agentDid}|${bitmask}|${opts.maxPerRequest}|${opts.dailyCap}|${expiresAt}`;
  const signature = crypto.createHmac('sha256', 'issuer-secret')
    .update(credentialData).digest('hex');

  return {
    agentDid,
    publicKey: opts.agentKeypair.publicKey,
    permissionBitmask: bitmask,
    maxPerRequest: opts.maxPerRequest,
    dailyCap: opts.dailyCap,
    allowedAssets: opts.allowedAssets,
    allowedNetworks: opts.allowedNetworks,
    issuedAt,
    expiresAt,
    issuer: opts.issuerDid,
    signature,
  };
}

/**
 * Verify a credential is valid (not expired, signature checks out).
 */
export function verifyCredential(cred: AgentCredential): { valid: boolean; reason?: string } {
  // Check expiry
  if (new Date() > new Date(cred.expiresAt)) {
    return { valid: false, reason: 'credential expired' };
  }

  // Verify signature
  const credentialData = `${cred.agentDid}|${cred.permissionBitmask}|${cred.maxPerRequest}|${cred.dailyCap}|${cred.expiresAt}`;
  const expectedSig = crypto.createHmac('sha256', 'issuer-secret')
    .update(credentialData).digest('hex');

  if (cred.signature !== expectedSig) {
    return { valid: false, reason: 'invalid signature' };
  }

  return { valid: true };
}

/**
 * Format a bitmask as human-readable permission list.
 */
export function formatPermissions(bitmask: number): string[] {
  const perms: string[] = [];
  for (const [name, bit] of Object.entries(PERMISSIONS)) {
    if (bitmask & (1 << bit)) {
      perms.push(name);
    }
  }
  return perms;
}
