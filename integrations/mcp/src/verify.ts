/**
 * Shared verification logic — used by both stdio and HTTP wrappers.
 * Lazy-imports @bolyra/sdk to avoid pulling crypto deps at module load.
 */

import type {
  BolyraProofBundle,
  BolyraAuthContext,
  BolyraMcpConfig,
} from './types';

const DEFAULTS = {
  network: 'base-sepolia',
  minScore: 70,
  maxProofAge: 300,
};

/** Decimal-string → bigint, with NaN guard. */
function toBigInt(value: string, field: string): bigint {
  if (!/^\d+$/.test(value)) {
    throw new Error(`Bolyra: invalid ${field} (expected decimal string, got "${value}")`);
  }
  return BigInt(value);
}

function buildDid(network: string, commitment: bigint): string {
  const hex = commitment.toString(16).padStart(64, '0');
  return `did:bolyra:${network}:${hex}`;
}

/**
 * Verify a Bolyra proof bundle against the configured registry and produce a
 * BolyraAuthContext. Never throws — failure is reported via `verified=false`
 * and `reason`, so the caller can return a structured MCP error instead of
 * blowing up the request.
 */
export async function verifyBundle(
  bundle: BolyraProofBundle,
  config: BolyraMcpConfig,
): Promise<BolyraAuthContext> {
  const network = config.network ?? DEFAULTS.network;
  const minScore = config.minScore ?? DEFAULTS.minScore;
  const maxProofAge = config.maxProofAge ?? DEFAULTS.maxProofAge;

  // Bundle shape sanity
  if (bundle.v !== 1) {
    return {
      verified: false,
      score: 0,
      did: '',
      permissionBitmask: 0n,
      warnings: [],
      reason: `Unsupported bundle version: ${bundle.v}`,
    };
  }

  let nonce: bigint;
  let commitment: bigint;
  try {
    nonce = toBigInt(bundle.nonce, 'nonce');
    commitment = toBigInt(bundle.credentialCommitment, 'credentialCommitment');
  } catch (e: unknown) {
    return {
      verified: false,
      score: 0,
      did: '',
      permissionBitmask: 0n,
      warnings: [],
      reason: e instanceof Error ? e.message : String(e),
    };
  }

  // Look up the credential the bundle is claiming to authenticate as.
  const credential = await config.resolveCredential(bundle.credentialCommitment);
  if (!credential) {
    return {
      verified: false,
      score: 0,
      did: buildDid(network, commitment),
      permissionBitmask: 0n,
      warnings: [],
      reason: `No credential found for commitment ${bundle.credentialCommitment}`,
    };
  }

  // Run the actual ZKP verification.
  const sdk = await import('@bolyra/sdk');
  let verifyResult: Awaited<ReturnType<typeof sdk.verifyHandshake>>;
  try {
    verifyResult = await sdk.verifyHandshake(
      bundle.humanProof,
      bundle.agentProof,
      nonce,
      config.sdkConfig,
    );
  } catch (e: unknown) {
    return {
      verified: false,
      score: 0,
      did: buildDid(network, commitment),
      permissionBitmask: credential.permissionBitmask,
      warnings: [],
      reason: `Proof verification threw: ${e instanceof Error ? e.message : String(e)}`,
    };
  }

  // Score the result. Same shape as @bolyra/openclaw for consistency.
  const warnings: string[] = [];
  let score = 0;

  if (verifyResult.verified) {
    score += 40;
  } else {
    warnings.push('ZKP verification failed — proofs are invalid');
  }

  const now = BigInt(Math.floor(Date.now() / 1000));
  if (credential.expiryTimestamp > now) {
    score += 20;
  } else {
    warnings.push(`Credential expired at ${credential.expiryTimestamp} (current: ${now})`);
  }

  const hasBasicPermissions = (credential.permissionBitmask & 0b11n) !== 0n;
  if (hasBasicPermissions) {
    score += 20;
  } else {
    warnings.push('Agent has no read/write permissions');
  }

  // Nonce is unix-seconds; sessionNonce on the verified result mirrors what
  // was bound into the proof. Stale nonce → fail freshness check.
  const nonceAgeSec = Number(now - nonce);
  if (nonceAgeSec >= 0 && nonceAgeSec < maxProofAge) {
    score += 10;
  } else {
    warnings.push(`Session nonce stale (${nonceAgeSec}s old, max ${maxProofAge}s)`);
  }

  if (verifyResult.scopeCommitment !== 0n) {
    score += 10;
  } else {
    warnings.push('Scope commitment is zero — delegation chain not initialized');
  }

  const passed = verifyResult.verified && score >= minScore;
  return {
    verified: passed,
    score,
    did: buildDid(network, commitment),
    permissionBitmask: credential.permissionBitmask,
    warnings,
    reason: passed
      ? undefined
      : warnings[0] ?? 'Verification failed for unknown reason',
  };
}

/** Per-tool permission gate. Returns null if allowed, error string if denied. */
export function checkToolPolicy(
  toolName: string,
  authCtx: BolyraAuthContext,
  config: BolyraMcpConfig,
): string | null {
  const required = config.toolPolicy?.[toolName];
  if (required === undefined) return null;
  // AND-cover: every required bit must be set in the granted bitmask.
  if ((authCtx.permissionBitmask & required) !== required) {
    return `Tool "${toolName}" requires permissions ${required.toString(2)}b, agent has ${authCtx.permissionBitmask.toString(2)}b`;
  }
  return null;
}
