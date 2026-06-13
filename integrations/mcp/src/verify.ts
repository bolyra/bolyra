/**
 * Shared verification logic — used by both stdio and HTTP wrappers.
 * Lazy-imports @bolyra/sdk and @bolyra/receipts to avoid pulling crypto
 * deps (ESM-only @noble/*) at module load time.
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

/** Build a failed BolyraAuthContext with a reason string (DRY helper). */
function failCtx(reason: string): BolyraAuthContext {
  return {
    verified: false,
    score: 0,
    did: '',
    permissionBitmask: 0n,
    warnings: [],
    reason,
    chainDepth: 0,
    effectiveCommitment: '',
  };
}

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
  // Dev mode: skip real ZKP verification
  if (config.devMode) {
    if (!bundle._dev) {
      return failCtx('Dev server received non-dev bundle. Client must set devMode: true.');
    }
    return verifyDevBundle(bundle, config);
  }

  // Production mode: reject dev bundles
  if (bundle._dev) {
    return failCtx('Production server received dev bundle. Remove _dev from client.');
  }

  // Production mode: require resolveCredential
  if (!config.resolveCredential) {
    throw new Error(
      '@bolyra/mcp: resolveCredential is required in production mode. ' +
      'Set devMode: true for testing without a credential registry.',
    );
  }

  const network = config.network ?? DEFAULTS.network;
  const minScore = config.minScore ?? DEFAULTS.minScore;
  const maxProofAge = config.maxProofAge ?? DEFAULTS.maxProofAge;

  // Bundle shape sanity
  if (bundle.v !== 1 && bundle.v !== 2) {
    return {
      verified: false,
      score: 0,
      did: '',
      permissionBitmask: 0n,
      warnings: [],
      reason: `Unsupported bundle version: ${bundle.v}`,
      chainDepth: 0,
      effectiveCommitment: '',
    };
  }
  if (bundle.v === 1 && bundle.delegationChain && bundle.delegationChain.length > 0) {
    return {
      verified: false,
      score: 0,
      did: '',
      permissionBitmask: 0n,
      warnings: [],
      reason: 'Bundle v=1 cannot carry a delegationChain. Use v=2.',
      chainDepth: 0,
      effectiveCommitment: '',
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
      chainDepth: 0,
      effectiveCommitment: '',
    };
  }

  // Look up the credential the bundle is claiming to authenticate as.
  // resolveCredential is guaranteed non-null here — the guard above throws if missing.
  const credential = await config.resolveCredential!(bundle.credentialCommitment);
  if (!credential) {
    return {
      verified: false,
      score: 0,
      did: buildDid(network, commitment),
      permissionBitmask: 0n,
      warnings: [],
      reason: `No credential found for commitment ${bundle.credentialCommitment}`,
      chainDepth: 0,
      effectiveCommitment: bundle.credentialCommitment,
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
      chainDepth: 0,
      effectiveCommitment: bundle.credentialCommitment,
    };
  }

  // Validate Merkle roots if validator is configured
  if (config.validateRoots) {
    const humanRoot = BigInt(bundle.humanProof.publicSignals[0]);
    const agentRoot = BigInt(bundle.agentProof.publicSignals[0]);
    const rootsValid = await config.validateRoots(humanRoot, agentRoot);
    if (!rootsValid) {
      return {
        verified: false,
        score: 0,
        did: buildDid(network, commitment),
        permissionBitmask: 0n,
        warnings: ['Merkle roots not recognized by the registry — proof may be against a private tree'],
        reason: 'Human or agent Merkle root validation failed',
        chainDepth: 0,
        effectiveCommitment: bundle.credentialCommitment,
      };
    }
  }

  // Nonce replay check
  if (config.nonceStore) {
    const isFresh = await config.nonceStore.markIfFresh(bundle.nonce, maxProofAge);
    if (!isFresh) {
      return failCtx('Nonce already used — proof replay rejected');
    }
  }

  // Bind proof to claimed credential: recompute scopeCommitment from the
  // resolved credential and compare to the proof's output. Without this an
  // attacker can generate a valid proof for credential A (attacker-owned),
  // set bundle.credentialCommitment to credential B (privileged), and the
  // server would resolve B, verify the proof (valid for A), and grant B's
  // permissions.
  const expectedScope = await sdk.poseidon3(
    credential.permissionBitmask,
    credential.commitment,
    credential.expiryTimestamp,
  );
  if (expectedScope !== verifyResult.scopeCommitment) {
    return {
      verified: false,
      score: 0,
      did: buildDid(network, commitment),
      permissionBitmask: 0n,
      warnings: ['Proof scopeCommitment does not match resolved credential — possible credential substitution attack'],
      reason: 'Proof is not bound to the claimed credential',
      chainDepth: 0,
      effectiveCommitment: bundle.credentialCommitment,
    };
  }

  // Enforce max delegation chain depth — mirrors IdentityRegistry.sol MAX_DELEGATION_HOPS=3.
  // Without this an attacker can submit 100+ hops for CPU exhaustion or to exploit
  // logic bugs in deep chains, since the contract never sees the off-chain bundle.
  const MAX_DELEGATION_HOPS = 3;
  if (bundle.delegationChain && bundle.delegationChain.length > MAX_DELEGATION_HOPS) {
    return {
      verified: false,
      score: 0,
      did: buildDid(network, commitment),
      permissionBitmask: 0n,
      warnings: [`Delegation chain exceeds max hops (${bundle.delegationChain.length} > ${MAX_DELEGATION_HOPS})`],
      reason: `Delegation chain too deep (max ${MAX_DELEGATION_HOPS} hops)`,
      chainDepth: 0,
      effectiveCommitment: bundle.credentialCommitment,
    };
  }

  // Walk the delegation chain (if present). Each hop must:
  //   1. Bind prev = handshake.scopeCommitment (hop 0) or prior hop's newScopeCommitment.
  //   2. Pass sdk.verifyDelegation — Groth16 verify + prev/nonce/currentTs binding.
  //   3. Recompute Poseidon3(scope, commitment, expiry) and match publicSignals[0].
  // On any failure we bail out with verified=false; warnings collect partial state.
  const chainWarnings: string[] = [];
  let chainOk = true;
  let chainPermissionBitmask = credential.permissionBitmask;
  let effectiveCommitment = bundle.credentialCommitment;
  let chainDepth = 0;
  if (bundle.delegationChain && bundle.delegationChain.length > 0) {
    let expectedPrev = verifyResult.scopeCommitment;
    for (let i = 0; i < bundle.delegationChain.length; i++) {
      const link = bundle.delegationChain[i];
      let dScope: bigint;
      let dCommit: bigint;
      let dExpiry: bigint;
      let dTs: bigint;
      try {
        dScope = toBigInt(link.delegateeScope, `delegationChain[${i}].delegateeScope`);
        dCommit = toBigInt(link.delegateeCommitment, `delegationChain[${i}].delegateeCommitment`);
        dExpiry = toBigInt(link.delegateeExpiry, `delegationChain[${i}].delegateeExpiry`);
        dTs = toBigInt(link.currentTimestamp, `delegationChain[${i}].currentTimestamp`);
      } catch (e: unknown) {
        chainOk = false;
        chainWarnings.push(e instanceof Error ? e.message : String(e));
        break;
      }
      try {
        await sdk.verifyDelegation(link.proof, expectedPrev, nonce, dTs, config.sdkConfig);
      } catch (e: unknown) {
        chainOk = false;
        chainWarnings.push(
          `delegationChain[${i}] verification failed: ${e instanceof Error ? e.message : String(e)}`,
        );
        break;
      }
      // Recompute newScopeCommitment = Poseidon3(scope, commitment, expiry) and
      // confirm the proof's public output matches. This is what binds (scope,
      // commitment, expiry) to the chain — without it a forged proof could
      // claim any (scope, commitment, expiry) tuple.
      const expectedNew = await sdk.poseidon3(dScope, dCommit, dExpiry);
      const proofNew = BigInt(link.proof.publicSignals[0]);
      if (expectedNew !== proofNew) {
        chainOk = false;
        chainWarnings.push(
          `delegationChain[${i}] newScopeCommitment mismatch: Poseidon3(scope, commitment, expiry)=${expectedNew}, proof bound ${proofNew}`,
        );
        break;
      }
      // Expiry guard — circuit binds currentTimestamp but does not enforce it
      // is < delegateeExpiry off-chain. Reject expired hops here so a leaked
      // delegation cannot be replayed past its window.
      if (dExpiry <= dTs) {
        chainOk = false;
        chainWarnings.push(`delegationChain[${i}] expired (expiry ${dExpiry} <= ts ${dTs})`);
        break;
      }
      chainDepth = i + 1;
      chainPermissionBitmask = dScope;
      effectiveCommitment = link.delegateeCommitment;
      expectedPrev = expectedNew;
    }
  }

  // Score the result. Same shape as @bolyra/openclaw for consistency.
  const warnings: string[] = [...chainWarnings];
  if (!config.validateRoots) {
    warnings.push('No root validator configured — Merkle root provenance not verified');
  }
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

  // Use the leaf scope when a chain narrowed the effective permissions; this
  // ensures the read/write check sees what the agent is actually allowed to do.
  const hasBasicPermissions = (chainPermissionBitmask & 0b11n) !== 0n;
  if (hasBasicPermissions) {
    score += 20;
  } else {
    warnings.push('Agent has no read/write permissions');
  }

  // Nonce layout: (unix_seconds << 64) | random_entropy.
  // Extract the timestamp from the upper bits for freshness check.
  const nonceTs = nonce >> 64n;
  const nonceAgeSec = Number(now - nonceTs);
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

  const passed = verifyResult.verified && chainOk && score >= minScore;
  const ctx: BolyraAuthContext = {
    verified: passed,
    score,
    did: buildDid(network, commitment),
    permissionBitmask: chainPermissionBitmask,
    warnings,
    reason: passed
      ? undefined
      : warnings[0] ?? 'Verification failed for unknown reason',
    chainDepth,
    effectiveCommitment,
  };
  return attachReceipt(ctx, bundle, config);
}

/**
 * Dev-mode verification: no real ZKP checks, but validates bundle shape,
 * nonce freshness, expiry, permissions, and delegation chain structure.
 * Scores identically to production (40+20+20+10+10 = 100).
 */
function verifyDevBundle(
  bundle: BolyraProofBundle,
  config: BolyraMcpConfig,
): BolyraAuthContext {
  const network = config.network ?? DEFAULTS.network;
  const minScore = config.minScore ?? DEFAULTS.minScore;
  const maxProofAge = config.maxProofAge ?? DEFAULTS.maxProofAge;

  let nonce: bigint;
  let commitment: bigint;
  try {
    nonce = toBigInt(bundle.nonce, 'nonce');
    commitment = toBigInt(bundle.credentialCommitment, 'credentialCommitment');
  } catch (e: unknown) {
    return failCtx(e instanceof Error ? e.message : String(e));
  }

  // Production signal layout: [3] = requiredScopeMask (same as permissionBitmask).
  // Expiry is a private circuit input — not in public signals. In dev mode
  // we skip the expiry check (synthetic credential, always valid).
  const agentSignals = bundle.agentProof.publicSignals;
  const permissionBitmask = agentSignals[3] ? BigInt(agentSignals[3]) : 0n;

  const warnings: string[] = [];
  let score = 0;

  // "ZKP passes" — in dev mode we always grant this.
  score += 40;

  // Expiry: dev credentials are always valid (expiry is not in public signals).
  const now = BigInt(Math.floor(Date.now() / 1000));
  score += 20;

  // Permission check.
  let effectivePermissions = permissionBitmask;
  let effectiveCommitment = bundle.credentialCommitment;
  let chainDepth = 0;

  // Enforce max delegation chain depth — same limit as production path.
  const MAX_DELEGATION_HOPS = 3;
  if (bundle.delegationChain && bundle.delegationChain.length > MAX_DELEGATION_HOPS) {
    const devDid = `did:bolyra:dev:${commitment.toString(16).padStart(64, '0')}`;
    return {
      verified: false,
      score: 0,
      did: devDid,
      permissionBitmask: 0n,
      warnings: [`Delegation chain exceeds max hops (${bundle.delegationChain.length} > ${MAX_DELEGATION_HOPS})`],
      reason: `Delegation chain too deep (max ${MAX_DELEGATION_HOPS} hops)`,
      chainDepth: 0,
      effectiveCommitment: bundle.credentialCommitment,
    };
  }

  // Walk delegation chain shape (no crypto — just extract leaf scope/commitment).
  if (bundle.delegationChain && bundle.delegationChain.length > 0) {
    for (let i = 0; i < bundle.delegationChain.length; i++) {
      const link = bundle.delegationChain[i];
      try {
        effectivePermissions = toBigInt(link.delegateeScope, `delegationChain[${i}].delegateeScope`);
        effectiveCommitment = link.delegateeCommitment;
        chainDepth = i + 1;
      } catch (e: unknown) {
        warnings.push(e instanceof Error ? e.message : String(e));
        break;
      }
    }
  }

  const hasBasicPermissions = (effectivePermissions & 0b11n) !== 0n;
  if (hasBasicPermissions) {
    score += 20;
  } else {
    warnings.push('Agent has no read/write permissions');
  }

  // Nonce layout: (unix_seconds << 64) | random_entropy.
  // Extract the timestamp from the upper bits for freshness check.
  const nonceTs = nonce >> 64n;
  const nonceAgeSec = Number(now - nonceTs);
  if (nonceAgeSec >= 0 && nonceAgeSec < maxProofAge) {
    score += 10;
  } else {
    warnings.push(`Session nonce stale (${nonceAgeSec}s old, max ${maxProofAge}s)`);
  }

  // Scope commitment — in dev mode, always grant since we don't have real poseidon output.
  score += 10;

  const passed = score >= minScore;
  const devDid = `did:bolyra:dev:${commitment.toString(16).padStart(64, '0')}`;
  return {
    verified: passed,
    score,
    did: devDid,
    permissionBitmask: effectivePermissions,
    warnings,
    reason: passed ? undefined : warnings[0] ?? 'Dev verification failed for unknown reason',
    chainDepth,
    effectiveCommitment,
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

/**
 * Attach a signed receipt to a BolyraAuthContext when receiptSigner is
 * configured. Only called on the final production verification result —
 * early returns (malformed bundle, dev mode) do not get receipts.
 *
 * Receipt signing failure is swallowed: it must never break verification.
 */
async function attachReceipt(
  ctx: BolyraAuthContext,
  bundle: BolyraProofBundle,
  config: BolyraMcpConfig,
): Promise<BolyraAuthContext> {
  if (!config.receiptSigner) return ctx;

  try {
    const { createAuthReceipt, signReceipt } = await import('@bolyra/receipts');
    type AuthReceiptInput = import('@bolyra/receipts').AuthReceiptInput;

    const input: AuthReceiptInput = {
      rootDid: ctx.did,
      actingDid: ctx.chainDepth > 0
        ? `did:bolyra:${config.network ?? 'base-sepolia'}:${BigInt(ctx.effectiveCommitment).toString(16).padStart(64, '0')}`
        : ctx.did,
      credentialCommitment: bundle.credentialCommitment,
      effectiveCommitment: ctx.effectiveCommitment,
      allowed: ctx.verified,
      reasonCode: ctx.reason,
      score: ctx.score,
      permissionBitmask: ctx.permissionBitmask.toString(),
      chainDepth: ctx.chainDepth,
      humanProof: bundle.humanProof,
      agentProof: bundle.agentProof,
      humanPublicSignals: bundle.humanProof.publicSignals,
      agentPublicSignals: bundle.agentProof.publicSignals,
      bundleVersion: bundle.v,
      nonce: bundle.nonce,
      delegationChain: bundle.delegationChain,
    };

    const payload = createAuthReceipt(input, {
      issuer: config.receiptSigner.issuer,
      keyId: config.receiptSigner.keyId,
    });
    const receipt = signReceipt(payload, config.receiptSigner);
    return { ...ctx, receipt };
  } catch {
    // Receipt signing failure should not break verification
    return ctx;
  }
}
