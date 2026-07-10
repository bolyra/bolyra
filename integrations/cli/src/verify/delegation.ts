/**
 * Delegation-chain verification for `bolyra verify` (spec §5.8, OQ-4, F5).
 *
 * A delegation chain is an ordered list of hops. Each hop carries a Groth16
 * Delegation proof whose public signals (in order) are:
 *
 *   [0] newScopeCommitment    [1] delegationNullifier   [2] delegateeMerkleRoot
 *   [3] previousScopeCommitment [4] sessionNonce         [5] currentTimestamp
 *
 * This module verifies the *chain semantics* on top of the SDK's per-hop
 * `verifyDelegation` (which does the Groth16 verify AND binds prev/nonce/ts and
 * rejects scope/expiry escalation). It enforces, in order:
 *
 *   1. Hop cap — at most {@link MAX_HOPS} hops (on-chain limit), checked before
 *      any proof is touched.
 *   2. Chain-linking — each hop's `newScopeCommitment` threads into the next
 *      hop as its `previousScopeCommitment` (enforced by `verifyDelegation`,
 *      which rejects a prev mismatch).
 *   3. Delegatee-root trust — the `delegateeMerkleRoot` each hop commits to must
 *      belong to a trusted enrollment tree (phantom-delegatee defense). THIS
 *      module owns that check.
 *   4. Per-hop nullifier replay — each `delegationNullifier` is burned once via
 *      the durable nonce store; a replay denies with `nonce_replayed`.
 *   5. Final-leaf recompute — the last hop's `newScopeCommitment` must equal
 *      `Poseidon3(delegateeScope, delegateeCredCommitment, delegateeExpiry)` for
 *      the disclosed final leaf (spec Delegation.circom:227).
 *
 * The effective authority of the chain is the FINAL leaf's scope, bounded in
 * lifetime by `min(agentExpiry, finalLeafExpiry)`.
 *
 * `verifyFn` is injectable so the chain semantics can be unit-tested with a fake
 * that returns crafted results; the real Groth16 path is covered end-to-end
 * (Task 16) with golden bundles.
 */

import { verifyDelegation, poseidon3 } from '@bolyra/sdk';
import type { BolyraConfig, DelegationResult, Proof } from '@bolyra/sdk';
import type { NonceStore } from '@bolyra/mcp';

import { VerifyDenial } from './verdict';
import { assertTrusted, type RootSource } from './roots';

/** On-chain hop cap: a delegation chain may not exceed 3 hops. */
export const MAX_HOPS = 3;

/**
 * The disclosed final-leaf attributes needed to recompute the final hop's
 * `newScopeCommitment`. Present on (at least) the final hop.
 */
export interface DelegationLeaf {
  /** Delegatee scope bitmask, as a decimal field-element string. */
  delegatee_scope: string;
  /** Delegatee credential commitment, as a decimal field-element string. */
  delegatee_commitment: string;
  /** Delegatee credential expiry (Unix seconds). */
  delegatee_expiry: number;
}

/** One hop of a delegation chain: a proof envelope plus optional disclosed leaf. */
export interface DelegationHop {
  /** The Delegation proof envelope: raw proof object + ordered public signals. */
  envelope: { publicSignals: string[]; proof: unknown };
  /** Disclosed leaf attributes; REQUIRED on the final hop for leaf recompute. */
  leaf?: DelegationLeaf;
}

/** Context threaded through delegation-chain verification. */
export interface DelegationChainContext {
  /** The delegator agent's scope commitment — the chain's root `previousScopeCommitment`. */
  agentScopeCommitment: bigint;
  /** Session nonce every hop must bind to. */
  sessionNonce: bigint;
  /** Current timestamp every hop must bind to. */
  currentTimestamp: bigint;
  /** The delegator agent's expiry, upper-bounding the chain's effective expiry. */
  agentExpiry: bigint;
  /** Trusted-root source used to gate each hop's delegatee Merkle root. */
  rootSource: RootSource;
  /** Durable replay store for per-hop delegation nullifiers. */
  nonceStore: NonceStore;
  /** TTL (seconds) for which a burned delegation nullifier is retained. */
  nonceTtlSeconds: number;
  /**
   * When `true`, do NOT burn per-hop delegation nullifiers into the local store.
   * Used in host nonce mode: every `delegationNullifier` is session-bound
   * (`Poseidon2(tokenHash, sessionNonce)`, pinned to the agent's `sessionNonce`),
   * so the host reserving the agent nullifier already covers delegation replay —
   * a host-mode verifier must therefore write no local delegation state and emit
   * no extra host entry for it. Defaults to `false` (local mode burns per hop).
   */
  skipNonceConsumption?: boolean;
  /** Injectable per-hop verifier; defaults to the SDK `verifyDelegation`. */
  verifyFn?: typeof verifyDelegation;
  /** Optional SDK config (e.g. circuit artifact dir) forwarded to the verifier. */
  config?: BolyraConfig;
}

/** The effective authority a verified delegation chain confers. */
export interface EffectiveDelegation {
  /** The final leaf's scope bitmask. */
  effectiveScope: bigint;
  /** min(agentExpiry, finalLeafExpiry) — the chain never outlives its delegator. */
  effectiveExpiry: bigint;
}

/** bigint minimum. */
function minBigInt(a: bigint, b: bigint): bigint {
  return a < b ? a : b;
}

/**
 * Verify a delegation chain and return its effective scope + expiry.
 *
 * Throws {@link VerifyDenial} on any failure; the core orchestrator maps the
 * thrown code to a wire `deny` verdict.
 */
export async function verifyDelegationChain(
  hops: DelegationHop[],
  ctx: DelegationChainContext,
): Promise<EffectiveDelegation> {
  // 1. Hop cap — before any proof verification.
  if (hops.length > MAX_HOPS) {
    throw new VerifyDenial('delegation_invalid', 'delegation chain exceeds max 3 hops', {
      length: hops.length,
    });
  }

  const verify = ctx.verifyFn ?? verifyDelegation;
  let prev = ctx.agentScopeCommitment;

  for (let i = 0; i < hops.length; i++) {
    const hop = hops[i];
    const proof: Proof = { proof: hop.envelope.proof, publicSignals: hop.envelope.publicSignals };

    // 2. Per-hop Groth16 verify + prev/nonce/ts binding + scope/expiry
    //    escalation (all thrown by verifyDelegation).
    let result: DelegationResult;
    try {
      result = await verify(proof, prev, ctx.sessionNonce, ctx.currentTimestamp, ctx.config);
    } catch (err) {
      throw new VerifyDenial('delegation_invalid', 'delegation hop failed verification', {
        hop: i,
        sdk_code: (err as { code?: string }).code,
      });
    }

    // 3. Delegatee-root trust — phantom-delegatee defense.
    assertTrusted(ctx.rootSource, result.delegateeMerkleRoot.toString(), 'delegatee');

    // 4. Per-hop nullifier replay. Skipped in host nonce mode: the per-hop
    //    delegation nullifier is bound to the agent's session nonce, so the
    //    host reserving the agent nullifier already covers delegation replay —
    //    the verifier writes no local delegation state in host mode.
    if (ctx.skipNonceConsumption !== true) {
      const fresh = await ctx.nonceStore.markIfFresh(
        result.delegationNullifier.toString(),
        ctx.nonceTtlSeconds,
      );
      if (!fresh) {
        throw new VerifyDenial('nonce_replayed', 'delegation nullifier replayed', { hop: i });
      }
    }

    // Thread this hop's new scope into the next hop's previous scope.
    prev = result.newScopeCommitment;
  }

  // 5. Final-leaf recompute against the last hop's newScopeCommitment (== prev).
  const finalLeaf = hops[hops.length - 1]?.leaf;
  if (!finalLeaf) {
    throw new VerifyDenial('delegation_invalid', 'final delegation hop missing leaf');
  }

  const leafCommit = await poseidon3(
    BigInt(finalLeaf.delegatee_scope),
    BigInt(finalLeaf.delegatee_commitment),
    BigInt(finalLeaf.delegatee_expiry),
  );
  if (leafCommit !== prev) {
    throw new VerifyDenial('delegation_invalid', 'final leaf does not match newScopeCommitment');
  }

  const effectiveScope = BigInt(finalLeaf.delegatee_scope);
  const effectiveExpiry = minBigInt(ctx.agentExpiry, BigInt(finalLeaf.delegatee_expiry));
  return { effectiveScope, effectiveExpiry };
}
