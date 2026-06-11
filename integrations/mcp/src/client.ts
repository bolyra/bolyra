/**
 * Client-side helper: generate a fresh Bolyra handshake proof and shape it for
 * both transports (HTTP header + stdio _meta) so callers don't have to pick.
 *
 * Lazy SDK import — heavy crypto only loads when the helper is actually used.
 */

import type {
  HumanIdentity,
  AgentCredential,
  BolyraConfig,
  BolyraProofBundle,
  BolyraClientAuth,
  BolyraDelegationLink,
  Proof,
} from './types';

export interface AttachProofOptions {
  devMode?: boolean;
  sdkConfig?: BolyraConfig;
}

/**
 * One delegation hop the caller wants the helper to produce a proof for.
 * Hops are walked in order: hop 0's delegator is the root credential, hop N's
 * delegator must be the previous hop's delegatee (with matching scope/expiry
 * so the identity-bound chain link Poseidon3(scope, commitment, expiry) lines
 * up across hops).
 */
export interface DelegationHopSpec {
  /** Credential delegating this hop. For hop 0, the root credential. */
  delegator: AgentCredential;
  /** Operator EdDSA private key that signed `delegator`. */
  delegatorOperatorPrivateKey: bigint | Buffer;
  /** Identity commitment of the recipient of this hop. */
  delegateeCommitment: bigint;
  /** Narrowed scope being granted (cumulative-bit subset of delegator's). */
  delegateeScope: bigint;
  /** Expiry being granted (≤ delegator.expiryTimestamp). */
  delegateeExpiry: bigint;
  /** Optional override for the unix-seconds timestamp bound into the proof.
   *  Defaults to the helper's shared currentTimestamp so all hops bind the same value. */
  currentTimestamp?: bigint;
}

/**
 * Generate a fresh handshake and return both transport-ready shapes.
 *
 * For HTTP transports: spread `result.headers` into your fetch headers.
 * For stdio MCP requests: merge `result.meta` into your request's `params`.
 *
 *   const auth = await attachBolyraProof(human, agentCred);
 *   await client.callTool({
 *     name: 'read_file',
 *     arguments: { path: '/etc/hosts' },
 *     _meta: auth.meta.bolyra ? { bolyra: auth.meta.bolyra } : undefined,
 *   });
 *
 * Each call generates a new proof. Cache `result.bundle` if you want to
 * reuse it within `maxProofAge` (default 5 min) instead of re-proving.
 */
export async function attachBolyraProof(
  human: HumanIdentity,
  credential: AgentCredential,
  options?: AttachProofOptions,
): Promise<BolyraClientAuth> {
  // Dev mode: skip real ZKP proving — return mock proofs.
  if (options?.devMode) {
    const nonce = BigInt(Math.floor(Date.now() / 1000));
    const mockProofStrings = Array.from({ length: 8 }, () =>
      BigInt(Math.floor(Math.random() * 2 ** 32)).toString(),
    );
    const humanProof: Proof = {
      proof: mockProofStrings as any,
      publicSignals: ['0', '0', '0', '0', nonce.toString()],
    };
    const agentProof: Proof = {
      proof: mockProofStrings as any,
      publicSignals: [
        '0',
        '0',
        credential.commitment.toString(),
        credential.permissionBitmask.toString(),
        credential.expiryTimestamp.toString(),
        nonce.toString(),
      ],
    };
    const bundle: BolyraProofBundle = {
      v: 1,
      humanProof,
      agentProof,
      nonce: nonce.toString(),
      credentialCommitment: credential.commitment.toString(),
      _dev: true,
    };
    const encoded = Buffer.from(JSON.stringify(bundle), 'utf8').toString('base64');
    return {
      headers: { Authorization: `Bolyra ${encoded}` },
      meta: { bolyra: bundle },
      bundle,
    };
  }

  const sdk = await import('@bolyra/sdk');
  const { humanProof, agentProof, nonce } = await sdk.proveHandshake(
    human,
    credential,
    { config: options?.sdkConfig },
  );

  const bundle: BolyraProofBundle = {
    v: 1,
    humanProof,
    agentProof,
    nonce: nonce.toString(),
    credentialCommitment: credential.commitment.toString(),
  };

  const encoded = Buffer.from(JSON.stringify(bundle), 'utf8').toString('base64');
  return {
    headers: { Authorization: `Bolyra ${encoded}` },
    meta: { bolyra: bundle },
    bundle,
  };
}

/**
 * Generate a fresh handshake AND walk a delegation chain, returning a v=2
 * bundle that carries the per-hop Delegation proofs.
 *
 * The chain starts from the root credential (whose commitment is what the
 * handshake itself proves authority for). Each hop produces a Groth16
 * Delegation proof that narrows scope; the verifier walks the chain,
 * recomputes Poseidon3(scope, commitment, expiry) per hop, and checks chain
 * continuity. The leaf delegatee's scope becomes the effective bitmask.
 *
 * Caller is responsible for keeping the per-hop credentials consistent —
 * specifically, for hop N (N ≥ 1), `hop[N].delegator` must be a credential
 * whose `permissionBitmask` equals `hop[N-1].delegateeScope`, whose
 * `expiryTimestamp` equals `hop[N-1].delegateeExpiry`, and whose `commitment`
 * equals `hop[N-1].delegateeCommitment`. Otherwise the SDK's chain-link
 * precheck throws `CHAIN_LINK_MISMATCH`.
 *
 * @example
 * ```ts
 * const auth = await attachDelegatedBolyraProof(human, rootCred, [
 *   { delegator: rootCred, delegatorOperatorPrivateKey: rootOpKey,
 *     delegateeCommitment: agentA.commitment, delegateeScope: 0b00001111n,
 *     delegateeExpiry: rootCred.expiryTimestamp - 3600n },
 *   { delegator: agentACred, delegatorOperatorPrivateKey: agentAOpKey,
 *     delegateeCommitment: agentB.commitment, delegateeScope: 0b00000011n,
 *     delegateeExpiry: agentACred.expiryTimestamp - 60n },
 * ]);
 * ```
 */
export async function attachDelegatedBolyraProof(
  human: HumanIdentity,
  rootCredential: AgentCredential,
  hops: DelegationHopSpec[],
  options?: AttachProofOptions,
): Promise<BolyraClientAuth> {
  if (hops.length === 0) {
    // No delegation requested — fall back to handshake-only bundle.
    return attachBolyraProof(human, rootCredential, options);
  }

  // Dev mode: skip delegation proving — return a v=1 bundle (no chain).
  if (options?.devMode) {
    return attachBolyraProof(human, rootCredential, options);
  }

  const sdk = await import('@bolyra/sdk');
  const sdkConfig = options?.sdkConfig;
  const { humanProof, agentProof, nonce } = await sdk.proveHandshake(
    human,
    rootCredential,
    { config: sdkConfig },
  );

  // Handshake binds the root credential's scopeCommitment as the first chain link.
  // This matches Poseidon3(root.permissionBitmask, root.commitment, root.expiryTimestamp)
  // by construction inside AgentPolicy.circom.
  let previousScopeCommitment = BigInt(agentProof.publicSignals[2]);
  // All hops share one currentTimestamp so they bind a consistent clock.
  // Hop-level overrides win when set.
  const sharedTs = BigInt(Math.floor(Date.now() / 1000));

  const chain: BolyraDelegationLink[] = [];
  for (let i = 0; i < hops.length; i++) {
    const hop = hops[i];
    const currentTimestamp = hop.currentTimestamp ?? sharedTs;
    const { proof: hopProof, result } = await sdk.delegate({
      delegator: hop.delegator,
      delegatorOperatorPrivateKey: hop.delegatorOperatorPrivateKey,
      delegateeCommitment: hop.delegateeCommitment,
      delegateeScope: hop.delegateeScope,
      delegateeExpiry: hop.delegateeExpiry,
      previousScopeCommitment,
      sessionNonce: nonce,
      currentTimestamp,
      hopIndex: i,
      config: sdkConfig,
    });
    chain.push({
      proof: hopProof,
      delegateeCommitment: hop.delegateeCommitment.toString(),
      delegateeScope: hop.delegateeScope.toString(),
      delegateeExpiry: hop.delegateeExpiry.toString(),
      currentTimestamp: currentTimestamp.toString(),
    });
    previousScopeCommitment = result.newScopeCommitment;
  }

  const bundle: BolyraProofBundle = {
    v: 2,
    humanProof,
    agentProof,
    nonce: nonce.toString(),
    credentialCommitment: rootCredential.commitment.toString(),
    delegationChain: chain,
  };

  const encoded = Buffer.from(JSON.stringify(bundle), 'utf8').toString('base64');
  return {
    headers: { Authorization: `Bolyra ${encoded}` },
    meta: { bolyra: bundle },
    bundle,
  };
}
