import {
  AgentCredential,
  DelegationResult,
  Proof,
  BolyraConfig,
} from './types';
import { BolyraError } from './errors';

/**
 * Delegate permissions from one agent to another via ZK proof.
 *
 * Creates a delegation proof that proves:
 * 1. The delegator has valid credentials (in the agent tree)
 * 2. The delegatee's permissions are a subset of the delegator's
 * 3. The delegation chain is valid (scope commitment links to parent)
 *
 * @param delegator - The delegating agent's credential
 * @param delegatee - The receiving agent's credential
 * @param parentScopeCommitment - Scope commitment from the parent handshake or delegation
 * @param hopIndex - Current hop index in the delegation chain (0-indexed)
 * @param config - SDK configuration
 * @returns Delegation proof ready for on-chain verification
 *
 * @example
 * ```ts
 * const { proof, newScopeCommitment } = await delegate(
 *   parentAgent,
 *   childAgent,
 *   handshakeResult.scopeCommitment,
 *   0, // first delegation hop
 * );
 * ```
 */
export async function delegate(
  _delegator: AgentCredential,
  _delegatee: AgentCredential,
  _parentScopeCommitment: bigint,
  _hopIndex: number,
  _config?: BolyraConfig,
): Promise<{ proof: Proof; result: DelegationResult }> {
  // TODO: Implement in SDK v0.2 — requires snarkjs proof generation
  throw new BolyraError(
    'delegate() not yet implemented — coming in @bolyra/sdk v0.2. ' +
      'Use the circuit files directly with snarkjs for now.',
    'NOT_IMPLEMENTED',
  );
}

/**
 * Verify a delegation proof on-chain.
 *
 * @param proof - The delegation ZK proof
 * @param parentScopeCommitment - Expected parent scope commitment
 * @param config - SDK configuration
 * @returns DelegationResult with new scope commitment and hop index
 */
export async function verifyDelegation(
  _proof: Proof,
  _parentScopeCommitment: bigint,
  _config?: BolyraConfig,
): Promise<DelegationResult> {
  throw new BolyraError(
    'verifyDelegation() not yet implemented — coming in @bolyra/sdk v0.2.',
    'NOT_IMPLEMENTED',
  );
}
