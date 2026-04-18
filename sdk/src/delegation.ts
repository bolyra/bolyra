import { BolyraError } from './errors';
import { DelegationResult, Proof, BolyraConfig, AgentCredential } from './types';

/**
 * Delegate scoped permissions to another agent.
 * Currently a stub -- full implementation requires the delegation circuit zkey.
 *
 * @param delegator - The delegating agent's credential
 * @param delegatee - The receiving agent's credential
 * @param parentScopeCommitment - Scope commitment from the parent handshake or delegation
 * @param hopIndex - Current hop index in the delegation chain (0-indexed)
 * @param config - SDK configuration
 * @returns Delegation proof ready for on-chain verification
 */
export async function delegate(
  _delegator: AgentCredential,
  _delegatee: AgentCredential,
  _parentScopeCommitment: bigint,
  _hopIndex: number,
  _config?: BolyraConfig,
): Promise<{ proof: Proof; result: DelegationResult }> {
  throw new BolyraError(
    'delegate() coming in @bolyra/sdk v0.3 — delegation circuit integration.',
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
    'verifyDelegation() coming in @bolyra/sdk v0.3.',
    'NOT_IMPLEMENTED',
  );
}
