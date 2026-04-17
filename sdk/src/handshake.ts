import {
  HumanIdentity,
  AgentCredential,
  HandshakeResult,
  Proof,
  BolyraConfig,
} from './types';
import { BolyraError } from './errors';

/**
 * Generate a mutual handshake proof (human + agent).
 *
 * This is the core operation: both parties independently generate proofs
 * that are batch-verified in a single on-chain transaction.
 *
 * @param human - The human's identity (secret + publicKey + commitment)
 * @param agent - The agent's credential (signed by operator)
 * @param options - Optional scope string, nonce override, and SDK config
 * @returns Both proofs and the session nonce
 *
 * @example
 * ```ts
 * const { humanProof, agentProof, nonce } = await proveHandshake(
 *   humanIdentity,
 *   agentCredential,
 *   { scope: "bolyra-handshake-v1" }
 * );
 * // Submit both proofs to IdentityRegistry.verifyHandshake()
 * ```
 */
export async function proveHandshake(
  _human: HumanIdentity,
  _agent: AgentCredential,
  _options?: { scope?: string; nonce?: bigint; config?: BolyraConfig },
): Promise<{ humanProof: Proof; agentProof: Proof; nonce: bigint }> {
  // TODO: Implement in SDK v0.2 — requires snarkjs proof generation
  throw new BolyraError(
    'proveHandshake() not yet implemented — coming in @bolyra/sdk v0.2. ' +
      'Use the circuit files directly with snarkjs for now.',
    'NOT_IMPLEMENTED',
  );
}

/**
 * Verify a handshake on-chain by submitting both proofs to the IdentityRegistry.
 *
 * @param humanProof - The human's ZK proof
 * @param agentProof - The agent's ZK proof
 * @param nonce - The session nonce used during proof generation
 * @param config - SDK configuration (RPC URL, contract address, etc.)
 * @returns HandshakeResult with nullifiers and verification status
 */
export async function verifyHandshake(
  _humanProof: Proof,
  _agentProof: Proof,
  _nonce: bigint,
  _config?: BolyraConfig,
): Promise<HandshakeResult> {
  throw new BolyraError(
    'verifyHandshake() not yet implemented — coming in @bolyra/sdk v0.2.',
    'NOT_IMPLEMENTED',
  );
}
