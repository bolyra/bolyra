/**
 * Authoritative signal name maps for each Bolyra circuit.
 *
 * These arrays define the positional ordering of public signals as
 * emitted by the corresponding .circom files. They are the single
 * source of truth for the BolyraEnvelope codec.
 *
 * Order must match `signal output` declarations in:
 *   - circuits/src/HumanUniqueness.circom
 *   - circuits/src/AgentPolicy.circom
 *   - circuits/src/Delegation.circom
 */

export const HUMAN_UNIQUENESS_SIGNALS = [
  'humanMerkleRoot',
  'nullifierHash',
  'nonceBinding',
] as const;

export const AGENT_POLICY_SIGNALS = [
  'credentialCommitment',
  'permissionsBitmask',
  'scopeCommitment',
  'expiryTimestamp',
] as const;

export const DELEGATION_SIGNALS = [
  'delegatorCredCommitment',
  'delegateeCredCommitment',
  'narrowedPermissionsBitmask',
  'delegationNullifier',
] as const;

export type CircuitName = 'HumanUniqueness' | 'AgentPolicy' | 'Delegation';

export type ProvingSystem = 'groth16' | 'plonk';

export const SIGNAL_MAPS: Record<CircuitName, readonly string[]> = {
  HumanUniqueness: HUMAN_UNIQUENESS_SIGNALS,
  AgentPolicy: AGENT_POLICY_SIGNALS,
  Delegation: DELEGATION_SIGNALS,
};

/** Valid proving systems per circuit. HumanUniqueness is Groth16-only. */
export const VALID_PROVING_SYSTEMS: Record<CircuitName, readonly ProvingSystem[]> = {
  HumanUniqueness: ['groth16'],
  AgentPolicy: ['groth16', 'plonk'],
  Delegation: ['groth16', 'plonk'],
};
