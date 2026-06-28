/**
 * Per-circuit signal name maps.
 *
 * Each entry maps a circuit name to an ordered array of public signal field
 * names.  The order matches the snarkjs publicSignals array: outputs first
 * (in declaration order), then public inputs (in declaration order).
 *
 * Source of truth: circuits/src/*.circom `signal output` and
 * `component main {public [...]}` declarations.
 */

/** Supported Bolyra circuit names. */
export type BolyraCircuit = 'HumanUniqueness' | 'AgentPolicy' | 'Delegation';

/** Supported proving systems. */
export type BolyraProvingSystem = 'groth16' | 'plonk';

/**
 * Positional signal name maps keyed by circuit.
 *
 * Index in the array === index in snarkjs `publicSignals[]`.
 */
export const SIGNAL_MAPS: Record<BolyraCircuit, readonly string[]> = {
  HumanUniqueness: [
    'nullifierHash',      // output 0
    'nonceBinding',       // output 1
    'humanMerkleRoot',    // public input 0
    'externalNullifier',  // public input 1
    'sessionNonce',       // public input 2
  ],
  AgentPolicy: [
    'credentialHash',      // output 0
    'nonceBinding',        // output 1
    'agentMerkleRoot',     // public input 0
    'currentTimestamp',    // public input 1
    'requiredPermissions', // public input 2
    'sessionNonce',        // public input 3
  ],
  Delegation: [
    'delegationHash',       // output 0
    'narrowedPermissions',  // output 1
    'nonceBinding',         // output 2
    'delegationMerkleRoot', // public input 0
    'currentTimestamp',     // public input 1
    'sessionNonce',         // public input 2
  ],
} as const;

/** Set of valid circuit names for runtime validation. */
export const VALID_CIRCUITS = new Set<string>(Object.keys(SIGNAL_MAPS));

/** Set of valid proving systems. */
export const VALID_PROVING_SYSTEMS = new Set<string>(['groth16', 'plonk']);
