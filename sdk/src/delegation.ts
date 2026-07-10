import * as path from 'path';
import * as fs from 'fs';
import {
  AgentCredential,
  BolyraConfig,
  DelegateeMerkleProof,
  DelegationResult,
  Proof,
} from './types';
import {
  BolyraError,
  CircuitArtifactNotFoundError,
  ProofGenerationError,
  ScopeEscalationError,
  VerificationError,
} from './errors';
import { eddsaSign, poseidon3, poseidon4 } from './utils';
import { proveGroth16, ProverBackend } from './prover';
import { loadSnarkjs } from './zk';

const DEFAULT_CIRCUIT_DIR =
  process.env.BOLYRA_CIRCUITS_DIR ?? path.join(__dirname, '../../circuits/build');

/** Delegation circuit MAX_DEPTH constant (matches circuits/src/Delegation.circom). */
const DELEGATION_MAX_DEPTH = 20;

/** snarkjs publicSignals layout for the Delegation circuit (outputs first):
 *    [0] newScopeCommitment
 *    [1] delegationNullifier
 *    [2] delegateeMerkleRoot
 *    [3] previousScopeCommitment
 *    [4] sessionNonce
 *    [5] currentTimestamp
 *  This MUST match IdentityRegistry.verifyDelegation()'s pubSignals layout.
 */
const PUBSIG_NEW_SCOPE = 0;
const PUBSIG_NULLIFIER = 1;
const PUBSIG_DELEGATEE_ROOT = 2;
const PUBSIG_PREV_SCOPE = 3;
const PUBSIG_SESSION_NONCE = 4;
const PUBSIG_CURRENT_TS = 5;

/** Build the single-leaf Merkle proof default (matches the conformance test pattern). */
function defaultMerkleProof(): DelegateeMerkleProof {
  return {
    length: 1,
    index: 0,
    siblings: new Array(DELEGATION_MAX_DEPTH).fill(0n),
  };
}

export interface DelegateInput {
  /** The delegating agent's credential (provides modelHash, operator pubkey, scope, expiry). */
  delegator: AgentCredential;
  /** Operator's EdDSA private key — used to sign the delegation token.
   *  Same key that minted the delegator credential. */
  delegatorOperatorPrivateKey: bigint | Buffer;
  /** Identity commitment of the recipient (leaf in agentTree). */
  delegateeCommitment: bigint;
  /** Narrowed scope being granted. Must be a subset of delegator.permissionBitmask
   *  under the cumulative-bit rules. Circuit enforces; SDK pre-checks for a clean error. */
  delegateeScope: bigint;
  /** Expiry being granted. Must be <= delegator.expiryTimestamp. */
  delegateeExpiry: bigint;
  /** Scope commitment from the prior chain link.
   *  For hop 1, this is the agent's scopeCommitment output from the handshake.
   *  For hop N+1, this is the previous delegation's newScopeCommitment. */
  previousScopeCommitment: bigint;
  /** Session nonce. Must match the nonce of the originating handshake. */
  sessionNonce: bigint;
  /** Unix-seconds timestamp the proof is bound to. Must be within MAX_CLOCK_SKEW
   *  of block.timestamp at on-chain verification time (300s in IdentityRegistry).
   *  Defaults to floor(Date.now() / 1000). */
  currentTimestamp?: bigint;
  /** Optional Merkle inclusion proof for the delegatee in agentTree.
   *  Defaults to the single-leaf pattern (sufficient for tests and demos). */
  delegateeMerkleProof?: DelegateeMerkleProof;
  /** Informational hop index (0-indexed). Not consumed by the circuit;
   *  echoed in DelegationResult for caller bookkeeping. */
  hopIndex?: number;
  config?: BolyraConfig;
  backend?: ProverBackend;
}

/**
 * Generate a Delegation proof.
 *
 * Produces a Groth16 proof matching the Delegation circuit. The caller submits
 * `{ proof, publicSignals }` to `IdentityRegistry.verifyDelegation()` along with
 * the session nonce.
 *
 * Scope narrowing is one-way: the circuit (and contract) reject any delegatee
 * scope that is not a subset of the delegator's, and any expiry past the
 * delegator's. The cumulative-bit invariants (bit 4 ⇒ 2+3, bit 3 ⇒ 2) are
 * enforced on the delegatee scope.
 *
 * @example
 * ```ts
 * const { proof, result } = await delegate({
 *   delegator: parentCredential,
 *   delegatorOperatorPrivateKey: operatorSecret,
 *   delegateeCommitment: childCredential.commitment,
 *   delegateeScope: 0b00000011n,                    // read + write (narrower)
 *   delegateeExpiry: parentCredential.expiryTimestamp - 3600n,
 *   previousScopeCommitment: handshake.scopeCommitment,
 *   sessionNonce: handshake.sessionNonce,
 * });
 * ```
 */
export async function delegate(
  input: DelegateInput,
): Promise<{ proof: Proof; result: DelegationResult }> {
  // Pre-flight scope check — gives a clean error before paying for proof generation.
  if (
    (input.delegateeScope & ~input.delegator.permissionBitmask) !== 0n
  ) {
    throw new ScopeEscalationError(
      input.delegator.permissionBitmask,
      input.delegateeScope,
    );
  }
  if (input.delegateeExpiry > input.delegator.expiryTimestamp) {
    throw new BolyraError(
      `Delegatee expiry (${input.delegateeExpiry}) exceeds delegator expiry (${input.delegator.expiryTimestamp}). Delegations may only narrow expiry, not extend it.`,
      'EXPIRY_ESCALATION',
      {
        delegateeExpiry: input.delegateeExpiry.toString(),
        delegatorExpiry: input.delegator.expiryTimestamp.toString(),
      },
    );
  }

  // Sanity check: the previousScopeCommitment passed in must equal the
  // identity-bound chain link Poseidon3(delegatorScope, delegatorCredCommitment,
  // delegatorExpiry). The circuit will assert this; we precheck for a clean error.
  // Ordered before artifact loading so CI environments without circuits still
  // surface CHAIN_LINK_MISMATCH instead of CIRCUIT_ARTIFACT_NOT_FOUND.
  const expectedPrev = await poseidon3(
    input.delegator.permissionBitmask,
    input.delegator.commitment,
    input.delegator.expiryTimestamp,
  );
  if (expectedPrev !== input.previousScopeCommitment) {
    throw new BolyraError(
      `previousScopeCommitment does not match the delegator's identity-bound chain link. Got ${input.previousScopeCommitment}, expected ${expectedPrev} (= Poseidon3(scope, credCommitment, expiry) for this delegator). For hop 1, pass the agent's scopeCommitment output from proveHandshake.`,
      'CHAIN_LINK_MISMATCH',
    );
  }

  const circuitDir = input.config?.circuitDir ?? DEFAULT_CIRCUIT_DIR;
  const backend = input.backend ?? 'auto';
  const currentTimestamp =
    input.currentTimestamp ?? BigInt(Math.floor(Date.now() / 1000));
  const merkleProof = input.delegateeMerkleProof ?? defaultMerkleProof();
  if (merkleProof.siblings.length !== DELEGATION_MAX_DEPTH) {
    throw new BolyraError(
      `Delegatee Merkle proof must have exactly ${DELEGATION_MAX_DEPTH} siblings (got ${merkleProof.siblings.length}).`,
      'INVALID_MERKLE_PROOF',
    );
  }

  const wasmPath = path.join(circuitDir, 'Delegation_js/Delegation.wasm');
  const zkeyPath = path.join(circuitDir, 'Delegation_final.zkey');
  if (!fs.existsSync(wasmPath)) {
    throw new CircuitArtifactNotFoundError(wasmPath, 'wasm');
  }
  if (!fs.existsSync(zkeyPath)) {
    throw new CircuitArtifactNotFoundError(zkeyPath, 'zkey');
  }

  // The delegator signs the delegation token, binding this delegation to a
  // specific recipient with specific scope+expiry.
  // Token = Poseidon4(previousScopeCommitment, delegateeCommitment, delegateeScope, delegateeExpiry).
  const tokenHash = await poseidon4(
    input.previousScopeCommitment,
    input.delegateeCommitment,
    input.delegateeScope,
    input.delegateeExpiry,
  );
  const sig = await eddsaSign(input.delegatorOperatorPrivateKey, tokenHash);

  const witnessInput: Record<string, unknown> = {
    delegatorScope: input.delegator.permissionBitmask.toString(),
    delegateeScope: input.delegateeScope.toString(),
    delegateeExpiry: input.delegateeExpiry.toString(),
    delegatorExpiry: input.delegator.expiryTimestamp.toString(),
    delegatorModelHash: input.delegator.modelHash.toString(),
    delegatorPubkeyAx: input.delegator.operatorPublicKey.x.toString(),
    delegatorPubkeyAy: input.delegator.operatorPublicKey.y.toString(),
    sigR8x: sig.R8.x.toString(),
    sigR8y: sig.R8.y.toString(),
    sigS: sig.S.toString(),
    delegatorCredCommitment: input.delegator.commitment.toString(),
    delegateeCredCommitment: input.delegateeCommitment.toString(),
    delegateeMerkleProofLength: merkleProof.length.toString(),
    delegateeMerkleProofIndex: merkleProof.index.toString(),
    delegateeMerkleProofSiblings: merkleProof.siblings.map((s) => s.toString()),
    previousScopeCommitment: input.previousScopeCommitment.toString(),
    sessionNonce: input.sessionNonce.toString(),
    currentTimestamp: currentTimestamp.toString(),
  };

  let proof: Proof;
  try {
    proof = await proveGroth16(witnessInput, wasmPath, zkeyPath, backend);
  } catch (err: any) {
    throw new ProofGenerationError('Delegation', err.message ?? String(err));
  }

  const result: DelegationResult = {
    newScopeCommitment: BigInt(proof.publicSignals[PUBSIG_NEW_SCOPE]),
    delegationNullifier: BigInt(proof.publicSignals[PUBSIG_NULLIFIER]),
    delegateeMerkleRoot: BigInt(proof.publicSignals[PUBSIG_DELEGATEE_ROOT]),
    hopIndex: input.hopIndex ?? 0,
  };

  return { proof, result };
}

/**
 * Verify a delegation proof off-chain (snarkjs Groth16 verify).
 *
 * For on-chain enforcement, submit `proof` and `proof.publicSignals` to
 * `IdentityRegistry.verifyDelegation(proof, pubSignals, sessionNonce)` — that
 * call additionally enforces chain state, hop count, expiry binding, and
 * nullifier replay. Off-chain verify here only confirms the proof itself is
 * mathematically valid and that the publicSignals match the expected chain link.
 */
export async function verifyDelegation(
  proof: Proof,
  previousScopeCommitment: bigint,
  sessionNonce: bigint,
  currentTimestamp: bigint,
  config?: BolyraConfig,
): Promise<DelegationResult> {
  if (!proof || !proof.proof || !Array.isArray(proof.publicSignals)) {
    throw new VerificationError(
      'Invalid Delegation proof structure: expected { proof: object, publicSignals: string[] }.',
    );
  }
  if (proof.publicSignals.length < 6) {
    throw new VerificationError(
      `Delegation proof has ${proof.publicSignals.length} public signals, expected 6.`,
    );
  }

  // Bind the public signals to the expected chain context before trusting the proof.
  if (BigInt(proof.publicSignals[PUBSIG_PREV_SCOPE]) !== previousScopeCommitment) {
    throw new VerificationError(
      `previousScopeCommitment mismatch: proof binds ${proof.publicSignals[PUBSIG_PREV_SCOPE]}, caller expected ${previousScopeCommitment}.`,
    );
  }
  if (BigInt(proof.publicSignals[PUBSIG_SESSION_NONCE]) !== sessionNonce) {
    throw new VerificationError(
      `sessionNonce mismatch: proof binds ${proof.publicSignals[PUBSIG_SESSION_NONCE]}, caller expected ${sessionNonce}.`,
    );
  }
  if (BigInt(proof.publicSignals[PUBSIG_CURRENT_TS]) !== currentTimestamp) {
    throw new VerificationError(
      `currentTimestamp mismatch: proof binds ${proof.publicSignals[PUBSIG_CURRENT_TS]}, caller expected ${currentTimestamp}.`,
    );
  }

  const circuitDir = config?.circuitDir ?? DEFAULT_CIRCUIT_DIR;
  const vkeyPath = path.join(circuitDir, 'Delegation_groth16_vkey.json');
  if (!fs.existsSync(vkeyPath)) {
    throw new CircuitArtifactNotFoundError(vkeyPath, 'vkey');
  }
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const vkey = require(vkeyPath);

  // ZK path begins here — snarkjs is loaded lazily so classical (Core)
  // callers of this module never pay the snarkjs module-load cost.
  const snarkjs = await loadSnarkjs();
  const valid = await snarkjs.groth16.verify(vkey, proof.publicSignals, proof.proof);
  if (!valid) {
    throw new VerificationError('Delegation proof failed Groth16 verification.');
  }

  return {
    newScopeCommitment: BigInt(proof.publicSignals[PUBSIG_NEW_SCOPE]),
    delegationNullifier: BigInt(proof.publicSignals[PUBSIG_NULLIFIER]),
    delegateeMerkleRoot: BigInt(proof.publicSignals[PUBSIG_DELEGATEE_ROOT]),
    hopIndex: 0,
  };
}
