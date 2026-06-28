/**
 * Agent credential creation and proof generation for the Bolyra protocol.
 *
 * CHANGE (scope-blinding-salt): createAgentCredential() now generates a
 * cryptographically random 32-byte blindingSalt. proveHandshake() passes
 * the salt as a private witness input to the AgentPolicy circuit.
 */

import { buildPoseidon } from 'circomlibjs';
import { buildEddsa } from 'circomlibjs';
import * as snarkjs from 'snarkjs';
import { webcrypto } from 'node:crypto';
import type {
  AgentCredential,
  DelegatedCredential,
  AgentHandshakeResult,
  DelegationProofResult,
  PermissionBitmask,
} from './types.js';
import { validateCumulativeBitEncoding } from './types.js';

const WASM_PATH_AGENT = 'circuits/build/AgentPolicy_js/AgentPolicy.wasm';
const ZKEY_PATH_AGENT = 'circuits/build/AgentPolicy_final.zkey';
const WASM_PATH_DELEGATION = 'circuits/build/Delegation_js/Delegation.wasm';
const ZKEY_PATH_DELEGATION = 'circuits/build/Delegation_final.zkey';

/**
 * Generate a cryptographically random 254-bit blinding salt.
 * Uses Web Crypto API (Node 18+ / browser) for CSPRNG.
 * The result fits within the BN254 scalar field.
 */
function generateBlindingSalt(): bigint {
  const buf = new Uint8Array(32);
  webcrypto.getRandomValues(buf);
  // Clear top 2 bits to ensure value < 2^254 (fits in BN254 scalar field)
  buf[0] &= 0x3f;
  let salt = 0n;
  for (let i = 0; i < 32; i++) {
    salt = (salt << 8n) | BigInt(buf[i]);
  }
  return salt;
}

/**
 * Create an agent credential with EdDSA-signed commitment and blinding salt.
 *
 * @param modelHash - Hash of the AI model identifier
 * @param operatorPrivKey - Operator's EdDSA private key (scalar)
 * @param permissions - 8-bit cumulative permission bitmask
 * @param expiry - Unix timestamp for credential expiry
 * @returns Signed AgentCredential with blindingSalt
 */
export async function createAgentCredential(
  modelHash: bigint,
  operatorPrivKey: bigint,
  permissions: PermissionBitmask,
  expiry: bigint,
): Promise<AgentCredential> {
  if (!validateCumulativeBitEncoding(permissions)) {
    throw new Error(
      `Invalid cumulative-bit encoding for permission bitmask: 0b${permissions.toString(2).padStart(8, '0')}`,
    );
  }

  const poseidon = await buildPoseidon();
  const eddsa = await buildEddsa();

  // Derive public key from private key
  const privKeyBuf = Buffer.from(operatorPrivKey.toString(16).padStart(64, '0'), 'hex');
  const pubKey = eddsa.prv2pub(privKeyBuf);
  const operatorPubKeyX = poseidon.F.toObject(pubKey[0]);
  const operatorPubKeyY = poseidon.F.toObject(pubKey[1]);

  // Compute credential commitment = Poseidon(modelHash, pubKeyX, permissionBitmask, expiry)
  const credentialCommitment = poseidon.F.toObject(
    poseidon([modelHash, operatorPubKeyX, BigInt(permissions), expiry]),
  );

  // Sign credential commitment with EdDSA
  const msgBuf = poseidon.F.e(credentialCommitment);
  const sig = eddsa.signPoseidon(privKeyBuf, msgBuf);
  const sigR8x = poseidon.F.toObject(sig.R8[0]);
  const sigR8y = poseidon.F.toObject(sig.R8[1]);
  const sigS = sig.S;

  // Generate blinding salt (CSPRNG, 254-bit)
  const blindingSalt = generateBlindingSalt();

  return {
    modelHash,
    operatorPubKeyX,
    operatorPubKeyY,
    operatorPrivKey,
    permissionBitmask: permissions,
    expiry,
    credentialCommitment,
    blindingSalt,
    sigR8x,
    sigR8y,
    sigS,
  };
}

/**
 * Generate a ZK proof of agent policy compliance for a handshake.
 *
 * @param credential - The agent's credential (includes blindingSalt)
 * @param sessionNonce - Fresh nonce binding this proof to a session
 * @param currentTimestamp - Current Unix timestamp for expiry check
 * @returns AgentHandshakeResult with proof and public outputs
 */
export async function proveHandshake(
  credential: AgentCredential,
  sessionNonce: bigint,
  currentTimestamp: bigint,
): Promise<AgentHandshakeResult> {
  const witness = {
    modelHash: credential.modelHash.toString(),
    operatorPubKeyX: credential.operatorPubKeyX.toString(),
    operatorPubKeyY: credential.operatorPubKeyY.toString(),
    permissionBitmask: credential.permissionBitmask.toString(),
    expiry: credential.expiry.toString(),
    blindingSalt: credential.blindingSalt.toString(),  // NEW: pass salt to circuit
    sigR8x: credential.sigR8x.toString(),
    sigR8y: credential.sigR8y.toString(),
    sigS: credential.sigS.toString(),
    sessionNonce: sessionNonce.toString(),
    currentTimestamp: currentTimestamp.toString(),
  };

  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    witness,
    WASM_PATH_AGENT,
    ZKEY_PATH_AGENT,
  );

  return {
    proof: {
      pi_a: [BigInt(proof.pi_a[0]), BigInt(proof.pi_a[1])],
      pi_b: [
        [BigInt(proof.pi_b[0][0]), BigInt(proof.pi_b[0][1])],
        [BigInt(proof.pi_b[1][0]), BigInt(proof.pi_b[1][1])],
      ],
      pi_c: [BigInt(proof.pi_c[0]), BigInt(proof.pi_c[1])],
      protocol: 'groth16',
    },
    credentialCommitment: BigInt(publicSignals[0]),
    scopeCommitment: BigInt(publicSignals[1]),
    nonceBinding: BigInt(publicSignals[2]),
  };
}

/**
 * Generate a ZK proof of valid delegation (scope narrowing).
 *
 * @param delegation - The delegated credential with parent reference
 * @param currentTimestamp - Current Unix timestamp
 * @returns DelegationProofResult with proof and public outputs
 */
export async function proveDelegation(
  delegation: DelegatedCredential,
  currentTimestamp: bigint,
): Promise<DelegationProofResult> {
  const witness = {
    parentPermissionBitmask: delegation.parentCredential.permissionBitmask.toString(),
    parentCredentialCommitment: delegation.parentCredential.credentialCommitment.toString(),
    parentBlindingSalt: delegation.parentCredential.blindingSalt.toString(),  // NEW
    delegatedPermissionBitmask: delegation.delegatedPermissionBitmask.toString(),
    delegatedCredentialCommitment: delegation.delegatedCredentialCommitment.toString(),
    delegatedBlindingSalt: delegation.delegatedBlindingSalt.toString(),  // NEW
    delegatorSecret: delegation.delegatorSecret.toString(),
    delegationExpiry: delegation.delegationExpiry.toString(),
    currentTimestamp: currentTimestamp.toString(),
  };

  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    witness,
    WASM_PATH_DELEGATION,
    ZKEY_PATH_DELEGATION,
  );

  return {
    proof: {
      pi_a: [BigInt(proof.pi_a[0]), BigInt(proof.pi_a[1])],
      pi_b: [
        [BigInt(proof.pi_b[0][0]), BigInt(proof.pi_b[0][1])],
        [BigInt(proof.pi_b[1][0]), BigInt(proof.pi_b[1][1])],
      ],
      pi_c: [BigInt(proof.pi_c[0]), BigInt(proof.pi_c[1])],
      protocol: 'groth16',
    },
    parentScopeCommitment: BigInt(publicSignals[0]),
    delegatedScopeCommitment: BigInt(publicSignals[1]),
    delegationBinding: BigInt(publicSignals[2]),
  };
}
