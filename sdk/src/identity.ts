import { HumanIdentity, AgentCredential, Permission } from './types';
import { poseidon2, poseidon5, eddsaSign, derivePublicKey } from './utils';
import { InvalidPermissionError } from './errors';

/**
 * Create a human identity (EdDSA keypair + commitment).
 * Compatible with Semaphore v4 identity scheme.
 *
 * @param secret - A secret value (random bigint or derived from a seed phrase).
 *                 KEEP THIS PRIVATE — it is the human's authentication key.
 * @returns HumanIdentity with secret, publicKey, and commitment
 *
 * @example
 * ```ts
 * const identity = await createHumanIdentity(BigInt(crypto.getRandomValues(new Uint8Array(32)).reduce((a, b) => a * 256n + BigInt(b), 0n)));
 * console.log(identity.commitment); // Poseidon2(Ax, Ay) — enroll this in humanTree
 * ```
 */
export async function createHumanIdentity(
  secret: bigint,
): Promise<HumanIdentity> {
  const publicKey = await derivePublicKey(secret);
  const commitment = await poseidon2(publicKey.x, publicKey.y);
  return { secret, publicKey, commitment };
}

/**
 * Create an AI agent credential signed by the operator.
 *
 * @param modelHash - Hash of the model identifier (e.g., sha256("gpt-4o"))
 * @param operatorPrivateKey - Operator's EdDSA private key (signs the credential)
 * @param permissions - Array of Permission flags (cumulative encoding enforced)
 * @param expiryTimestamp - Unix timestamp when the credential expires
 * @returns AgentCredential with all fields + operator signature + commitment
 *
 * @example
 * ```ts
 * const credential = await createAgentCredential(
 *   hashModel("gpt-4o"),
 *   operatorKey,
 *   [Permission.READ_DATA, Permission.WRITE_DATA, Permission.FINANCIAL_SMALL],
 *   BigInt(Math.floor(Date.now() / 1000) + 86400) // +1 day
 * );
 * console.log(credential.commitment); // enroll this in agentTree
 * ```
 */
export async function createAgentCredential(
  modelHash: bigint,
  operatorPrivateKey: bigint | Buffer,
  permissions: Permission[],
  expiryTimestamp: bigint,
): Promise<AgentCredential> {
  const bitmask = permissionsToBitmask(permissions);
  validateCumulativeBitEncoding(bitmask);

  const operatorPublicKey = await derivePublicKey(
    typeof operatorPrivateKey === 'bigint'
      ? operatorPrivateKey
      : BigInt('0x' + operatorPrivateKey.toString('hex')),
  );

  const commitment = await poseidon5(
    modelHash,
    operatorPublicKey.x,
    operatorPublicKey.y,
    bitmask,
    expiryTimestamp,
  );

  const signature = await eddsaSign(operatorPrivateKey, commitment);

  return {
    modelHash,
    operatorPublicKey,
    permissionBitmask: bitmask,
    expiryTimestamp,
    signature,
    commitment,
  };
}

/** Convert an array of Permission flags to a 64-bit bitmask */
export function permissionsToBitmask(permissions: Permission[]): bigint {
  let bitmask = 0n;
  for (const p of permissions) {
    bitmask |= 1n << BigInt(p);
  }
  return bitmask;
}

/** Validate cumulative bit encoding: bit 4 implies 2+3, bit 3 implies 2 */
export function validateCumulativeBitEncoding(bitmask: bigint): void {
  const bit2 = (bitmask >> 2n) & 1n;
  const bit3 = (bitmask >> 3n) & 1n;
  const bit4 = (bitmask >> 4n) & 1n;

  if (bit4 && !bit3) {
    throw new InvalidPermissionError(
      'FINANCIAL_UNLIMITED (bit 4) requires FINANCIAL_MEDIUM (bit 3)',
    );
  }
  if (bit4 && !bit2) {
    throw new InvalidPermissionError(
      'FINANCIAL_UNLIMITED (bit 4) requires FINANCIAL_SMALL (bit 2)',
    );
  }
  if (bit3 && !bit2) {
    throw new InvalidPermissionError(
      'FINANCIAL_MEDIUM (bit 3) requires FINANCIAL_SMALL (bit 2)',
    );
  }
}
