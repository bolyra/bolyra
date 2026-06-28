/**
 * Bolyra SDK — Maps IdentityRegistry on-chain revert reasons to typed
 * BolyraError instances with contextual recovery hints.
 *
 * Requires ethers v6.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

import { Interface, type ErrorDescription } from 'ethers';
import { BolyraError } from './errors.js';
import { ErrorCode } from './error-codes.js';

/**
 * ABI fragments for every IdentityRegistry custom error.
 * Keep in sync with contracts/src/IdentityRegistry.sol.
 */
const REGISTRY_ERROR_ABI = [
  'error StaleRoot(uint256 providedBlock, uint256 latestBlock)',
  'error NullifierSpent(bytes32 nullifier)',
  'error ScopeMismatch(uint8 required, uint8 provided)',
  'error InvalidProof()',
  'error NonceAlreadyUsed(bytes32 nonce)',
  'error CredentialExpired(uint256 expiry)',
  'error Unauthorized()',
  'error RootNotFound(bytes32 root)',
];

const iface = new Interface(REGISTRY_ERROR_ABI);

/**
 * Map a parsed ErrorDescription to a BolyraError.
 */
function fromErrorDescription(
  desc: ErrorDescription,
  cause?: unknown,
): BolyraError {
  switch (desc.name) {
    case 'StaleRoot': {
      const providedBlock = Number(desc.args[0]);
      const latestBlock = Number(desc.args[1]);
      const delta = latestBlock - providedBlock;
      return BolyraError.staleRoot(delta > 0 ? delta : 1);
    }
    case 'NullifierSpent': {
      const nullifier = String(desc.args[0]);
      return BolyraError.nullifierSpent(nullifier);
    }
    case 'ScopeMismatch': {
      const required = Number(desc.args[0]);
      const provided = Number(desc.args[1]);
      return BolyraError.scopeMismatch(required, provided);
    }
    case 'InvalidProof':
      return BolyraError.proofInvalid(
        'On-chain Groth16/PLONK verification failed',
        cause,
      );
    case 'NonceAlreadyUsed': {
      const nonce = String(desc.args[0]);
      return BolyraError.nonceReused(nonce);
    }
    case 'CredentialExpired': {
      const expiry = Number(desc.args[0]);
      return BolyraError.expiredCredential(expiry);
    }
    case 'RootNotFound':
      return BolyraError.staleRoot(0);
    case 'Unauthorized':
      return BolyraError.registryRevert('Unauthorized', '', cause);
    default:
      return BolyraError.registryRevert(
        desc.name,
        desc.args.map(String).join(', '),
        cause,
      );
  }
}

/**
 * Decode an ethers revert error into a typed BolyraError.
 *
 * Accepts the raw `data` bytes from a CALL_EXCEPTION, or an Error
 * object whose `.data` field contains the revert selector.
 *
 * @param errOrData - Raw hex revert data or an Error with `.data`
 * @returns A BolyraError with the appropriate code and hint
 */
export function mapRevertToBolyraError(errOrData: unknown): BolyraError {
  let data: string | undefined;

  if (typeof errOrData === 'string') {
    data = errOrData;
  } else if (errOrData && typeof errOrData === 'object') {
    const err = errOrData as Record<string, unknown>;
    // ethers v6 CALL_EXCEPTION shape
    if (typeof err.data === 'string') {
      data = err.data;
    } else if (
      err.error &&
      typeof err.error === 'object' &&
      typeof (err.error as Record<string, unknown>).data === 'string'
    ) {
      data = (err.error as Record<string, unknown>).data as string;
    }
  }

  if (!data || data.length < 10) {
    // No selector — fall back to generic revert
    const message =
      errOrData instanceof Error ? errOrData.message : String(errOrData);
    return BolyraError.registryRevert('Unknown', message, errOrData);
  }

  try {
    const parsed = iface.parseError(data);
    if (parsed) {
      return fromErrorDescription(parsed, errOrData);
    }
  } catch {
    // Selector not in our ABI — fall through
  }

  return BolyraError.registryRevert(
    'UnknownSelector',
    data.slice(0, 10),
    errOrData,
  );
}
