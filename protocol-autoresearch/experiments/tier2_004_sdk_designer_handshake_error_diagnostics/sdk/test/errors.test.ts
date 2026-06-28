/**
 * Bolyra SDK — Error system unit tests.
 *
 * Covers:
 * - Each ErrorCode triggered under its condition
 * - Hint interpolation correctness
 * - Cause chain preservation
 * - Revert decoder mapping for every IdentityRegistry custom error
 * - BolyraError.wrap() idempotence
 *
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it } from 'mocha';
import { expect } from 'chai';
import { Interface } from 'ethers';
import { BolyraError, ErrorCode } from '../src/errors.js';
import { HintMap, interpolateHint } from '../src/error-codes.js';
import { mapRevertToBolyraError } from '../src/revert-decoder.js';
import {
  classifyVerificationError,
  verifyProofSafe,
} from '../src/proof-verifier.js';

/* ------------------------------------------------------------------ */
/*  Factory helpers                                                    */
/* ------------------------------------------------------------------ */

describe('BolyraError factories', () => {
  it('staleRoot: code, hint with delta', () => {
    const err = BolyraError.staleRoot(5);
    expect(err.code).to.equal(ErrorCode.STALE_ROOT);
    expect(err.hint).to.include('5 blocks behind');
    expect(err.hint).to.include('registry.latestRoot()');
    expect(err.details).to.deep.include({ delta: 5 });
  });

  it('expiredCredential: code, hint with expiry', () => {
    const expiry = Math.floor(Date.now() / 1000) - 3600;
    const err = BolyraError.expiredCredential(expiry);
    expect(err.code).to.equal(ErrorCode.EXPIRED_CREDENTIAL);
    expect(err.hint).to.include('expired');
    expect(err.hint).to.include('createAgentCredential()');
    expect(err.details).to.have.property('expiry', expiry);
  });

  it('scopeMismatch: code, hint with binary bitmasks', () => {
    const err = BolyraError.scopeMismatch(0b00001111, 0b00000011);
    expect(err.code).to.equal(ErrorCode.SCOPE_MISMATCH);
    expect(err.hint).to.include('00001111');
    expect(err.hint).to.include('00000011');
    expect(err.hint).to.include('delegate()');
  });

  it('nonceReused: code, hint with nonce value', () => {
    const nonce = '0xdeadbeef';
    const err = BolyraError.nonceReused(nonce);
    expect(err.code).to.equal(ErrorCode.NONCE_REUSED);
    expect(err.hint).to.include(nonce);
    expect(err.hint).to.include('fresh nonce');
  });

  it('nullifierSpent: code, hint with nullifier', () => {
    const nullifier = '0xabcdef1234567890';
    const err = BolyraError.nullifierSpent(nullifier);
    expect(err.code).to.equal(ErrorCode.NULLIFIER_SPENT);
    expect(err.hint).to.include(nullifier);
    expect(err.hint).to.include('already been spent');
  });

  it('proofInvalid: code, hint with reason, cause preserved', () => {
    const cause = new Error('snarkjs: invalid witness');
    const err = BolyraError.proofInvalid('witness generation failed', cause);
    expect(err.code).to.equal(ErrorCode.PROOF_INVALID);
    expect(err.hint).to.include('witness generation failed');
    expect(err.hint).to.include('circuit artifacts');
    expect(err.cause).to.equal(cause);
  });

  it('registryRevert: code, hint with error name', () => {
    const err = BolyraError.registryRevert('StaleRoot', '100, 105');
    expect(err.code).to.equal(ErrorCode.REGISTRY_REVERT);
    expect(err.hint).to.include('StaleRoot');
    expect(err.hint).to.include('100, 105');
  });

  it('unknown: code, hint with message', () => {
    const err = BolyraError.unknown('something broke');
    expect(err.code).to.equal(ErrorCode.UNKNOWN);
    expect(err.hint).to.include('something broke');
    expect(err.hint).to.include('github.com/bolyra/bolyra/issues');
  });
});

/* ------------------------------------------------------------------ */
/*  wrap() idempotence                                                 */
/* ------------------------------------------------------------------ */

describe('BolyraError.wrap()', () => {
  it('returns same instance for BolyraError input', () => {
    const original = BolyraError.staleRoot(3);
    const wrapped = BolyraError.wrap(original);
    expect(wrapped).to.equal(original);
  });

  it('wraps generic Error as UNKNOWN with cause', () => {
    const raw = new Error('kaboom');
    const wrapped = BolyraError.wrap(raw);
    expect(wrapped.code).to.equal(ErrorCode.UNKNOWN);
    expect(wrapped.message).to.equal('kaboom');
    expect(wrapped.cause).to.equal(raw);
  });

  it('wraps string as UNKNOWN', () => {
    const wrapped = BolyraError.wrap('oops');
    expect(wrapped.code).to.equal(ErrorCode.UNKNOWN);
    expect(wrapped.message).to.equal('oops');
  });
});

/* ------------------------------------------------------------------ */
/*  Hint interpolation                                                 */
/* ------------------------------------------------------------------ */

describe('interpolateHint()', () => {
  it('replaces all placeholders', () => {
    const result = interpolateHint('a {x} b {y} c', { x: 1, y: 'two' });
    expect(result).to.equal('a 1 b two c');
  });

  it('preserves unknown placeholders', () => {
    const result = interpolateHint('{known} {unknown}', { known: 'yes' });
    expect(result).to.equal('yes {unknown}');
  });

  it('every HintMap entry is a non-empty string', () => {
    for (const code of Object.values(ErrorCode)) {
      expect(HintMap[code]).to.be.a('string').with.length.greaterThan(0);
    }
  });
});

/* ------------------------------------------------------------------ */
/*  Revert decoder                                                     */
/* ------------------------------------------------------------------ */

describe('mapRevertToBolyraError()', () => {
  const abi = [
    'error StaleRoot(uint256 providedBlock, uint256 latestBlock)',
    'error NullifierSpent(bytes32 nullifier)',
    'error ScopeMismatch(uint8 required, uint8 provided)',
    'error InvalidProof()',
    'error NonceAlreadyUsed(bytes32 nonce)',
    'error CredentialExpired(uint256 expiry)',
    'error Unauthorized()',
    'error RootNotFound(bytes32 root)',
  ];
  const iface = new Interface(abi);

  function encodeError(name: string, args: unknown[]): string {
    return iface.encodeErrorResult(name, args);
  }

  it('StaleRoot → STALE_ROOT', () => {
    const data = encodeError('StaleRoot', [100, 105]);
    const err = mapRevertToBolyraError(data);
    expect(err.code).to.equal(ErrorCode.STALE_ROOT);
    expect(err.hint).to.include('5 blocks behind');
  });

  it('NullifierSpent → NULLIFIER_SPENT', () => {
    const nullifier = '0x' + 'ab'.repeat(32);
    const data = encodeError('NullifierSpent', [nullifier]);
    const err = mapRevertToBolyraError(data);
    expect(err.code).to.equal(ErrorCode.NULLIFIER_SPENT);
    expect(err.hint).to.include(nullifier);
  });

  it('ScopeMismatch → SCOPE_MISMATCH', () => {
    const data = encodeError('ScopeMismatch', [0x0f, 0x03]);
    const err = mapRevertToBolyraError(data);
    expect(err.code).to.equal(ErrorCode.SCOPE_MISMATCH);
    expect(err.hint).to.include('00001111');
    expect(err.hint).to.include('00000011');
  });

  it('InvalidProof → PROOF_INVALID', () => {
    const data = encodeError('InvalidProof', []);
    const err = mapRevertToBolyraError(data);
    expect(err.code).to.equal(ErrorCode.PROOF_INVALID);
  });

  it('NonceAlreadyUsed → NONCE_REUSED', () => {
    const nonce = '0x' + 'ff'.repeat(32);
    const data = encodeError('NonceAlreadyUsed', [nonce]);
    const err = mapRevertToBolyraError(data);
    expect(err.code).to.equal(ErrorCode.NONCE_REUSED);
    expect(err.hint).to.include(nonce);
  });

  it('CredentialExpired → EXPIRED_CREDENTIAL', () => {
    const expiry = Math.floor(Date.now() / 1000) - 600;
    const data = encodeError('CredentialExpired', [expiry]);
    const err = mapRevertToBolyraError(data);
    expect(err.code).to.equal(ErrorCode.EXPIRED_CREDENTIAL);
    expect(err.hint).to.include('expired');
  });

  it('Unauthorized → REGISTRY_REVERT', () => {
    const data = encodeError('Unauthorized', []);
    const err = mapRevertToBolyraError(data);
    expect(err.code).to.equal(ErrorCode.REGISTRY_REVERT);
  });

  it('RootNotFound → STALE_ROOT', () => {
    const root = '0x' + 'cc'.repeat(32);
    const data = encodeError('RootNotFound', [root]);
    const err = mapRevertToBolyraError(data);
    expect(err.code).to.equal(ErrorCode.STALE_ROOT);
  });

  it('unknown data → REGISTRY_REVERT with selector', () => {
    const err = mapRevertToBolyraError('0xdeadbeef00');
    expect(err.code).to.equal(ErrorCode.REGISTRY_REVERT);
  });

  it('Error object with .data field', () => {
    const data = encodeError('InvalidProof', []);
    const rawErr = Object.assign(new Error('revert'), { data });
    const err = mapRevertToBolyraError(rawErr);
    expect(err.code).to.equal(ErrorCode.PROOF_INVALID);
  });

  it('plain string without selector → generic REGISTRY_REVERT', () => {
    const err = mapRevertToBolyraError('short');
    expect(err.code).to.equal(ErrorCode.REGISTRY_REVERT);
  });
});

/* ------------------------------------------------------------------ */
/*  Proof verifier classification                                      */
/* ------------------------------------------------------------------ */

describe('classifyVerificationError()', () => {
  it('expired keyword → EXPIRED_CREDENTIAL', () => {
    const err = classifyVerificationError(new Error('credential expired at 123'));
    expect(err.code).to.equal(ErrorCode.EXPIRED_CREDENTIAL);
  });

  it('nonce reuse keyword → NONCE_REUSED', () => {
    const err = classifyVerificationError(new Error('nonce already used'));
    expect(err.code).to.equal(ErrorCode.NONCE_REUSED);
  });

  it('nullifier spent keyword → NULLIFIER_SPENT', () => {
    const err = classifyVerificationError(
      new Error('nullifier 0xabcd already spent'),
    );
    expect(err.code).to.equal(ErrorCode.NULLIFIER_SPENT);
  });

  it('stale root keyword → STALE_ROOT', () => {
    const err = classifyVerificationError(new Error('root not found'));
    expect(err.code).to.equal(ErrorCode.STALE_ROOT);
  });

  it('scope keyword → SCOPE_MISMATCH', () => {
    const err = classifyVerificationError(new Error('scope validation failed'));
    expect(err.code).to.equal(ErrorCode.SCOPE_MISMATCH);
  });

  it('generic error → PROOF_INVALID', () => {
    const err = classifyVerificationError(new Error('something else'));
    expect(err.code).to.equal(ErrorCode.PROOF_INVALID);
  });
});

/* ------------------------------------------------------------------ */
/*  verifyProofSafe wrapper                                            */
/* ------------------------------------------------------------------ */

describe('verifyProofSafe()', () => {
  it('returns true when verify returns true', async () => {
    const mockVerify = async () => true;
    const result = await verifyProofSafe(mockVerify, {}, [], {});
    expect(result).to.equal(true);
  });

  it('throws PROOF_INVALID when verify returns false', async () => {
    const mockVerify = async () => false;
    try {
      await verifyProofSafe(mockVerify, {}, [], {});
      expect.fail('should have thrown');
    } catch (err) {
      expect(err).to.be.instanceOf(BolyraError);
      expect((err as BolyraError).code).to.equal(ErrorCode.PROOF_INVALID);
    }
  });

  it('classifies thrown errors and preserves cause', async () => {
    const cause = new Error('credential expired');
    const mockVerify = async () => { throw cause; };
    try {
      await verifyProofSafe(mockVerify, {}, [], {});
      expect.fail('should have thrown');
    } catch (err) {
      expect(err).to.be.instanceOf(BolyraError);
      expect((err as BolyraError).code).to.equal(ErrorCode.EXPIRED_CREDENTIAL);
      expect((err as BolyraError).cause).to.equal(cause);
    }
  });

  it('passes through BolyraError without re-wrapping', async () => {
    const original = BolyraError.nonceReused('0x123');
    const mockVerify = async () => { throw original; };
    try {
      await verifyProofSafe(mockVerify, {}, [], {});
      expect.fail('should have thrown');
    } catch (err) {
      expect(err).to.equal(original);
    }
  });
});
